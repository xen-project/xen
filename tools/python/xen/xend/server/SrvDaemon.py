###########################################################
## Xen controller daemon
## Copyright (c) 2004, K A Fraser (University of Cambridge)
## Copyright (C) 2004, Mike Wray <mike.wray@hp.com>
###########################################################

import os
import os.path
import signal
import sys
import threading
import linecache
import socket
import pwd
import re
import StringIO
import traceback

from twisted.internet import pollreactor
pollreactor.install()

from twisted.internet import reactor
from twisted.internet import protocol
from twisted.internet import abstract
from twisted.internet import defer

from xen.lowlevel import xu

from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend import EventServer
eserver = EventServer.instance()
from xen.xend.XendError import XendError
from xen.xend.server import SrvServer
from xen.xend import XendRoot
from xen.xend.XendLogging import log

from xen.util.ip import _readline, _readlines

import channel
import blkif
import netif
import usbif
import console
import domain
from params import *

DAEMONIZE = 1
DEBUG = 1

class NotifierProtocol(protocol.Protocol):
    """Asynchronous handler for i/o on the notifier (event channel).
    """

    def __init__(self, channelFactory):
        self.channelFactory = channelFactory

    def notificationReceived(self, idx):
        channel = self.channelFactory.getChannel(idx)
        if channel:
            channel.notificationReceived()

    def connectionLost(self, reason=None):
        pass

    def doStart(self):
        pass

    def doStop(self):
        pass

    def startProtocol(self):
        pass

    def stopProtocol(self):
        pass

class NotifierPort(abstract.FileDescriptor):
    """Transport class for the event channel.
    """

    def __init__(self, daemon, notifier, proto, reactor=None):
        assert isinstance(proto, NotifierProtocol)
        abstract.FileDescriptor.__init__(self, reactor)
        self.daemon = daemon
        self.notifier = notifier
        self.protocol = proto

    def startListening(self):
        self._bindNotifier()
        self._connectToProtocol()

    def stopListening(self):
        if self.connected:
            result = self.d = defer.Deferred()
        else:
            result = None
        self.loseConnection()
        return result

    def fileno(self):
        return self.notifier.fileno()

    def _bindNotifier(self):
        self.connected = 1

    def _connectToProtocol(self):
        self.protocol.makeConnection(self)
        self.startReading()

    def loseConnection(self):
        if self.connected:
            self.stopReading()
            self.disconnecting = 1
            reactor.callLater(0, self.connectionLost)

    def connectionLost(self, reason=None):
        abstract.FileDescriptor.connectionLost(self, reason)
        if hasattr(self, 'protocol'):
            self.protocol.doStop()
        self.connected = 0
        #self.notifier.close()   # (this said:) Not implemented.
        #os.close(self.fileno()) # But yes it is...
        del self.notifier        # ...as _dealloc!
        if hasattr(self, 'd'):
            self.d.callback(None)
            del self.d
        
    def doRead(self):
        count = 0
        while 1:            
            notification = self.notifier.read()
            if not notification:
                break
            self.protocol.notificationReceived(notification)
            self.notifier.unmask(notification)
            count += 1

class EventProtocol(protocol.Protocol):
    """Asynchronous handler for a connected event socket.
    """

    def __init__(self, daemon):
        #protocol.Protocol.__init__(self)
        self.daemon = daemon
        # Event queue.
        self.queue = []
        # Subscribed events.
        self.events = []
        self.parser = sxp.Parser()
        self.pretty = 0

        # For debugging subscribe to everything and make output pretty.
        self.subscribe(['*'])
        self.pretty = 1

    def dataReceived(self, data):
        try:
            self.parser.input(data)
            if self.parser.ready():
                val = self.parser.get_val()
                res = self.dispatch(val)
                self.send_result(res)
            if self.parser.at_eof():
                self.loseConnection()
        except SystemExit:
            raise
        except:
            if DEBUG:
                raise
            else:
                self.send_error()

    def loseConnection(self):
        if self.transport:
            self.transport.loseConnection()
        if self.connected:
            reactor.callLater(0, self.connectionLost)

    def connectionLost(self, reason=None):
        self.unsubscribe()

    def send_reply(self, sxpr):
        io = StringIO.StringIO()
        if self.pretty:
            PrettyPrint.prettyprint(sxpr, out=io)
        else:
            sxp.show(sxpr, out=io)
        print >> io
        io.seek(0)
        return self.transport.write(io.getvalue())

    def send_result(self, res):
        return self.send_reply(['ok', res])

    def send_error(self):
        (extype, exval) = sys.exc_info()[:2]
        return self.send_reply(['err',
                                ['type', str(extype)],
                                ['value', str(exval)]])

    def send_event(self, val):
        return self.send_reply(['event', val[0], val[1]])

    def unsubscribe(self):
        for event in self.events:
            eserver.unsubscribe(event, self.queue_event)

    def subscribe(self, events):
        self.unsubscribe()
        for event in events:
            eserver.subscribe(event, self.queue_event)
        self.events = events

    def queue_event(self, name, v):
        # Despite the name we don't queue the event here.
        # We send it because the transport will queue it.
        self.send_event([name, v])
        
    def opname(self, name):
         return 'op_' + name.replace('.', '_')

    def operror(self, name, req):
        raise XendError('Invalid operation: ' +name)

    def dispatch(self, req):
        op_name = sxp.name(req)
        op_method_name = self.opname(op_name)
        op_method = getattr(self, op_method_name, self.operror)
        return op_method(op_name, req)

    def op_help(self, name, req):
        def nameop(x):
            if x.startswith('op_'):
                return x[3:].replace('_', '.')
            else:
                return x
        
        l = [ nameop(k) for k in dir(self) if k.startswith('op_') ]
        return l

    def op_quit(self, name, req):
        self.loseConnection()

    def op_exit(self, name, req):
        sys.exit(0)

    def op_pretty(self, name, req):
        self.pretty = 1
        return ['ok']

    def op_console_disconnect(self, name, req):
        id = sxp.child_value(req, 'id')
        if not id:
            raise XendError('Missing console id')
        id = int(id)
        self.daemon.console_disconnect(id)
        return ['ok']

    def op_info(self, name, req):
        val = ['info']
        val += self.daemon.consoles()
        val += self.daemon.blkifs()
        val += self.daemon.netifs()
        val += self.daemon.usbifs()
        return val

    def op_sys_subscribe(self, name, v):
        # (sys.subscribe event*)
        # Subscribe to the events:
        self.subscribe(v[1:])
        return ['ok']

    def op_sys_inject(self, name, v):
        # (sys.inject event)
        event = v[1]
        eserver.inject(sxp.name(event), event)
        return ['ok']

    def op_trace(self, name, v):
        mode = (v[1] == 'on')
        self.daemon.tracing(mode)

    def op_log_stderr(self, name, v):
        mode = v[1]
        logging = XendRoot.instance().get_logging()
        if mode == 'on':
            logging.addLogStderr()
        else:
            logging.removeLogStderr()

    def op_debug_msg(self, name, v):
        mode = v[1]
        import messages
        messages.DEBUG = (mode == 'on')

    def op_debug_controller(self, name, v):
        mode = v[1]
        import controller
        controller.DEBUG = (mode == 'on')


class EventFactory(protocol.Factory):
    """Asynchronous handler for the event server socket.
    """
    protocol = EventProtocol
    service = None

    def __init__(self, daemon):
        #protocol.Factory.__init__(self)
        self.daemon = daemon

    def buildProtocol(self, addr):
        proto = self.protocol(self.daemon)
        proto.factory = self
        return proto

class VirqClient:
    def __init__(self, daemon):
        self.daemon = daemon

    def virqReceived(self, virq):
        print 'VirqClient.virqReceived>', virq
        eserver.inject('xend.virq', virq)

    def lostChannel(self, channel):
        print 'VirqClient.lostChannel>', channel
        
class Daemon:
    """The xend daemon.
    """
    def __init__(self):
        self.shutdown = 0
        self.traceon = 0

    def daemon_pids(self):
        pids = []
        pidex = '(?P<pid>\d+)'
        pythonex = '(?P<python>\S*python\S*)'
        cmdex = '(?P<cmd>.*)'
        procre = re.compile('^\s*' + pidex + '\s*' + pythonex + '\s*' + cmdex + '$')
        xendre = re.compile('^/usr/sbin/xend\s*(start|restart)\s*.*$')
        procs = os.popen('ps -e -o pid,args 2>/dev/null')
        for proc in procs:
            pm = procre.match(proc)
            if not pm: continue
            xm = xendre.match(pm.group('cmd'))
            if not xm: continue
            #print 'pid=', pm.group('pid'), 'cmd=', pm.group('cmd')
            pids.append(int(pm.group('pid')))
        return pids

    def new_cleanup(self, kill=0):
        err = 0
        pids = self.daemon_pids()
        if kill:
            for pid in pids:
                print "Killing daemon pid=%d" % pid
                os.kill(pid, signal.SIGHUP)
        elif pids:
            err = 1
            print "Daemon already running: ", pids
        return err

    def read_pid(self, pidfile):
        """Read process id from a file.

        @param pidfile: file to read
        @return pid or 0
        """
        pid = 0
        if os.path.isfile(pidfile) and os.path.getsize(pidfile):
            try:
                pid = open(pidfile, 'r').read()
                pid = int(pid)
            except:
                pid = 0
        return pid

    def find_process(self, pid, name):
        """Search for a process.

        @param pid: process id
        @param name: process name
        @return: pid if found, 0 otherwise
        """
        running = 0
        if pid:
            lines = _readlines(os.popen('ps %d 2>/dev/null' % pid))
            exp = '^ *%d.+%s' % (pid, name)
            for line in lines:
                if re.search(exp, line):
                    running = pid
                    break
        return running

    def cleanup_process(self, pidfile, name, kill):
        """Clean up the pidfile for a process.
        If a running process is found, kills it if 'kill' is true.

        @param pidfile: pid file
        @param name: process name
        @param kill: whether to kill the process
        @return running process id or 0
        """
        running = 0
        pid = self.read_pid(pidfile)
        if self.find_process(pid, name):
            if kill:
                os.kill(pid, 1)
            else:
                running = pid
        if running == 0 and os.path.isfile(pidfile):
            os.remove(pidfile)
        return running

    def cleanup_xend(self, kill=False):
        return self.cleanup_process(XEND_PID_FILE, "xend", kill)

    def cleanup_xfrd(self, kill=False):
        return self.cleanup_process(XFRD_PID_FILE, "xfrd", kill)

    def cleanup(self, kill=False):
        self.cleanup_xend(kill=kill)
        self.cleanup_xfrd(kill=kill)
            
    def status(self):
        """Returns the status of the xend and xfrd daemons.
        The return value is defined by the LSB:
        0  Running
        3  Not running
        """
        if (self.cleanup_process(XEND_PID_FILE, "xend", False) == 0 or
            self.cleanup_process(XFRD_PID_FILE, "xfrd", False) == 0):
            return 3
        else:
            return 0

    def install_child_reaper(self):
        #signal.signal(signal.SIGCHLD, self.onSIGCHLD)
        # Ensure that zombie children are automatically reaped.
        xu.autoreap()

    def onSIGCHLD(self, signum, frame):
        code = 1
        while code > 0:
            code = os.waitpid(-1, os.WNOHANG)

    def fork_pid(self, pidfile):
        """Fork and write the pid of the child to 'pidfile'.

        @param pidfile: pid file
        @return: pid of child in parent, 0 in child
        """
        pid = os.fork()
        if pid:
            # Parent
            pidfile = open(pidfile, 'w')
            pidfile.write(str(pid))
            pidfile.close()
        return pid

    def start_xfrd(self):
        """Fork and exec xfrd, writing its pid to XFRD_PID_FILE.
        """
        if self.fork_pid(XFRD_PID_FILE):
            # Parent
            pass
        else:
            # Child
            os.execl("/usr/sbin/xfrd", "xfrd")

    def daemonize(self):
        if not DAEMONIZE: return
        # Detach from TTY.
        os.setsid()

        # Detach from standard file descriptors.
        # I do this at the file-descriptor level: the overlying Python file
        # objects also use fd's 0, 1 and 2.
        os.close(0)
        os.close(1)
        os.close(2)
        if DEBUG:
            os.open('/dev/null', os.O_RDONLY)
            # XXX KAF: Why doesn't this capture output from C extensions that
            # fprintf(stdout) or fprintf(stderr) ??
            os.open('/var/log/xend-debug.log', os.O_WRONLY|os.O_CREAT)
        else:
            os.open('/dev/null', os.O_RDWR)
            os.dup(0)
        os.dup(1)
        
    def start(self, trace=0):
        """Attempts to start the daemons.
        The return value is defined by the LSB:
        0  Success
        4  Insufficient privileges
        """
        xend_pid = self.cleanup_xend()
        xfrd_pid = self.cleanup_xfrd()


        self.daemonize()
        
        if self.set_user():
            return 4
        os.chdir("/")

        if xfrd_pid == 0:
            self.start_xfrd()
        if xend_pid > 0:
            # Trying to run an already-running service is a success.
            return 0

        self.install_child_reaper()

        if self.fork_pid(XEND_PID_FILE):
            #Parent
            pass
        else:
            # Child
            self.tracing(trace)
            self.run()
        return 0

    def tracing(self, traceon):
        """Turn tracing on or off.

        @param traceon: tracing flag
        """
        if traceon == self.traceon:
            return
        self.traceon = traceon
        if traceon:
            self.tracefile = open(XEND_TRACE_FILE, 'w+', 1)
            self.traceindent = 0
            sys.settrace(self.trace)
            try:
                threading.settrace(self.trace) # Only in Python >= 2.3
            except:
                pass

    def print_trace(self, str):
        for i in range(self.traceindent):
            ch = " "
            if (i % 5):
                ch = ' '
            else:
                ch = '|'
            self.tracefile.write(ch)
        self.tracefile.write(str)
            
    def trace(self, frame, event, arg):
        if not self.traceon:
            print >>self.tracefile
            print >>self.tracefile, '-' * 20, 'TRACE OFF', '-' * 20
            self.tracefile.close()
            self.tracefile = None
            return None
        if event == 'call':
            code = frame.f_code
            filename = code.co_filename
            m = re.search('.*xend/(.*)', filename)
            if not m:
                return None
            modulename = m.group(1)
            if re.search('sxp.py', modulename):
                return None
            self.traceindent += 1
            self.print_trace("> %s:%s\n"
                             % (modulename, code.co_name))
        elif event == 'line':
            filename = frame.f_code.co_filename
            lineno = frame.f_lineno
            self.print_trace("%4d %s" %
                             (lineno, linecache.getline(filename, lineno)))
        elif event == 'return':
            code = frame.f_code
            filename = code.co_filename
            m = re.search('.*xend/(.*)', filename)
            if not m:
                return None
            modulename = m.group(1)
            self.print_trace("< %s:%s\n"
                             % (modulename, code.co_name))
            self.traceindent -= 1
        elif event == 'exception':
            self.print_trace("! Exception:\n")
            (ex, val, tb) = arg
            traceback.print_exception(ex, val, tb, 10, self.tracefile)
            #del tb
        return self.trace

    def set_user(self):
        # Set the UID.
        try:
            os.setuid(pwd.getpwnam(USER)[2])
            return 0
        except KeyError, error:
            print "Error: no such user '%s'" % USER
            return 1

    def stop(self):
        return self.cleanup(kill=True)

    def run(self):
        xroot = XendRoot.instance()
        log.info("Xend Daemon started")
        self.createFactories()
        self.listenEvent()
        self.listenNotifier()
        self.listenVirq()
        SrvServer.create(bridge=1)
        reactor.run()

    def createFactories(self):
        self.channelF = channel.channelFactory()
        self.domainCF = domain.DomainControllerFactory()
        self.blkifCF = blkif.BlkifControllerFactory()
        self.netifCF = netif.NetifControllerFactory()
        self.usbifCF = usbif.UsbifControllerFactory()
        self.consoleCF = console.ConsoleControllerFactory()

    def listenEvent(self):
        protocol = EventFactory(self)
        return reactor.listenTCP(EVENT_PORT, protocol)

    def listenNotifier(self):
        protocol = NotifierProtocol(self.channelF)
        p = NotifierPort(self, self.channelF.notifier, protocol, reactor)
        p.startListening()
        return p

    def listenVirq(self):
        virqChan = self.channelF.virqChannel(channel.VIRQ_DOM_EXC)
        virqChan.registerClient(VirqClient(self))

    def exit(self):
        reactor.disconnectAll()
        sys.exit(0)

    def getDomChannel(self, dom):
        """Get the channel to a domain.

        @param dom: domain
        @return: channel (or None)
        """
        return self.channelF.getDomChannel(dom)

    def createDomChannel(self, dom, local_port=0, remote_port=0):
        """Get the channel to a domain, creating if necessary.

        @param dom: domain
        @param local_port: optional local port to re-use
        @param remote_port: optional remote port to re-use
        @return: channel
        """
        return self.channelF.domChannel(dom, local_port=local_port,
                                        remote_port=remote_port)

    def blkif_create(self, dom, recreate=0):
        """Create or get a block device interface controller.
        
        Returns controller
        """
        blkif = self.blkifCF.getController(dom)
        blkif.daemon = self
        return blkif

    def blkifs(self):
        return [ x.sxpr() for x in self.blkifCF.getControllers() ]

    def blkif_get(self, dom):
        return self.blkifCF.getControllerByDom(dom)

    def netif_create(self, dom, recreate=0):
        """Create or get a network interface controller.
        
        """
        return self.netifCF.getController(dom)

    def netifs(self):
        return [ x.sxpr() for x in self.netifCF.getControllers() ]

    def netif_get(self, dom):
        return self.netifCF.getControllerByDom(dom)

    def usbif_create(self, dom, recreate=0):
        return self.usbifCF.getController(dom)
    
    def usbifs(self):
        return [ x.sxpr() for x in self.usbifCF.getControllers() ]

    def usbif_get(self, dom):
        return self.usbifCF.getControllerByDom(dom)

    def console_create(self, dom, console_port=None):
        """Create a console for a domain.
        """
        console = self.consoleCF.getControllerByDom(dom)
        if console is None:
            console = self.consoleCF.createController(dom, console_port)
        return console

    def consoles(self):
        return [ c.sxpr() for c in self.consoleCF.getControllers() ]

    def get_consoles(self):
        return self.consoleCF.getControllers()

    def get_console(self, id):
        return self.consoleCF.getControllerByIndex(id)

    def get_domain_console(self, dom):
        return self.consoleCF.getControllerByDom(dom)

    def console_disconnect(self, id):
        """Disconnect any connected console client.
        """
        console = self.get_console(id)
        if not console:
            raise XendError('Invalid console id')
        console.disconnect()

    def domain_shutdown(self, dom, reason, key=0):
        """Shutdown a domain.
        """
        dom = int(dom)
        ctrl = self.domainCF.getController(dom)
        if not ctrl:
            raise XendError('No domain controller: %s' % dom)
        ctrl.shutdown(reason, key)
        return 0

    def domain_mem_target_set(self, dom, target):
        """Set memory target for a domain.
        """
        dom = int(dom)
        ctrl = self.domainCF.getController(dom)
        if not ctrl:
            raise XendError('No domain controller: %s' % dom)
        ctrl.mem_target_set(target)
        return 0
        
def instance():
    global inst
    try:
        inst
    except:
        inst = Daemon()
    return inst
