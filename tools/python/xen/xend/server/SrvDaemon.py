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

from xen.xend.server import SrvServer

import channel
import blkif
import netif
import console
import domain
from params import *

DEBUG = 1

class MgmtProtocol(protocol.DatagramProtocol):
    """Handler for the management socket (unix-domain).
    """

    def __init__(self, daemon):
        #protocol.DatagramProtocol.__init__(self)
        self.daemon = daemon
    
    def write(self, data, addr):
        return self.transport.write(data, addr)

    def datagramReceived(self, data, addr):
        if DEBUG: print 'datagramReceived> addr=', addr, 'data=', data
        io = StringIO.StringIO(data)
        try:
            vals = sxp.parse(io)
            res = self.dispatch(vals[0])
            self.send_result(addr, res)
        except SystemExit:
            raise
        except:
            if DEBUG:
                raise
            else:
                self.send_error(addr)

    def send_reply(self, addr, sxpr):
        io = StringIO.StringIO()
        sxp.show(sxpr, out=io)
        io.seek(0)
        self.write(io.getvalue(), addr)

    def send_result(self, addr, res):
        
        def fn(res, self=self, addr=addr):
            self.send_reply(addr, ['ok', res])
            
        if isinstance(res, defer.Deferred):
            res.addCallback(fn)
        else:
            fn(res)

    def send_error(self, addr):
        (extype, exval) = sys.exc_info()[:2]
        self.send_reply(addr, ['err',
                               ['type',  str(extype) ],
                               ['value', str(exval)  ] ] )

    def opname(self, name):
        """Get the name of the method for an operation.
        """
        return 'op_' + name.replace('.', '_')

    def operror(self, name, v):
        """Default operation handler - signals an error.
        """
        raise NotImplementedError('Invalid operation: ' +name)

    def dispatch(self, req):
        """Dispatch a request to its handler.
        """
        op_name = sxp.name(req)
        op_method_name = self.opname(op_name)
        op_method = getattr(self, op_method_name, self.operror)
        return op_method(op_name, req)

    def op_console_create(self, name, req):
        """Create a new control interface - console for a domain.
        """
        print name, req
        dom = sxp.child_value(req, 'domain')
        if not dom: raise ValueError('Missing domain')
        dom = int(dom)
        console_port = sxp.child_value(req, 'console_port')
        if console_port:
            console_port = int(console_port)
        resp = self.daemon.console_create(dom, console_port)
        print name, resp
        return resp

    def op_consoles(self, name, req):
        """Get a list of the consoles.
        """
        return self.daemon.consoles()

    def op_console_disconnect(self, name, req):
        id = sxp.child_value(req, 'id')
        if not id:
            raise ValueError('Missing console id')
        id = int(id)
        console = self.daemon.get_console(id)
        if not console:
            raise ValueError('Invalid console id')
        if console.conn:
            console.conn.loseConnection()
        return ['ok']

    def op_blkifs(self, name, req):
        pass
    
    def op_blkif_devs(self, name, req):
        pass

    def op_blkif_create(self, name, req):
        pass
    
    def op_blkif_dev_create(self, name, req):
        pass

    def op_netifs(self, name, req):
        pass

    def op_netif_devs(self, name, req):
        pass

    def op_netif_create(self, name, req):
        pass

    def op_netif_dev_create(self, name, req):
        pass

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
        #self.notifier.close() # Not implemented.
        os.close(self.fileno())
        del self.notifier
        if hasattr(self, 'd'):
            self.d.callback(None)
            del self.d
        
    def doRead(self):
        #print 'NotifierPort>doRead>', self
        count = 0
        while 1:            
            #print 'NotifierPort>doRead>', count
            notification = self.notifier.read()
            if not notification:
                break
            self.protocol.notificationReceived(notification)
            self.notifier.unmask(notification)
            count += 1
        #print 'NotifierPort>doRead<'

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
        # Despite the name we dont' queue the event here.
        # We send it because the transport will queue it.
        self.send_event([name, v])
        
    def opname(self, name):
         return 'op_' + name.replace('.', '_')

    def operror(self, name, req):
        raise NotImplementedError('Invalid operation: ' +name)

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
            raise ValueError('Missing console id')
        self.daemon.console_disconnect(id)
        return ['ok']

    def op_info(self, name, req):
        val = ['info']
        val += self.daemon.consoles()
        val += self.daemon.blkifs()
        val += self.daemon.netifs()
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

    def op_traceon(self, name, v):
        self.daemon.tracing(1)

    def op_traceoff(self, name, v):
        self.daemon.tracing(0)


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
            
    def cleanup(self, kill=False):
        # No cleanup to do if PID_FILE is empty.
        if not os.path.isfile(PID_FILE) or not os.path.getsize(PID_FILE):
            return 0
        # Read the pid of the previous invocation and search active process list.
        pid = open(PID_FILE, 'r').read()
        lines = os.popen('ps ' + pid + ' 2>/dev/null').readlines()
        for line in lines:
            if re.search('^ *' + pid + '.+xend', line):
                if not kill:
                    print "Daemon is already running (pid %d)" % int(pid)
                    return 1
                # Old daemon is still active: terminate it.
                os.kill(int(pid), 1)
        # Delete the stale PID_FILE.
        os.remove(PID_FILE)
        return 0

    def install_child_reaper(self):
        #signal.signal(signal.SIGCHLD, self.onSIGCHLD)
        # Ensure that zombie children are automatically reaped.
        xu.autoreap()

    def onSIGCHLD(self, signum, frame):
        code = 1
        while code > 0:
            code = os.waitpid(-1, os.WNOHANG)

    def start(self, trace=0):
        if self.cleanup(kill=False):
            return 1

        # Detach from TTY.
        if not DEBUG:
            os.setsid()

        if self.set_user():
            return 1

        self.install_child_reaper()

        # Fork -- parent writes PID_FILE and exits.
        pid = os.fork()
        if pid:
            # Parent
            pidfile = open(PID_FILE, 'w')
            pidfile.write(str(pid))
            pidfile.close()
            return 0
        # Child
        logfile = self.open_logfile()
        self.redirect_output(logfile)
        
        self.tracing(trace)

        self.run()
        return 0

    def tracing(self, traceon):
        """Turn tracing on or off.

        traceon tracing flag
        """
        if traceon == self.traceon:
            return
        self.traceon = traceon
        if traceon:
            self.tracefile = open('/var/log/xend.trace', 'w+', 1)
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

    def open_logfile(self):
        if not os.path.exists(CONTROL_DIR):
            os.makedirs(CONTROL_DIR)

        # Open log file. Truncate it if non-empty, and request line buffering.
        if os.path.isfile(LOG_FILE):
            os.rename(LOG_FILE, LOG_FILE+'.old')
        logfile = open(LOG_FILE, 'w+', 1)
        return logfile

    def set_user(self):
        # Set the UID.
        try:
            os.setuid(pwd.getpwnam(USER)[2])
            return 0
        except KeyError, error:
            print "Error: no such user '%s'" % USER
            return 1

    def redirect_output(self, logfile):
        if DEBUG: return
        # Close down standard file handles
        try:
            os.close(0) # stdin
            os.close(1) # stdout
            os.close(2) # stderr
        except:
            pass
        # Redirect output to log file.
        sys.stdout = sys.stderr = logfile

    def stop(self):
        return self.cleanup(kill=True)

    def run(self):
        self.createFactories()
        self.listenMgmt()
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
        self.consoleCF = console.ConsoleControllerFactory()

    def listenMgmt(self):
        protocol = MgmtProtocol(self)
        s = os.path.join(CONTROL_DIR, MGMT_SOCK)
        if os.path.exists(s):
            os.unlink(s)
        return reactor.listenUNIXDatagram(s, protocol)

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
        reactor.diconnectAll()
        sys.exit(0)

    def blkif_set_control_domain(self, dom, recreate=0):
        """Set the block device backend control domain.
        """
        return self.blkifCF.setControlDomain(dom, recreate=recreate)
    
    def blkif_get_control_domain(self, dom):
        """Get the block device backend control domain.
        """
        return self.blkifCF.getControlDomain()
    
    def blkif_create(self, dom, recreate=0):
        """Create a block device interface controller.
        
        Returns Deferred
        """
        d = self.blkifCF.createInstance(dom, recreate=recreate)
        return d

    def blkifs(self):
        return [ x.sxpr() for x in self.blkifCF.getInstances() ]

    def blkif_get(self, dom):
        return self.blkifCF.getInstanceByDom(dom)

    def blkif_dev(self, dom, vdev):
        return self.blkifCF.getDomainDevice(dom, vdev)

    def blkif_dev_create(self, dom, vdev, mode, segment, recreate=0):
        """Create a block device.
        
        Returns Deferred
        """
        ctrl = self.blkifCF.getInstanceByDom(dom)
        if not ctrl:
            raise ValueError('No blkif controller: %d' % dom)
        print 'blkif_dev_create>', dom, vdev, mode, segment
        d = ctrl.attachDevice(vdev, mode, segment, recreate=recreate)
        return d

    def netif_set_control_domain(self, dom, recreate=0):
        """Set the network interface backend control domain.
        """
        return self.netifCF.setControlDomain(dom, recreate=recreate)

    def netif_get_control_domain(self, dom):
        """Get the network interface backend control domain.
        """
        return self.netifCF.getControlDomain()
    
    def netif_create(self, dom, recreate=0):
        """Create a network interface controller.
        
        """
        return self.netifCF.createInstance(dom, recreate=recreate)

    def netifs(self):
        return [ x.sxpr() for x in self.netifCF.getInstances() ]

    def netif_get(self, dom):
        return self.netifCF.getInstanceByDom(dom)

    def netif_dev_create(self, dom, vif, vmac, recreate=0):
        """Create a network device.

        todo
        """
        ctrl = self.netifCF.getInstanceByDom(dom)
        if not ctrl:
            raise ValueError('No netif controller: %d' % dom)
        d = ctrl.attachDevice(vif, vmac, recreate=recreate)
        return d

    def netif_dev(self, dom, vif):
        return self.netifCF.getDomainDevice(dom, vif)

    def console_create(self, dom, console_port=None):
        """Create a console for a domain.
        """
        console = self.consoleCF.getInstanceByDom(dom)
        if console is None:
            console = self.consoleCF.createInstance(dom, console_port)
        return console.sxpr()

    def consoles(self):
        return [ c.sxpr() for c in self.consoleCF.getInstances() ]

    def get_console(self, id):
        return self.consoleCF.getInstance(id)

    def get_domain_console(self, dom):
        return self.consoleCF.getInstanceByDom(dom)

    def console_disconnect(self, id):
        """Disconnect any connected console client.
        """
        console = self.get_console(id)
        if not console:
            raise ValueError('Invalid console id')
        console.disconnect()

    def domain_shutdown(self, dom, reason):
        """Shutdown a domain.
        """
        ctrl = self.domainCF.getInstanceByDom(dom)
        if not ctrl:
            raise ValueError('No domain controller: %d' % dom)
        ctrl.shutdown(reason)
        return 0
        
def instance():
    global inst
    try:
        inst
    except:
        inst = Daemon()
    return inst
