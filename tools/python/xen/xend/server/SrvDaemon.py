###########################################################
## Xen controller daemon
## Copyright (c) 2004, K A Fraser (University of Cambridge)
## Copyright (C) 2004, Mike Wray <mike.wray@hp.com>
###########################################################

import os
import signal
import sys
import threading
import linecache
import socket
import pwd
import re
import StringIO
import traceback
import time
import glob

from xen.lowlevel import xu

from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend import EventServer; eserver = EventServer.instance()
from xen.xend.XendError import XendError
from xen.xend.server import SrvServer
from xen.xend.XendLogging import log
from xen.xend import XendRoot; xroot = XendRoot.instance()

import channel
import controller
import event
import relocate
from params import *

class Daemon:
    """The xend daemon.
    """
    def __init__(self):
        self.channelF = None
        self.shutdown = 0
        self.traceon = 0
        self.tracefile = None
        self.traceindent = 0

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
            lines = os.popen('ps %d 2>/dev/null' % pid).readlines()
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

    def cleanup(self, kill=False):
        self.cleanup_xend(kill=kill)

    def status(self):
        """Returns the status of the xend daemon.
        The return value is defined by the LSB:
        0  Running
        3  Not running
        """
        if self.cleanup_process(XEND_PID_FILE, "xend", False) == 0:
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

    def daemonize(self):
        if not XEND_DAEMONIZE: return
        # Detach from TTY.
        os.setsid()

        # Detach from standard file descriptors.
        # I do this at the file-descriptor level: the overlying Python file
        # objects also use fd's 0, 1 and 2.
        os.close(0)
        os.close(1)
        os.close(2)
        if XEND_DEBUG:
            os.open('/dev/null', os.O_RDONLY)
            # XXX KAF: Why doesn't this capture output from C extensions that
            # fprintf(stdout) or fprintf(stderr) ??
            os.open(XEND_DEBUG_LOG, os.O_WRONLY|os.O_CREAT)
            os.dup(1)
        else:
            os.open('/dev/null', os.O_RDWR)
            os.dup(0)
            os.open(XEND_DEBUG_LOG, os.O_WRONLY|os.O_CREAT)

        
    def start(self, trace=0):
        """Attempts to start the daemons.
        The return value is defined by the LSB:
        0  Success
        4  Insufficient privileges
        """
        xend_pid = self.cleanup_xend()

        if self.set_user():
            return 4
        os.chdir("/")

        if xend_pid > 0:
            # Trying to run an already-running service is a success.
            return 0

        self.install_child_reaper()

        if self.fork_pid(XEND_PID_FILE):
            #Parent. Sleep to give child time to start.
            time.sleep(1)
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
            os.setuid(pwd.getpwnam(XEND_USER)[2])
            return 0
        except KeyError, error:
            print >>sys.stderr, "Error: no such user '%s'" % XEND_USER
            return 1

    def stop(self):
        return self.cleanup(kill=True)

    def run(self):
        _enforce_dom0_cpus()
        try:
            log.info("Xend Daemon started")
            self.createFactories()
            event.listenEvent(self)
            relocate.listenRelocation()
            self.listenChannels()
            servers = SrvServer.create()
            self.daemonize()
            servers.start()
        except Exception, ex:
            print >>sys.stderr, 'Exception starting xend:', ex
            if XEND_DEBUG:
                traceback.print_exc()
            log.exception("Exception starting xend")
            self.exit(1)
            
    def createFactories(self):
        self.channelF = channel.channelFactory()

    def listenChannels(self):
        def virqReceived(virq):
            eserver.inject('xend.virq', virq)

        self.channelF.setVirqHandler(virqReceived)
        self.channelF.start()

    def exit(self, rc=0):
        if self.channelF:
            self.channelF.stop()
        # Calling sys.exit() raises a SystemExit exception, which only
        # kills the current thread. Calling os._exit() makes the whole
        # Python process exit immediately. There doesn't seem to be another
        # way to exit a Python with running threads.
        #sys.exit(rc)
        os._exit(rc)

def _enforce_dom0_cpus():
    dn = xroot.get_dom0_cpus()

    for d in glob.glob("/sys/devices/system/cpu/cpu*"):
        cpu = int(os.path.basename(d)[3:])
        if (dn == 0) or (cpu < dn):
            v = "1"
        else:
            v = "0"
        try:
            f = open("%s/online" %d, "r+")
            c = f.read(1)
            if (c != v):
                if v == "0":
                    log.info("dom0 is trying to give back cpu %d", cpu)
                else:
                    log.info("dom0 is trying to take cpu %d", cpu)
                f.seek(0)
                f.write(v)
                f.close()
                log.info("dom0 successfully enforced cpu %d", cpu)
            else:
                f.close()
        except:
            pass

def instance():
    global inst
    try:
        inst
    except:
        inst = Daemon()
    return inst
