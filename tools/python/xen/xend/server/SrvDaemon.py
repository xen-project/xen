###########################################################
## Xen controller daemon
## Copyright (c) 2004, K A Fraser (University of Cambridge)
## Copyright (C) 2004, Mike Wray <mike.wray@hp.com>
## Copyright (C) 2005, XenSource Ltd
###########################################################

import os
import signal
import sys
import threading
import linecache
import pwd
import re
import traceback

import xen.lowlevel.xc

from xen.xend.server import SrvServer
from xen.xend.XendLogging import log

import event
import relocate
from params import *


class Daemon:
    """The xend daemon.
    """
    def __init__(self):
        self.shutdown = 0
        self.traceon = 0
        self.tracefile = None
        self.traceindent = 0
        self.child = 0 
        
    def read_pid(self, pidfile):
        """Read process id from a file.

        @param pidfile: file to read
        @return pid or 0
        """
        if os.path.isfile(pidfile) and os.path.getsize(pidfile):
            try:
                f = open(pidfile, 'r')
                try:
                    return int(f.read())
                finally:
                    f.close()
            except:
                return 0
        else:
            return 0

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

    def cleanup_xend(self, kill):
        return self.cleanup_process(XEND_PID_FILE, "xend", kill)

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

    def fork_pid(self, pidfile):
        """Fork and write the pid of the child to 'pidfile'.

        @param pidfile: pid file
        @return: pid of child in parent, 0 in child
        """

        self.child = os.fork()

        if self.child:
            # Parent
            pidfile = open(pidfile, 'w')
            try:
                pidfile.write(str(self.child))
            finally:
                pidfile.close()

        return self.child

    def daemonize(self):
        if not XEND_DAEMONIZE: return
        # Detach from TTY.
        os.setsid()

        # Detach from standard file descriptors, and redirect them to
        # /dev/null or the log as appropriate.
        os.close(0)
        os.close(1)
        os.close(2)
        if XEND_DEBUG:
            os.open('/dev/null', os.O_RDONLY)
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
        xend_pid = self.cleanup_xend(False)

        if self.set_user():
            return 4
        os.chdir("/")

        if xend_pid > 0:
            # Trying to run an already-running service is a success.
            return 0

        ret = 0

        # we use a pipe to communicate between the parent and the child process
        # this way we know when the child has actually initialized itself so
        # we can avoid a race condition during startup
        
        r,w = os.pipe()
        if self.fork_pid(XEND_PID_FILE):
            os.close(w)
            r = os.fdopen(r, 'r')
            try:
                s = r.read()
            finally:
                r.close()
            if not len(s):
                ret = 1
            else:
                ret = int(s)
        else:
            os.close(r)
            # Child
            self.tracing(trace)
            self.run(os.fdopen(w, 'w'))

        return ret

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

    def print_trace(self, string):
        for i in range(self.traceindent):
            ch = " "
            if (i % 5):
                ch = ' '
            else:
                ch = '|'
            self.tracefile.write(ch)
        self.tracefile.write(string)
            
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
        except KeyError:
            print >>sys.stderr, "Error: no such user '%s'" % XEND_USER
            return 1

    def stop(self):
        return self.cleanup_xend(True)

    def run(self, status):
        try:
            log.info("Xend Daemon started")

            xc = xen.lowlevel.xc.new()
            xinfo = xc.xeninfo()
            log.info("Xend changeset: %s.", xinfo['xen_changeset'])
            del xc

            event.listenEvent(self)
            relocate.listenRelocation()
            servers = SrvServer.create()
            self.daemonize()
            servers.start(status)
        except Exception, ex:
            print >>sys.stderr, 'Exception starting xend:', ex
            if XEND_DEBUG:
                traceback.print_exc()
            log.exception("Exception starting xend (%s)" % ex)
            status.write('1')
            status.close()
            self.exit(1)
            
    def exit(self, rc=0):
        # Calling sys.exit() raises a SystemExit exception, which only
        # kills the current thread. Calling os._exit() makes the whole
        # Python process exit immediately. There doesn't seem to be another
        # way to exit a Python with running threads.
        #sys.exit(rc)
        os._exit(rc)

def instance():
    global inst
    try:
        inst
    except:
        inst = Daemon()
    return inst
