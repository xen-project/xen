###########################################################
## Xen controller daemon
## Copyright (c) 2004, K A Fraser (University of Cambridge)
## Copyright (C) 2004, Mike Wray <mike.wray@hp.com>
## Copyright (C) 2005, XenSource Ltd
###########################################################

import os
import os.path
import signal
import stat
import sys
import threading
import time
import linecache
import pwd
import re
import traceback

import xen.lowlevel.xc

from xen.xend.XendLogging import log
from xen.xend import osdep
from xen.util import mkdir

import relocate
import SrvServer
from params import *


XEND_PROCESS_NAME = 'xend'


class Daemon:
    """The xend daemon.
    """
    def __init__(self):
        self.traceon = False
        self.tracefile = None
        self.traceindent = 0
        self.child = 0 


    def cleanup_xend(self, kill):
        """Clean up the Xend pidfile.
        If a running process is found, kills it if 'kill' is true.

        @param kill: whether to kill the process
        @return running process id or 0
        """
        running = 0
        pid = read_pid(XEND_PID_FILE)
        if find_process(pid, XEND_PROCESS_NAME):
            if kill:
                os.kill(pid, signal.SIGTERM)
            else:
                running = pid
        if running == 0 and os.path.isfile(XEND_PID_FILE):
            os.remove(XEND_PID_FILE)
        return running


    def reloadConfig(self):
        """
        """
        pid = read_pid(XEND_PID_FILE)
        if find_process(pid, XEND_PROCESS_NAME):
            os.kill(pid, signal.SIGHUP)


    def status(self):
        """Returns the status of the xend daemon.
        The return value is defined by the LSB:
        0  Running
        3  Not running
        """
        if self.cleanup_xend(False) == 0:
            return 3
        else:
            return 0


    def fork_pid(self):
        """Fork and write the pid of the child to XEND_PID_FILE.

        @return: pid of child in parent, 0 in child
        """

        self.child = os.fork()

        if self.child:
            # Parent
            pidfile = open(XEND_PID_FILE, 'w')
            try:
                pidfile.write(str(self.child))
            finally:
                pidfile.close()

        return self.child


    def daemonize(self):
        # Detach from TTY.

        # Become the group leader (already a child process)
        os.setsid()

        # Fork, this allows the group leader to exit,
        # which means the child can never again regain control of the
        # terminal
        if os.fork():
            os._exit(0)

        # Detach from standard file descriptors, and redirect them to
        # /dev/null or the log as appropriate.
        # We open the log file first, so that we can diagnose a failure to do
        # so _before_ we close stderr.
        try:
            parent = os.path.dirname(XEND_DEBUG_LOG)
            mkdir.parents(parent, stat.S_IRWXU)
            fd = os.open(XEND_DEBUG_LOG, os.O_WRONLY|os.O_CREAT|os.O_APPEND)
        except Exception, exn:
            print >>sys.stderr, exn
            print >>sys.stderr, ("Xend failed to open %s.  Exiting!" %
                                 XEND_DEBUG_LOG)
            sys.exit(1)

        os.close(0)
        os.close(1)
        os.close(2)
        if XEND_DEBUG:
            os.open('/dev/null', os.O_RDONLY)
            os.dup(fd)
            os.dup(fd)
        else:
            os.open('/dev/null', os.O_RDWR)
            os.dup(0)
            os.dup(fd)
        os.close(fd)

        print >>sys.stderr, ("Xend started at %s." %
                             time.asctime(time.localtime()))

        
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

        # If we're not going to create a daemon, simply
        # call the run method right here.
        if not XEND_DAEMONIZE:
            self.tracing(trace)
            self.run(None)
            return ret
        
        # we use a pipe to communicate between the parent and the child process
        # this way we know when the child has actually initialized itself so
        # we can avoid a race condition during startup
        
        r,w = os.pipe()
        if os.fork():
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
            self.daemonize()
            self.tracing(trace)

            # If Xend proper segfaults, then we want to restart it.  Thus,
            # we fork a child for running Xend itself, and if it segfaults
            # (or exits any way other than cleanly) then we run it again.
            # The first time through we want the server to write to the (r,w)
            # pipe created above, so that we do not exit until the server is
            # ready to receive requests.  All subsequent restarts we don't
            # want this behaviour, or the pipe will eventually fill up, so
            # we just pass None into run in subsequent cases (by clearing w
            # in the parent of the first fork).  On some operating systems,
            # restart is managed externally, so we won't fork, and just exit.
            while True:

                if not osdep.xend_autorestart:
                    self.run(os.fdopen(w, 'w'))
                    os._exit(0)

                pid = self.fork_pid()
                if pid:
                    if w is not None:
                        os.close(w)
                        w = None

                    (_, status) = os.waitpid(pid, 0)

                    if os.WIFEXITED(status):
                        code = os.WEXITSTATUS(status)
                        log.info('Xend exited with status %d.', code)
                        sys.exit(code)

                    if os.WIFSIGNALED(status):
                        sig = os.WTERMSIG(status)

                        if sig in (signal.SIGINT, signal.SIGTERM):
                            log.info('Xend stopped due to signal %d.', sig)
                            sys.exit(0)
                        else:
                            log.fatal(
                                'Xend died due to signal %d!  Restarting it.',
                                sig)
                else:
                    self.run(w and os.fdopen(w, 'w') or None)
                    # if we reach here, the child should quit.
                    os._exit(0)

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
            if modulename.endswith('.pyc'):
                modulename = modulename[:-1]
            if modulename == 'sxp.py' or \
               modulename == 'XendLogging.py' or \
               modulename == 'XendMonitor.py' or \
               modulename == 'server/SrvServer.py':
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

            xc = xen.lowlevel.xc.xc()
            xinfo = xc.xeninfo()
            log.info("Xend changeset: %s.", xinfo['xen_changeset'])
            del xc

            try:
                from xen import VERSION
                log.info("Xend version: %s", VERSION)
            except ImportError:
                log.info("Xend version: Unknown.")

            relocate.listenRelocation()
            servers = SrvServer.create()
            servers.start(status)
            del servers
            
        except Exception, ex:
            print >>sys.stderr, 'Exception starting xend:', ex
            if XEND_DEBUG:
                traceback.print_exc()
            log.exception("Exception starting xend (%s)" % ex)
            if status:
                status.write('1')
                status.close()
            sys.exit(1)
            
def instance():
    global inst
    try:
        inst
    except:
        inst = Daemon()
    return inst


def read_pid(pidfile):
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


def find_process(pid, name):
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


def main(argv = None):
    global XEND_DAEMONIZE
    
    XEND_DAEMONIZE = False
    if argv is None:
        argv = sys.argv

    try:
        daemon = instance()
    
        r,w = os.pipe()
        daemon.run(os.fdopen(w, 'w'))
        return 0
    except Exception, exn:
        log.fatal(exn)
        return 1


if __name__ == "__main__":
    sys.exit(main())
