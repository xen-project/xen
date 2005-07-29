###########################################################
## XenSV Web Control Interface Daemon
## Copyright (C) 2004, K A Fraser (University of Cambridge)
## Copyright (C) 2004, Mike Wray <mike.wray@hp.com>
## Copyright (C) 2004, Tom Wilkie <tw275@cam.ac.uk>
###########################################################

import os
import os.path
import sys
import re

from xen.sv.params import *

from twisted.internet import reactor
from twisted.web import static, server, script

from xen.util.ip import _readline, _readlines

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
        lines = _readlines(os.popen('ps ' + pid + ' 2>/dev/null'))
        for line in lines:
            if re.search('^ *' + pid + '.+xensv', line):
                if not kill:
                    print "Daemon is already running (pid %d)" % int(pid)
                    return 1
                # Old daemon is still active: terminate it.
                os.kill(int(pid), 1)
        # Delete the stale PID_FILE.
        os.remove(PID_FILE)
        return 0

    def start(self, trace=0):
        if self.cleanup(kill=False):
            return 1
   
        # Fork -- parent writes PID_FILE and exits.
        pid = os.fork()
        if pid:
            # Parent
            pidfile = open(PID_FILE, 'w')
            pidfile.write(str(pid))
            pidfile.close()
            return 0
        # Child
        self.run()
        return 0

    def stop(self):
        return self.cleanup(kill=True)

    def run(self):
	root = static.File( SV_ROOT )
        root.indexNames = [ 'Main.rpy' ]
        root.processors = { '.rpy': script.ResourceScript }
        reactor.listenTCP( SV_PORT, server.Site( root ) )
        reactor.run()

    def exit(self):
        reactor.disconnectAll()
        sys.exit(0)

def instance():
    global inst
    try:
        inst
    except:
        inst = Daemon()
    return inst
