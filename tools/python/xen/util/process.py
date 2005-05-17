# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>

# os.system() replacement which outputs through the logger

import popen2
import select
import string

from xen.xend.XendLogging import log

def runscript(cmd):
    # split after first space, then grab last component of path
    cmdname = "[%s] " % cmd.split()[0].split('/')[-1]
    # run command and grab stdin, stdout and stderr
    cout, cin, cerr = popen2.popen3(cmd)
    # close stdin to get command to terminate if it waits for input
    cin.close()
    # wait for output and process
    p = select.poll()
    p.register(cout)
    p.register(cerr)
    stdout = ""
    while True:
        r = p.poll()
        for (fd, event) in r:
            if event == select.POLLHUP:
                return stdout
            if fd == cout.fileno():
                stdout = stdout + cout.readline()
            if fd == cerr.fileno():
                l = cerr.readline()
                if l[0] == '-':
                    log.debug(cmdname + l[1:].rstrip())
                elif l[0] == '*':
                    log.info(cmdname + l[1:].rstrip())
                else:
                    log.error(cmdname + l.rstrip())
