# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>

# os.system() replacement which outputs through the logger

import popen2
import select

from xen.xend.XendLogging import log

def system(cmd):
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
    while True:
        r = p.poll()
        for (fd, event) in r:
            if event == select.POLLHUP:
                return
            if fd == cout.fileno():
                l = cout.readline()
                log.info(cmdname + l.rstrip())
            if fd == cerr.fileno():
                l = cerr.readline()
                log.error(cmdname + l.rstrip())
