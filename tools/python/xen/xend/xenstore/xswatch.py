# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import threading
from xen.xend.xenstore.xsutil import xshandle

from xen.xend.XendLogging import log


class xswatch:

    def __init__(self, path, fn, *args, **kwargs):
        self.path = path
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        watchStart()
        xs.watch(path, self)


    def unwatch(self):
        xs.unwatch(self.path, self)


watchThread = None
xs = None
xslock = threading.Lock()

def watchStart():
    global watchThread
    global xs
    
    xslock.acquire()
    try:
        if watchThread:
            return
        xs = xshandle()
        watchThread = threading.Thread(name="Watcher", target=watchMain)
        watchThread.setDaemon(True)
        watchThread.start()
    finally:
        xslock.release()


def watchMain():
    while True:
        try:
            we = xs.read_watch()
            watch = we[1]
            res = watch.fn(*watch.args, **watch.kwargs)
            if not res:
                watch.unwatch()
        except:
            log.exception("read_watch failed")
            # Ignore this exception -- there's no point throwing it
            # further on because that will just kill the watcher thread,
            # which achieves nothing.
