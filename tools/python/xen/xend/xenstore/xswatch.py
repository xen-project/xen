# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import select
import threading
from xen.lowlevel import xs
from xen.xend.xenstore.xsutil import xshandle

from xen.xend.XendLogging import log


class xswatch:

    watchThread = None
    xs = None
    xslock = threading.Lock()
    
    def __init__(self, path, fn, *args, **kwargs):
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        xswatch.watchStart()
        xswatch.xs.watch(path, self)

    def watchStart(cls):
        cls.xslock.acquire()
        if cls.watchThread:
            cls.xslock.release()
            return
        cls.xs = xshandle()
        cls.watchThread = threading.Thread(name="Watcher",
                                           target=cls.watchMain)
        cls.watchThread.setDaemon(True)
        cls.watchThread.start()
        cls.xslock.release()

    watchStart = classmethod(watchStart)

    def watchMain(cls):
        while True:
            try:
                we = cls.xs.read_watch()
                watch = we[1]
                watch.fn(*watch.args, **watch.kwargs)
            except:
                log.exception("read_watch failed")
                # Ignore this exception -- there's no point throwing it
                # further on because that will just kill the watcher thread,
                # which achieves nothing.


    watchMain = classmethod(watchMain)
