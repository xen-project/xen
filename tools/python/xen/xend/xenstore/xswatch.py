# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import select
import threading
from xen.lowlevel import xs

class xswatch:

    watchThread = None
    threadcond = threading.Condition()
    xs = None
    xslock = threading.Lock()
    
    def __init__(self, path, fn, *args, **kwargs):
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        xswatch.watchStart()
        xswatch.xslock.acquire()
        xswatch.xs.watch(path, self)
        xswatch.xslock.release()

    def watchStart(cls):
        cls.threadcond.acquire()
        if cls.watchThread:
            cls.threadcond.release()
            return
        cls.watchThread = threading.Thread(name="Watcher",
                                           target=cls.watchMain)
        cls.watchThread.setDaemon(True)
        cls.watchThread.start()
        while cls.xs == None:
            cls.threadcond.wait()
        cls.threadcond.release()

    watchStart = classmethod(watchStart)

    def watchMain(cls):
        cls.threadcond.acquire()
        cls.xs = xs.open()
        cls.threadcond.notifyAll()
        cls.threadcond.release()
        while True:
            try:
                (fd, _1, _2) = select.select([ cls.xs ], [], [])
                cls.xslock.acquire()
                # reconfirm ready to read with lock
                (fd, _1, _2) = select.select([ cls.xs ], [], [], 0.001)
                if not cls.xs in fd:
                    cls.xslock.release()
                    continue
                we = cls.xs.read_watch()
                watch = we[1]
                cls.xs.acknowledge_watch(watch)
                cls.xslock.release()
            except RuntimeError, ex:
                print ex
                raise
            watch.fn(*watch.args, **watch.kwargs)

    watchMain = classmethod(watchMain)
