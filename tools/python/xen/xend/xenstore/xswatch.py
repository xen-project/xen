# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import errno
import threading
from xen.xend.xenstore.xsutil import xshandle


class xswatch:

    ##
    # Create a watch on the given path in the store.  The watch will fire
    # immediately, then subsequently each time the watched path is changed,
    # until the watch is deregistered, either by the return value from the
    # watch callback being False, or by an explicit call to unwatch.
    #
    # @param fn The function to be called when the watch fires.  This function
    # should take the path that has changed as its first argument, followed by
    # the extra arguments given to this constructor, if any.  It should return
    # True if the watch is to remain registered, or False if it is to be
    # deregistered.
    #
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
            res = watch.fn(we[0], *watch.args, **watch.kwargs)
            if not res:
                try:
                    watch.unwatch()
                except RuntimeError, exn:
                    if exn.args[0] == errno.ENOENT:
                        # The watch has already been unregistered -- that's
                        # fine.
                        pass
                    else:
                        raise
        except:
            pass
            # Ignore this exception -- there's no point throwing it
            # further on because that will just kill the watcher thread,
            # which achieves nothing.
