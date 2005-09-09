# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import threading
from xen.lowlevel import xs

handles = {}

# XXX need to g/c handles from dead threads
def xshandle():
    if not handles.has_key(threading.currentThread()):
        handles[threading.currentThread()] = xs.open()
    return handles[threading.currentThread()]

class xstransact:

    def __init__(self, path):
        self.path = path.rstrip("/")
        xshandle().transaction_start(path)
        self.in_transaction = True

    def __del__(self):
        if self.in_transaction:
            xshandle().transaction_end(True)

    def commit(self):
        if not self.in_transaction:
            raise RuntimeError
        self.in_transaction = False
        return xshandle().transaction_end(False)

    def abort(self):
        if not self.in_transaction:
            raise RuntimeError
        self.in_transaction = False
        return xshandle().transaction_end(True)

    def _read(self, key):
        path = "%s/%s" % (self.path, key)
        return xshandle().read(path)

    def read(self, *args):
        if len(args) == 0:
            raise TypeError
        if len(args) == 1:
            return self._read(args[0])
        ret = []
        for key in args:
            ret.append(self._read(key))
        return ret

    def _write(self, key, data, create=True, excl=False):
        path = "%s/%s" % (self.path, key)
        xshandle().write(path, data, create=create, excl=excl)

    def write(self, *args, **opts):
        create = opts.get('create') or True
        excl = opts.get('excl') or False
        if len(args) == 0:
            raise TypeError
        if isinstance(args[0], dict):
            for d in args:
                if not isinstance(d, dict):
                    raise TypeError
                for key in d.keys():
                    self._write(key, d[key], create, excl)
        elif isinstance(args[0], list):
            for l in args:
                if not len(l) == 2:
                    raise TypeError
                self._write(l[0], l[1], create, excl)
        elif len(args) % 2 == 0:
            for i in range(len(args) / 2):
                self._write(args[i * 2], args[i * 2 + 1], create, excl)
        else:
            raise TypeError

    def Read(cls, path, *args):
        t = cls(path)
        v = t.read(*args)
        t.commit()
        return v

    Read = classmethod(Read)

    def Write(cls, path, *args, **opts):
        t = cls(path)
        t.write(*args, **opts)
        t.commit()

    Write = classmethod(Write)

    def SafeRead(cls, path, *args):
        while True:
            try:
                return cls.Read(path, *args)
            except RuntimeError, ex:
                pass

    SafeRead = classmethod(SafeRead)

    def SafeWrite(cls, path, *args, **opts):
        while True:
            try:
                cls.Write(path, *args, **opts)
                return
            except RuntimeError, ex:
                pass

    SafeWrite = classmethod(SafeWrite)
