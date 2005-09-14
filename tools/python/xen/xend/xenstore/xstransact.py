# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import errno
import threading
from xen.lowlevel import xs
from xen.xend.xenstore.xsutil import xshandle

class xstransact:

    def __init__(self, path):
        self.in_transaction = False
        self.path = path.rstrip("/")
        while True:
            try:
                xshandle().transaction_start(path)
                self.in_transaction = True
                return
            except RuntimeError, ex:
                if ex.args[0] == errno.ENOENT and path != "/":
                    path = "/".join(path.split("/")[0:-1]) or "/"
                else:
                    raise

    def __del__(self):
        if self.in_transaction:
            xshandle().transaction_end(True)

    def commit(self):
        if not self.in_transaction:
            raise RuntimeError
        self.in_transaction = False
        return xshandle().transaction_end(False)

    def abort(self):
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

    def _remove(self, key):
        path = "%s/%s" % (self.path, key)
        return xshandle().rm(path)

    def remove(self, *args):
        if len(args) == 0:
            raise TypeError
        for key in args:
            self._remove(key)

    def _list(self, key):
        path = "%s/%s" % (self.path, key)
        l = xshandle().ls(path)
        if l:
            return map(lambda x: key + "/" + x, l)
        return []

    def list(self, *args):
        if len(args) == 0:
            raise TypeError
        ret = []
        for key in args:
            ret.extend(self._list(key))
        return ret

    def gather(self, *args):
        ret = []
        for tup in args:
            if len(tup) == 2:
                (key, fn) = tup
                defval = None
            else:
                (key, fn, defval) = tup
            try:
                val = fn(self.read(key))
            except TypeError:
                val = defval
            ret.append(val)
        if len(ret) == 1:
            return ret[0]
        return ret


    def Read(cls, path, *args):
        while True:
            try:
                t = cls(path)
                v = t.read(*args)
                t.commit()
                return v
            except RuntimeError, ex:
                t.abort()
                if ex.args[0] == errno.ETIMEDOUT:
                    pass
                else:
                    raise
            except:
                t.abort()
                raise

    Read = classmethod(Read)

    def Write(cls, path, *args, **opts):
        while True:
            try:
                t = cls(path)
                t.write(*args, **opts)
                t.commit()
                return
            except RuntimeError, ex:
                t.abort()
                if ex.args[0] == errno.ETIMEDOUT:
                    pass
                else:
                    raise
            except:
                t.abort()
                raise

    Write = classmethod(Write)

    def Remove(cls, path, *args):
        while True:
            try:
                t = cls(path)
                t.remove(*args)
                t.commit()
                return
            except RuntimeError, ex:
                t.abort()
                if ex.args[0] == errno.ETIMEDOUT:
                    pass
                else:
                    raise
            except:
                t.abort()
                raise

    Remove = classmethod(Remove)

    def List(cls, path, *args):
        while True:
            try:
                t = cls(path)
                v = t.list(*args)
                t.commit()
                return v
            except RuntimeError, ex:
                t.abort()
                if ex.args[0] == errno.ETIMEDOUT:
                    pass
                else:
                    raise
            except:
                t.abort()
                raise

    List = classmethod(List)

    def Gather(cls, path, *args):
        while True:
            try:
                t = cls(path)
                v = t.gather(*args)
                t.commit()
                return v
            except RuntimeError, ex:
                t.abort()
                if ex.args[0] == errno.ETIMEDOUT:
                    pass
                else:
                    raise
            except:
                t.abort()
                raise

    Gather = classmethod(Gather)
