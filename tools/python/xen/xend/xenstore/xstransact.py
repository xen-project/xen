# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

from xen.xend.xenstore.xsutil import xshandle


class xstransact:

    def __init__(self, path):
        assert path is not None
        
        self.in_transaction = False # Set this temporarily -- if this
                                    # constructor fails, then we need to
                                    # protect __del__.
        self.path = path.rstrip("/")
        self.transaction = xshandle().transaction_start()
        self.in_transaction = True

    def __del__(self):
        if self.in_transaction:
            xshandle().transaction_end(self.transaction, True)

    def commit(self):
        if not self.in_transaction:
            raise RuntimeError
        self.in_transaction = False
        rc = xshandle().transaction_end(self.transaction, False)
        self.transaction = "0"
        return rc

    def abort(self):
        if not self.in_transaction:
            return True
        self.in_transaction = False
        rc = xshandle().transaction_end(self.transaction, True)
        self.transaction = "0"
        return rc

    def _read(self, key):
        path = "%s/%s" % (self.path, key)
        try:
            return xshandle().read(self.transaction, path)
        except RuntimeError, ex:
            raise RuntimeError(ex.args[0],
                               '%s, while reading %s' % (ex.args[1], path))

    def read(self, *args):
        """If no arguments are given, return the value at this transaction's
        path.  If one argument is given, treat that argument as a subpath to
        this transaction's path, and return the value at that path.
        Otherwise, treat each argument as a subpath to this transaction's
        path, and return a list composed of the values at each of those
        instead.
        """
        if len(args) == 0:
            return xshandle().read(self.transaction, self.path)
        if len(args) == 1:
            return self._read(args[0])
        ret = []
        for key in args:
            ret.append(self._read(key))
        return ret

    def _write(self, key, data):
        path = "%s/%s" % (self.path, key)
        try:
            xshandle().write(self.transaction, path, data)
        except RuntimeError, ex:
            raise RuntimeError(ex.args[0],
                               ('%s, while writing %s : %s' %
                                (ex.args[1], path, str(data))))

    def write(self, *args):
        if len(args) == 0:
            raise TypeError
        if isinstance(args[0], dict):
            for d in args:
                if not isinstance(d, dict):
                    raise TypeError
                for key in d.keys():
                    try:
                        self._write(key, d[key])
                    except TypeError, msg:
                        raise TypeError('Writing %s: %s: %s' %
                                        (key, str(d[key]), msg))
        elif isinstance(args[0], list):
            for l in args:
                if not len(l) == 2:
                    raise TypeError
                self._write(l[0], l[1])
        elif len(args) % 2 == 0:
            for i in range(len(args) / 2):
                self._write(args[i * 2], args[i * 2 + 1])
        else:
            raise TypeError

    def _remove(self, key):
        path = "%s/%s" % (self.path, key)
        return xshandle().rm(self.transaction, path)

    def remove(self, *args):
        """If no arguments are given, remove this transaction's path.
        Otherwise, treat each argument as a subpath to this transaction's
        path, and remove each of those instead.
        """
        if len(args) == 0:
            xshandle().rm(self.transaction, self.path)
        else:
            for key in args:
                self._remove(key)

    def _list(self, key):
        path = "%s/%s" % (self.path, key)
        l = xshandle().ls(self.transaction, path)
        if l:
            return map(lambda x: key + "/" + x, l)
        return []

    def list(self, *args):
        """If no arguments are given, list this transaction's path, returning
        the entries therein, or the empty list if no entries are found.
        Otherwise, treat each argument as a subpath to this transaction's
        path, and return the cumulative listing of each of those instead.
        """
        if len(args) == 0:
            ret = xshandle().ls(self.transaction, self.path)
            if ret is None:
                return []
            else:
                return ret
        else:
            ret = []
            for key in args:
                ret.extend(self._list(key))
            return ret


    def list_recursive_(self, subdir, keys):
        ret = []
        for key in keys:
            new_subdir = subdir + "/" + key
            l = xshandle().ls(self.transaction, new_subdir)
            if l:
                ret.append([key, self.list_recursive_(new_subdir, l)])
            else:
                ret.append([key, xshandle().read(self.transaction, new_subdir)])
        return ret


    def list_recursive(self, *args):
        """If no arguments are given, list this transaction's path, returning
        the entries therein, or the empty list if no entries are found.
        Otherwise, treat each argument as a subpath to this transaction's
        path, and return the cumulative listing of each of those instead.
        """
        if len(args) == 0:
            args = self.list()
            if args is None or len(args) == 0:
                return []

        return self.list_recursive_(self.path, args)


    def gather(self, *args):
        if len(args) and type(args[0]) != tuple:
            args = args,
        ret = []
        for tup in args:
            if len(tup) == 2:
                (key, fn) = tup
                defval = None
            else:
                (key, fn, defval) = tup

            val = self._read(key)
            # If fn is str, then this will successfully convert None to
            # 'None'.  If it is int, then it will throw TypeError on None, or
            # on any other non-integer value.  We have to, therefore, both
            # check explicitly for None, and catch TypeError.  Either failure
            # will result in defval being used instead.
            if val is None:
                val = defval
            else:
                try:
                    val = fn(val)
                except TypeError:
                    val = defval
            ret.append(val)
        if len(ret) == 1:
            return ret[0]
        return ret

    def store(self, *args):
        if len(args) and type(args[0]) != tuple:
            args = args,
        for tup in args:
            if len(tup) == 2:
                (key, val) = tup
                try:
                    fmt = { str : "%s",
                            int : "%i",
                            float : "%f",
                            type(None) : None }[type(val)]
                except KeyError:
                    raise TypeError
            else:
                (key, val, fmt) = tup
            if val is None:
                self._remove(key)
            else:
                self._write(key, fmt % val)


    def Read(cls, path, *args):
        """If only one argument is given (path), return the value stored at
        that path.  If two arguments are given, treat the second argument as a
        subpath within the first, and return the value at the composed path.
        Otherwise, treat each argument after the first as a subpath to the
        given path, and return a list composed of the values at each of those
        instead.  This operation is performed inside a transaction.
        """
        while True:
            t = cls(path)
            try:
                v = t.read(*args)
                t.abort()
                return v
            except:
                t.abort()
                raise

    Read = classmethod(Read)

    def Write(cls, path, *args):
        while True:
            t = cls(path)
            try:
                t.write(*args)
                if t.commit():
                    return
            except:
                t.abort()
                raise

    Write = classmethod(Write)

    def Remove(cls, path, *args):
        """If only one argument is given (path), remove it.  Otherwise, treat
        each further argument as a subpath to the given path, and remove each
        of those instead.  This operation is performed inside a transaction.
        """
        while True:
            t = cls(path)
            try:
                t.remove(*args)
                if t.commit():
                    return
            except:
                t.abort()
                raise

    Remove = classmethod(Remove)

    def List(cls, path, *args):
        """If only one argument is given (path), list its contents, returning
        the entries therein, or the empty list if no entries are found.
        Otherwise, treat each further argument as a subpath to the given path,
        and return the cumulative listing of each of those instead.  This
        operation is performed inside a transaction.
        """
        while True:
            t = cls(path)
            try:
                v = t.list(*args)
                if t.commit():
                    return v
            except:
                t.abort()
                raise

    List = classmethod(List)

    def ListRecursive(cls, path, *args):
        """If only one argument is given (path), list its contents
        recursively, returning the entries therein, or the empty list if no
        entries are found.  Otherwise, treat each further argument as a
        subpath to the given path, and return the cumulative listing of each
        of those instead.  This operation is performed inside a transaction.
        """
        while True:
            t = cls(path)
            try:
                v = t.list_recursive(*args)
                if t.commit():
                    return v
            except:
                t.abort()
                raise

    ListRecursive = classmethod(ListRecursive)

    def Gather(cls, path, *args):
        while True:
            t = cls(path)
            try:
                v = t.gather(*args)
                if t.commit():
                    return v
            except:
                t.abort()
                raise

    Gather = classmethod(Gather)

    def Store(cls, path, *args):
        while True:
            t = cls(path)
            try:
                v = t.store(*args)
                if t.commit():
                    return v
            except:
                t.abort()
                raise

    Store = classmethod(Store)
