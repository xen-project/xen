# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

from xen.xend.xenstore.xsutil import xshandle

class xstransact:
    """WARNING: Be very careful if you're instantiating an xstransact object
       yourself (i.e. not using the capitalized static helpers like .Read().
       It is essential that you clean up the object in place via
       t.commit/abort(): GC can happen at any time, including contexts where
       it's not safe to to use the shared xenstore socket fd. In particular,
       if xend forks, and GC occurs, we can have two processes trying to
       use the same xenstore fd, and all hell breaks loose.
       """


    def __init__(self, path = ""):
        
        self.in_transaction = False # Set this temporarily -- if this
                                    # constructor fails, then we need to
                                    # protect __del__.

        assert path is not None
        self.path = path.rstrip("/")
        self.transaction = xshandle().transaction_start()
        self.in_transaction = True

    def __del__(self):
        # see above.
        if self.in_transaction:
            raise RuntimeError("ERROR: GC of live transaction")

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
        path = self.prependPath(key)
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
        path = self.prependPath(key)
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
        path = self.prependPath(key)
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
        path = self.prependPath(key)
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
            # If fn is str, then this will successfully convert None to 'None'
            # (which we don't want).  If it is int or float, then it will
            # throw ValueError on any non-convertible value.  We check
            # explicitly for None, using defval instead, but allow ValueError
            # to propagate.
            if val is None:
                val = defval
            else:
                val = fn(val)
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
                    fmt = { str        : "%s",
                            int        : "%i",
                            float      : "%f",
                            long       : "%li",
                            type(None) : None }[type(val)]
                except KeyError:
                    raise TypeError
            else:
                (key, val, fmt) = tup
            if val is None:
                self._remove(key)
            else:
                self._write(key, fmt % val)


    def mkdir(self, *args):
        if len(args) == 0:
            xshandle().mkdir(self.transaction, self.path)
        else:
            for key in args:
                xshandle().mkdir(self.transaction, self.prependPath(key))


    def get_permissions(self, *args):
        """If no arguments are given, return the permissions at this
        transaction's path.  If one argument is given, treat that argument as
        a subpath to this transaction's path, and return the permissions at
        that path.  Otherwise, treat each argument as a subpath to this
        transaction's path, and return a list composed of the permissions at
        each of those instead.
        """
        if len(args) == 0:
            return xshandle().get_permissions(self.transaction, self.path)
        if len(args) == 1:
            return self._get_permissions(args[0])
        ret = []
        for key in args:
            ret.append(self._get_permissions(key))
        return ret


    def _get_permissions(self, key):
        path = self.prependPath(key)
        try:
            return xshandle().get_permissions(self.transaction, path)
        except RuntimeError, ex:
            raise RuntimeError(ex.args[0],
                               '%s, while getting permissions from %s' %
                               (ex.args[1], path))


    def set_permissions(self, *args):
        if len(args) == 0:
            raise TypeError
        elif isinstance(args[0], str):
            self.callRebased(args[0], self.set_permissions, *args[1:])
        else:
            if not self.path:
                raise RuntimeError('Cannot set permissions on the root')

            xshandle().set_permissions(self.transaction, self.path,
                                       list(args))


    def remove2(self, middlePath, *args):
        self.callRebased(middlePath, self.remove, *args)


    def write2(self, middlePath, *args):
        self.callRebased(middlePath, self.write, *args)


    def callRebased(self, middlePath, func, *args):
        oldpath = self.path
        self.path = self.prependPath(middlePath)
        try:
            func(*args)
        finally:
            self.path = oldpath


    def prependPath(self, key):
        if self.path:
            return self.path + '/' + key
        else:
            return key


    def Read(cls, path, *args):
        """If only one argument is given (path), return the value stored at
        that path.  If two arguments are given, treat the second argument as a
        subpath within the first, and return the value at the composed path.
        Otherwise, treat each argument after the first as a subpath to the
        given path, and return a list composed of the values at each of those
        instead.  This operation is performed inside a transaction.
        """
        return complete(path, lambda t: t.read(*args))
    Read = classmethod(Read)

    def Write(cls, path, *args):
        complete(path, lambda t: t.write(*args))
    Write = classmethod(Write)

    def Remove(cls, path, *args):
        """If only one argument is given (path), remove it.  Otherwise, treat
        each further argument as a subpath to the given path, and remove each
        of those instead.  This operation is performed inside a transaction.
        """
        complete(path, lambda t: t.remove(*args))
    Remove = classmethod(Remove)

    def List(cls, path, *args):
        """If only one argument is given (path), list its contents, returning
        the entries therein, or the empty list if no entries are found.
        Otherwise, treat each further argument as a subpath to the given path,
        and return the cumulative listing of each of those instead.  This
        operation is performed inside a transaction.
        """
        return complete(path, lambda t: t.list(*args))
    List = classmethod(List)

    def ListRecursive(cls, path, *args):
        """If only one argument is given (path), list its contents
        recursively, returning the entries therein, or the empty list if no
        entries are found.  Otherwise, treat each further argument as a
        subpath to the given path, and return the cumulative listing of each
        of those instead.  This operation is performed inside a transaction.
        """
        return complete(path, lambda t: t.list_recursive(*args))
    ListRecursive = classmethod(ListRecursive)

    def Gather(cls, path, *args):
        return complete(path, lambda t: t.gather(*args))
    Gather = classmethod(Gather)

    def Store(cls, path, *args):
        complete(path, lambda t: t.store(*args))
    Store = classmethod(Store)

    def SetPermissions(cls, path, *args):
        complete(path, lambda t: t.set_permissions(*args))
    SetPermissions = classmethod(SetPermissions)

    def Mkdir(cls, path, *args):
        complete(path, lambda t: t.mkdir(*args))
    Mkdir = classmethod(Mkdir)


def complete(path, f):
    while True:
        t = xstransact(path)
        try:
            result = f(t)
            if t.commit():
                return result
        except:
            t.abort()
            raise
