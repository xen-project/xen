import types
import StringIO

import sxp

class ArgError(StandardError):
    pass

class Args:
    """Argument encoding support for HTTP.
    """
    
    def __init__(self, paramspec, keyspec):
        self.arg_ord = []
        self.arg_dict = {}
        self.key_ord = []
        self.key_dict = {}
        for (name, type) in paramspec:
                self.arg_ord.append(name)
                self.arg_dict[name] = type
        for (name, type) in keyspec:
                self.key_ord.append(name)
                self.key_dict[name] = type

    def get_args(self, d, xargs=None):
        args = {}
        keys = {}
        params = []
        if xargs:
            self.split_args(xargs, args, keys)
        self.split_args(d, args, keys)
        for a in self.arg_ord:
            if a in args:
                params.append(args[a])
            else:
                raise ArgError('Missing parameter: %s' % a)
        return (params, keys)

    def split_args(self, d, args, keys):
        for (k, v) in d.items():
            if k in self.arg_dict:
                type = self.arg_dict[k]
                val = self.coerce(type, v)
                args[k] = val
            elif k in self.key_dict:
                type = self.key_dict[k]
                val = self.coerce(type, v)
                keys[k] = val
            else:
                raise ArgError('Invalid parameter: %s' % k)

    def get_form_args(self, f, xargs=None):
        d = {}
        for (k, v) in f.items():
            if ((k not in self.arg_dict) and
                (k not in self.key_dict)):
                continue
            if isinstance(v, types.ListType):
                n = len(v)
                if n == 0:
                    continue
                elif n == 1:
                    val = v[0]
                else:
                    raise ArgError('Too many values for %s' % k)
            else:
                val = v
            d[k] = val
        return self.get_args(d, xargs=xargs)

    def coerce(self, type, v):
        try:
            if type == 'int':
                val = int(v)
            elif type == 'long':
                val = long(v)
            elif type == 'str':
                val = str(v)
            elif type == 'sxpr':
                val = self.sxpr(v)
            elif type == 'bool':
                val = self.bool(v)
            else:
                raise ArgError('invalid type:' + str(type))
            return val
        except ArgError:
            raise
        except StandardError, ex:
            raise ArgError(str(ex))

    def bool(self, v):
        return (v.lower() in ['on', 'yes', '1', 'true'])

    def sxpr(self, v):
        if isinstance(v, types.ListType):
            val = v
        elif isinstance(v, types.FileType) or hasattr(v, 'readline'):
            val = self.sxpr_file(v)
        elif isinstance(v, types.StringType):
            val = self.sxpr_file(StringIO.StringIO(v))
        else:
            val = str(v)
        return val

    def sxpr_file(self, fin):
        try:
            vals = sxp.parse(fin)
        except:
            raise ArgError('Coercion to sxpr failed')
        if len(vals) == 1:
            return vals[0]
        else:
            raise ArgError('Too many sxprs')

    def call_with_args(self, fn, args, xargs=None):
        (params, keys) = self.get_args(args, xargs=xargs)
        return fn(*params, **keys)

    def call_with_form_args(self, fn, fargs, xargs=None):
        (params, keys) = self.get_form_args(fargs, xargs=xargs)
        return fn(*params, **keys)

class ArgFn(Args):
    """Represent a remote HTTP operation as a function.
    Used on the client.
    """

    def __init__(self, fn, paramspec, keyspec={}):
        Args.__init__(self, paramspec, keyspec)
        self.fn = fn

    def __call__(self, fargs, xargs=None):
        return self.call_with_args(self.fn, fargs, xargs=xargs)
    
class FormFn(Args):
    """Represent an operation as a function over a form.
    Used in the HTTP server.
    """

    def __init__(self, fn, paramspec, keyspec={}):
        Args.__init__(self, paramspec, keyspec)
        self.fn = fn

    def __call__(self, fargs, xargs=None):
        return self.call_with_form_args(self.fn, fargs, xargs=xargs)
