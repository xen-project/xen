from getopt import getopt
import os
import os.path
import sys
import types

class Opt:
    def __init__(self, opts, name, short=None, long=None,
                 val=None, fn=None, use=None, default=None):
        self.opts = opts
        self.name = name
        self.short = short
        if long is None:
            long = name
        self.long = long
        self.val = val
        self.use = use
        self.default = default
        self.optkeys = []
        if self.short:
            self.optkeys.append('-' + self.short)
        if self.long:
            self.optkeys.append('--' + self.long)
        self.fn = fn
        self.specified_opt = None
        self.specified_val = None
        self.set(default)

    def set(self, value):
        setattr(self.opts, self.name, value)

    def get(self):
        return getattr(self.opts, self.name)

    def append(self, value):
        self.set(self.get().append(value))

    def short_opt(self):
        if self.short:
            if self.val:
                return self.short + ':'
            else:
                return self.short
        else:
            return None

    def long_opt(self):
        if self.long:
            if self.val:
                return self.long + '='
            else:
                return self.long
        else:
            return None

    def show(self):
        sep = ''
        for x in self.optkeys:
            print sep, x,
            sep = ','
        if self.val:
            print self.val,
        print
        if self.use:
            print '\t',
            print self.use
        if self.val:
            print '\tDefault', self.default or 'None'

    def specify(self, k, v):
        if k in self.optkeys:
            if self.val is None and v:
                self.opts.err("Option '%s' does not take a value" % k)
            self.specified_opt = k
            self.specified_val = v
            if self.fn:
                self.fn(self, k, v)
            return 1
        else:
            return 0

    def specified(self):
        return self.specified_opt

class Opts:
    def __init__(self, use=None):
        self._usage = use
        self._options = []
        self._options_map = {}
        self._argv = []
        self._vals = {}
        self._globals = {}
        self._locals = {}
        self.quiet = 0

    def opt(self, name, **args):
        x = Opt(self, name, **args)
        self._options.append(x)
        self._options_map[name] = x
        return x

    def getopt(self, name):
        return self._options_map.get(name)

    def specified(self, name):
        opt = self.getopt(name)
        return opt and opt.specified()

    def setvar(self, name, val):
        self._globals[name] = val

    def err(self, msg):
        print >>sys.stderr, "Error:", msg
        sys.exit(1)

    def info(self, msg):
        if self.quiet: return
        print msg

    def warn(self, msg):
        print >>sys.stderr, "Warning:", msg

    def parse(self, argv):
        self._argv = argv
        (vals, args) = getopt(argv[1:], self.short_opts(), self.long_opts())
        self._args = args
        for (k, v) in vals:
            for opt in self._options:
                if opt.specify(k, v): break
            else:
                print >>sys.stderr, "Error: Unknown option:", k
                self.usage()
        return args

    def short_opts(self):
        l = []
        for x in self._options:
            y = x.short_opt()
            if not y: continue
            l.append(y)
        return ''.join(l)

    def long_opts(self):
        l = []
        for x in self._options:
            y = x.long_opt()
            if not y: continue
            l.append(y)
        return ''.join(l)

    def usage(self):
        print 'Usage: ', self._argv[0], self._usage or 'OPTIONS'
        for opt in self._options:
            opt.show()

    def load_defaults(self):
        for x in [ '' ] + self.path.split(':'):
            if x:
                p = os.path.join(x, self.defaults)
            else:
                p = self.defaults
            if os.path.exists(p):
                self.load(p)
                break
        else:
            self.err("Cannot open defaults file %s" % self.defaults)

    def load(self, defaults):
        self._globals['sys'] = sys
        self._globals['config_file'] = defaults
        execfile(defaults, self._globals, self._locals)
        vtypes = [ types.StringType,
                   types.ListType,
                   types.IntType,
                   types.FloatType
                   ]
        for (k, v) in self._locals.items():
            if self.specified(k): continue
            if not(type(v) in vtypes): continue
            print 'SET ', k, v
            setattr(self, k, v)

def set_true(opt, k, v):
    opt.set(1)

def set_false(opt, k, v):
    opt.set(0)

def set_value(opt, k, v):
    opt.set(v)

def set_int(opt, k, v):
    try:
        v = int(v)
    except:
        opt.opts.err('Invalid value: ' + str(v))
    opt.set(v)

def append_value(opt, k, v):
    opt.append(v)
