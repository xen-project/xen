# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Object-oriented command-line option support.
"""
from getopt import getopt, GetoptError
import os
import os.path
import sys
import types

class Opt:
    """An individual option.
    """
    def __init__(self, opts, name, short=None, long=None,
                 val=None, fn=None, use=None, default=None):
        """Create an option.

        opts    parent options object
        name    name of the field it controls
        short   short (1-char) command line switch (optional)
        long    long command-line switch. Defaults to option name.
        val     string used to print option args in help.
                If val is not specified the option has no arg.
        fn      function to call when the option is specified.
        use     usage (help) string
        default default value if not specified on command-line
        """
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
        self.value = None
        self.set(default)

    def __repr__(self):
        return self.name + '=' + str(self.specified_val)

    __str__ = __repr__

    def set(self, value):
        """Set the option value.
        """
        self.opts.setopt(self.name, value)

    def get(self):
        """Get the option value.
        """
        return self.opts.getopt(self.name)

    def append(self, value):
        """Append a value to the option value.
        """
        v = self.get() or []
        v.append(value)
        self.set(v)

    def short_opt(self):
        """Short option spec.
        """
        if self.short:
            if self.val:
                return self.short + ':'
            else:
                return self.short
        else:
            return None

    def long_opt(self):
        """Long option spec.
        """
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
        """Specify the option. Called when the option is set
        from the command line.

        k  option switch used
        v  optional value given (if any)
        """
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
        """Test whether the option has been specified: set
        from the command line.
        """
        return self.specified_opt

class OptVar(Opt):
    """An individual option variable.
    """
    def __init__(self, opts, name,
                 val=None, fn=None, use=None, default=None):
        """Create an option.

        opts    parent options object
        name    name of the field it controls
        val     string used to print option args in help.
                If val is not specified the option has no arg.
        fn      function to call when the option is specified.
        use     usage (help) string
        default default value if not specified on command-line
        """
        if val is None:
            val = name.upper()
        Opt.__init__(self, opts, name, val=val, fn=fn, use=use, default=default)
        self.optkeys = []
        self.optkeys.append(self.long)

    def short_opt(self):
        return None

    def long_opt(self):
        return None

    def show(self):
        print '%s=%s' %(self.optkeys[0], self.val) 
        print
        if self.use:
            print '\t',
            print self.use
        if self.val:
            print '\tDefault', self.default or 'None'

class OptVals:
    """Class to hold option values.
    """
    pass

class Opts:
    """Container for options.
    """

    imports = ["import sys",
               "import os",
               "import os.path",
               "from xen.util.ip import *",
               ]

    def __init__(self, use=None):
        """Options constructor.

        use  usage string
        """
        self.use = use
        # List of options.
        self.options = []
        # Options indexed by name.
        self.options_map = {}
        # Command-line arguments.
        self.argv = []
        # Option values.
        self.vals = OptVals()
        self.vals.quiet = 0
        # Variables for default scripts.
        self.vars = {}

    def __repr__(self):
        return '\n'.join(map(str, self.options))

    __str__ = __repr__

    def opt(self, name, **args):
        """Add an option.

        name    option name
        **args  keyword params for option constructor
        """
        x = Opt(self, name, **args)
        self.options.append(x)
        self.options_map[name] = x
        return x

    def var(self, name, **args):
        x = OptVar(self, name, **args)
        self.options.append(x)
        self.options_map[name] = x
        return x     

    def setvar(self, var, val):
        """Set a default script variable.
        """
        self.vars[var] = val

    def getvar(self, var):
        """Get a default script variable.
        """
        return self.vars.get(var)

    def option(self, name):
        """Get an option (object).
        """
        return self.options_map.get(name)

    def setopt(self, name, val):
        """Set an option value.
        An option can also be set using 'opts.vals.name = val'.
        """
        setattr(self.vals, name, val)

    def getopt(self, name):
        """Get an option value.
        An option value can also be got using 'opts.vals.name'.
        """
        return getattr(self.vals, name)

    def specified(self, name):
        """Test if an option has been specified.
        """
        opt = self.option(name)
        return opt and opt.specified()

    def err(self, msg):
        """Print an error to stderr and exit.
        """
        print >>sys.stderr, "Error:", msg
        sys.exit(1)

    def info(self, msg):
        """Print a message to stdout (unless quiet is set).
        """
        if self.vals.quiet: return
        print msg

    def warn(self, msg):
        """Print a warning to stdout.
        """
        print >>sys.stderr, "Warning:", msg

    def parse(self, argv):
        """Parse arguments argv using the options.

        return remaining arguments
        """
        self.argv = argv

        try:
            (vals, args) = getopt(argv[1:], self.short_opts(), self.long_opts())
        except GetoptError, err:
            self.err(str(err))

	# hack to work around lack of gnu getopts parsing in python 2.2
	xargs = args
	while xargs[1:]:
	    (v,xargs) = getopt(xargs[1:], self.short_opts(), self.long_opts())
	    vals = vals + v

	# back to the real work
        self.args = args
        for (k, v) in vals:
            for opt in self.options:
                if opt.specify(k, v): break
            else:
                print >>sys.stderr, "Error: Unknown option:", k
                self.usage()
        xargs = []
        for arg in args:
            isvar = 0
            if '=' in arg:
                (k, v) = arg.split('=', 1)
                for opt in self.options:
                    if opt.specify(k, v):
                        isvar = 1
                        break
            if not isvar:
                xargs.append(arg)
        return xargs

    def short_opts(self):
        """Get short options specifier for getopt.
        """
        l = []
        for x in self.options:
            y = x.short_opt()
            if not y: continue
            l.append(y)
        return ''.join(l)

    def long_opts(self):
        """Get long options specifier for getopt.
        """
        l = []
        for x in self.options:
            y = x.long_opt()
            if not y: continue
            l.append(y)
        return l

    def usage(self):
        print 'Usage: ', self.argv[0], self.use or 'OPTIONS'
        for opt in self.options:
            print
            opt.show()

    def load_defaults(self, help=0):
        """Load a defaults script. Assumes these options set:
        'path'    search path
        'default' script name
        """
        for x in [ '' ] + self.vals.path.split(':'):
            if x:
                p = os.path.join(x, self.vals.defaults)
            else:
                p = self.vals.defaults
            if os.path.exists(p):
		self.info('Using config file %s' % p)
                self.load(p, help)
                break
        else:
            self.err("Cannot open defaults file %s" % self.vals.defaults)

    def load(self, defaults, help):
        """Load a defaults file. Local variables in the file
        are used to set options with the same names.
        Variables are not used to set options that are already specified.
        """
        # Create global and lobal dicts for the file.
        # Initialize locals to the vars.
        # Use exec to do the standard imports and
        # define variables we are passing to the script.
        globals = {}
        locals = {}
        locals.update(self.vars)
        cmd = '\n'.join(self.imports + 
                        [ "from xen.xm.help import Vars",
                          "xm_file = '%s'" % defaults,
                          "xm_help = %d" % help,
                          "xm_vars = Vars(xm_file, xm_help, locals())"
                          ])
        exec cmd in globals, locals
        try:
            execfile(defaults, globals, locals)
        except:
            if not help: raise
        if help:
            print 'The following imports are done automatically:'
            for x in self.imports:
                print x
            return
        # Extract the values set by the script and set the corresponding
        # options, if not set on the command line.
        vtypes = [ types.StringType,
                   types.ListType,
                   types.IntType,
                   types.FloatType
                   ]
        for (k, v) in locals.items():
            if self.specified(k): continue
            if not(type(v) in vtypes): continue
            self.setopt(k, v)

def set_true(opt, k, v):
    """Set an option true."""
    opt.set(1)

def set_false(opt, k, v):
    """Set an option false."""
    opt.set(0)

def set_bool(opt, k, v):
    """Set a boolean option.
    """
    if v in ['yes']:
        opt.set(1)
    elif v in ['no']:
        opt.set(0)
    else:
        opt.opts.err('Invalid value:' +v)
        

def set_value(opt, k, v):
    """Set an option to a value."""
    opt.set(v)

def set_int(opt, k, v):
    """Set an option to an integer value."""
    try:
        v = int(v)
    except:
        opt.opts.err('Invalid value: ' + str(v))
    opt.set(v)

def set_float(opt, k, v):
    """Set an option to a float value."""
    try:
        v = float(v)
    except:
        opt.opts.err('Invalid value: ' + str(v))
    opt.set(v)

def append_value(opt, k, v):
    """Append a value to a list option."""
    opt.append(v)

def set_var(opt, k, v):
    """Set a default script variable.
    """
    (var, val) = v.strip().split('=', 1)
    opt.opts.setvar(var.strip(), val.strip())

