# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Object-oriented command-line option support.
"""
from getopt import getopt
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

class OptVals:
    """Class to hold option values.
    """
    pass

class Opts:
    """Container for options.
    """
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
        getattr(self.vals, name)

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
        (vals, args) = getopt(argv[1:], self.short_opts(), self.long_opts())
        self.args = args
        for (k, v) in vals:
            for opt in self.options:
                if opt.specify(k, v): break
            else:
                print >>sys.stderr, "Error: Unknown option:", k
                self.usage()
        return args

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
            opt.show()

    def load_defaults(self):
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
                self.load(p)
                break
        else:
            self.err("Cannot open defaults file %s" % self.defaults)

    def load(self, defaults, help=0):
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
        cmd = '\n'.join(["import sys",
                         "import os",
                         "import os.path",
                         "xm_file = '%s'" % defaults,
                         "xm_help = %d" % help ])
        exec cmd in globals, locals
        execfile(defaults, globals, locals)
        if help: return
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

def set_value(opt, k, v):
    """Set an option to a valoue."""
    opt.set(v)

def set_int(opt, k, v):
    """Set an option to an integer value."""
    try:
        v = int(v)
    except:
        opt.opts.err('Invalid value: ' + str(v))
    opt.set(v)

def append_value(opt, k, v):
    """Append a value to a list option."""
    opt.append(v)

def set_var(opt, k, v):
    """Set a default script variable.
    """
    (var, val) = v.strip().split('=')
    opt.opts.setvar(var.strip(), val.strip())

