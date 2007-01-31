#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd.
#============================================================================

"""Object-oriented command-line option support.
"""
import getopt
import os
import os.path
import sys
import types

def _line_wrap(text, width = 70):
    lines = []
    current_line = ''
    words = text.strip().split()
    while words:
        word = words.pop(0)
        if len(current_line) + len(word) + 1 < width:
            current_line += word + ' '
        else:
            lines.append(current_line.strip())
            current_line = word + ' '
            
    if current_line:
        lines.append(current_line.strip())
    return lines

def wrap(text, width = 70):
    """ Really basic textwrap. Useful because textwrap is not available
    for Python 2.2, and textwrap.wrap ignores newlines in Python 2.3+.
    """
    if len(text) < width:
        return [text]
    
    lines = []
    for line in text.split('\n'):
        lines += _line_wrap(line, width)
    return lines

class OptionError(Exception):
    """Denotes an error in option parsing."""
    def __init__(self, message, usage = ''):
        self.message = message
        self.usage = usage
    def __str__(self):
        return self.message

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


    def reset(self):
        self.specified_opt = None
        self.specified_val = None
        self.value = None
        self.set(self.default)


    def __repr__(self):
        return self.name + '=' + str(self.specified_val)

    def __str__(self):
        """ Formats the option into:
        '-k, --key     description'
        """
        PARAM_WIDTH = 20
        if self.val:
            keys = ', '.join(['%s=%s' % (k, self.val) for k in self.optkeys])
        else:
            keys = ', '.join(self.optkeys)
        desc = wrap(self.use, 55)
        if len(keys) > PARAM_WIDTH:
            desc = [''] + desc
            
        wrapped = ('\n' + ' ' * (PARAM_WIDTH + 1)).join(desc)
        return keys.ljust(PARAM_WIDTH + 1) + wrapped

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

    def format(self, str, start='    ', out=sys.stdout):
        """Print a string, with consistent indentation at the start of lines.
        """
        lines = str.split('\n')
        for l in lines:
            l = l.strip()
            if start:
                out.write(start)
            out.write(l)
            out.write('\n')

    def show(self, out=sys.stdout):
        sep = ' '
        for x in self.optkeys:
            out.write(sep)
            out.write(x)
            sep = ', '
        if self.val:
            out.write(' ')
            out.write(self.val)
        out.write('\n')
        if self.use:
            self.format(self.use, out=out);
        if self.val:
            self.format('Default ' + str(self.default or 'None'), out=out)

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

    def show(self, out=sys.stdout):
        print >>out, ' %s=%s' % (self.optkeys[0], self.val) 
        if self.use:
            self.format(self.use, out=out);
        if self.val:
            self.format('Default ' + str(self.default or 'None'), out=out)

class OptVals:
    """Class to hold option values.
    """
    def __init__(self):
        self.quiet = False

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
        # Variables for default scripts.
        self.vars = {}
        # Option to use for bare words.
        self.default_opt = None


    def reset(self):
        self.vals = OptVals()
        self.vars = {}
        for opt in self.options:
            opt.reset()


    def __repr__(self):
        return '\n'.join(map(str, self.options))

    def __str__(self):
        options = [s for s in self.options if s.optkeys[0][0] == '-']
        output = ''
        if options:
            output += '\nOptions:\n\n'
            output += '\n'.join([str(o) for o in options])
            output += '\n'
        return output

    def val_usage(self):
        optvals = [s for s in self.options if s.optkeys[0][0] != '-']
        output = ''
        if optvals:
            output += '\nValues:\n\n'
            output += '\n'.join([str(o) for o in optvals])
            output += '\n'
        return output
    
    def opt(self, name, **args):
        """Add an option.

        name    option name
        **args  keyword params for option constructor
        """
        x = Opt(self, name, **args)
        self.options.append(x)
        self.options_map[name] = x
        return x

    def default(self, name):
        self.default_opt = name

    def getdefault(self, val):
        if self.default_opt is None:
            return 0
        opt = self.option(self.default_opt)
        return opt.set(val)

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

        # hack to work around lack of gnu getopts parsing in python 2.2
        args = argv[1:]
        xargs = []
        while args:
            # let getopt parse whatever it feels like -- if anything
            try:
                (xvals, args) = getopt.getopt(args[0:],
                                              self.short_opts(),
                                              self.long_opts())
            except getopt.GetoptError, err:
                raise OptionError(str(err), self.use)
            #self.err(str(err))
                
            for (k, v) in xvals:
                for opt in self.options:
                    if opt.specify(k, v): break
                else:
                    raise OptionError('Unknown option: %s' % k, self.use)

            if not args:
                break
            
            # then process the 1st arg 
            (arg,args) = (args[0], args[1:])

            isvar = 0
            if '=' in arg:
                (k, v) = arg.split('=', 1)
                for opt in self.options:
                    if opt.specify(k, v):
                        isvar = 1
                        break
            elif self.getdefault(arg):
                isvar = 1
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
        print
        if self.options:
            for opt in self.options:
                opt.show()
                print
            print

    def var_usage(self):
        if self.vars:
            print 'The config file defines the following variables:'
            for var in self.vars:
                var.show()
                print
            print

    def config_usage(self):
        if self.imports:
            print 'The following are automically imported:'
            for x in self.imports:
                print '   ', x
            print
        self.var_usage()

    def load_defconfig(self, help=0):
        """Load a defconfig script. Assumes these options set:
        'path'    search path
        'defconfig' script name
        """
        for x in [ '' ] + self.vals.path.split(':'):
            if x:
                p = os.path.join(x, self.vals.defconfig)
            else:
                p = self.vals.defconfig
            if not p.startswith('/'):
                p = os.path.join(os.path.curdir, p)
            if os.path.exists(p):
                self.info('Using config file "%s".' % p)
                self.load(p, help)
                break
        else:
            raise OptionError('Unable to open config file: %s' % \
                              self.vals.defconfig,
                              self.use)

    def load(self, defconfig, help):
        """Load a defconfig file. Local variables in the file
        are used to set options with the same names.
        Variables are not used to set options that are already specified.
        """
        # Create global and local dicts for the file.
        # Initialize locals to the vars.
        # Use exec to do the standard imports and
        # define variables we are passing to the script.
        globs = {}
        locs = {}
        locs.update(self.vars)
        cmd = '\n'.join(self.imports + 
                        [ "from xen.xm.help import Vars",
                          "xm_file = '%s'" % defconfig,
                          "xm_help = %d" % help,
                          "xm_vars = Vars(xm_file, xm_help, locals())"
                          ])
        exec cmd in globs, locs
        try:
            execfile(defconfig, globs, locs)
        except SyntaxError,e:
                raise SyntaxError, \
                "Errors were found at line %d while processing %s:\n\t%s"\
                %(e.lineno,defconfig,e.text)
        except:
            if not help: raise
        if help:
            self.config_usage()
            return
        # Extract the values set by the script and set the corresponding
        # options, if not set on the command line.
        vtypes = [ types.StringType,
                   types.ListType,
                   types.IntType,
                   types.FloatType
                   ]
        for (k, v) in locs.items():
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
    if v in ('yes', 'y'):
        opt.set(1)
    elif v in ('no', 'n'):
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

def set_long(opt, k, v):
    """Set an option to a long integer value."""
    try:
        v = long(v)
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

