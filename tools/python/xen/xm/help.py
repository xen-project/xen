# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Variable definition and help support for Python defconfig files.
"""

import sys

class Vars:
    """A set of configuration variables.
    """

    def __init__(self, name, help, env):
        """Create a variable set.

        name name of the defconfig file
        help help flag
        env  local environment
        """
        self.name = name
        self.help = help
        self.env = env
        self.vars = []

    def var(self, name, use=None, check=None):
        """Define a configuration variable.
        If provided, the check function will be called as check(var, val)
        where var is the variable name and val is its value (string).
        It should return a new value for the variable, or raise ValueError if
        the value is not acceptable.

        name  variable name
        use   variable usage string
        check variable check function
        """
        self.vars.append(Var(name, use, check))

    def check(self):
        """Execute the variable checks or print help, depending on the value
        of the help flag passed to the constructor.
        """
        if self.help:
            self.doHelp()
        else:
            for v in self.vars:
                v.doCheck(self.env)

    def doHelp(self, out=sys.stderr):
        """Print help for the variables.
        """
        if self.vars:
            print >>out, "\nConfiguration variables for %s:\n" % self.name
            for v in self.vars:
                v.doHelp(out)
            print >>out

class Var:
    """A single variable.
    """

    def __init__(self, name, use, check):
        """Create a variable.

        name  variable name
        use   variable use string
        check variable value check function
        """
        self.name = name
        self.use = use or ''
        self.check = check

    def doCheck(self, env):
        """Execute the check and set the variable to the new value.
        """
        if not self.check: return
        env[self.name] = self.check(self.name, env.get(self.name))

    def doHelp(self, out):
        """Print help for the variable.
        """
        print >>out, "%-12s" % self.name, self.use

        
