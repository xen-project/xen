# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Grand unified management application for Xen.
"""
import os
import os.path
import sys

from xenmgr import PrettyPrint
from xenmgr import sxp
from xenmgr.XendClient import server
from xenmgr.xm import create, shutdown

class Prog:
    """Base class for sub-programs.
    """

    """Program group it belongs to"""
    group = 'all'
    """Program name."""
    name = '??'
    """Short program info."""
    info = ''

    def __init__(self, xm):
        self.xm = xm

    def err(self, msg):
        self.xm.err(msg)

    def help(self, args):
        self.shortHelp(args)

    def shortHelp(self, args):
        print "%-14s %s" % (self.name, self.info)

    def main(self, args):
        """Program main entry point.
        """
        pass


class ProgUnknown(Prog):

    name = 'unknown'
    info = ''
    
    def help(self, args):
        self.xm.err("Unknown command: %s\nTry '%s help' for more information."
                    % (args[0], self.xm.name))

    main = help

class Xm:
    """Main application.
    """

    def __init__(self):
        self.name = 'xm'
        self.unknown = ProgUnknown(self)
        self.progs = {}

    def err(self, msg):
        print >>sys.stderr, "Error:", msg
        sys.exit(1)

    def main(self, args):
        """Main entry point. Dispatches to the progs.
        """
        self.name = args[0]
        if len(args) < 2:
            self.err("Missing command\nTry '%s help' for more information."
                     % self.name)
        help = self.helparg(args)
        p = self.getprog(args[1], self.unknown)
        if help:
            p.help(args[1:])
        else:
            p.main(args[1:])

    def helparg(self, args):
        for a in args:
            if a in ['-h', '--help']:
                return 1
        return 0

    def prog(self, pklass):
        """Add a sub-program.

        pklass  program class (Prog subclass)
        """
        p = pklass(self)
        self.progs[p.name] = p
        return p

    def getprog(self, name, val=None):
        """Get a sub-program.
        """
        return self.progs.get(name, val)

    def proglist(self):
        """Get a list of sub-programs, ordered by group.
        """
        groups = {}
        for p in self.progs.values():
            l = groups.get(p.group, [])
            l.append(p)
            groups[p.group] = l
        kl = groups.keys()
        kl.sort()
        pl = []
        for k in kl:
            l = groups[k]
            l.sort()
            pl += l
        return pl
        
# Create the application object, then add the sub-program classes.
xm = Xm()

class ProgHelp(Prog):

    name = "help"
    info = "Print help."
    
    def help(self, args):
        if len(args) == 2:
            name = args[1]
            p = self.xm.getprog(name)
            if p:
                p.help(args)
            else:
                print '%s: Unknown command: %s' % (self.name, name)
        else:
            for p in self.xm.proglist():
                p.shortHelp(args)
            print "\nTry '%s help CMD' for help on CMD" % self.xm.name

    main = help

xm.prog(ProgHelp)

class ProgCreate(Prog):

    group = 'domain'
    name = "create"
    info = """Create a domain."""

    def help(self, args):
        create.main([args[0], '-h'])

    def main(self, args):
        create.main(args)

xm.prog(ProgCreate)

class ProgSave(Prog):
    group = 'domain'
    name = "save"
    info = """Save domain state (and config) to file."""

    def help(self, args):
        print self.name, "DOM FILE [CONFIG]"
        print """\nSave domain with id DOM to FILE.
        Optionally save config to CONFIG."""
        
    def main(self, args):
        if len(args) < 3: self.err("%s: Missing arguments" % self.name)
        dom = args[1]
        savefile = os.path.abspath(args[2])
        configfile = None
        if len(args) == 4:
            configfile = os.path.abspath(args[3])
        if configfile:
            out = file(configfile, 'w')
            config = server.xend_domain(dom)
            PrettyPrint.prettyprint(config, out=out)
            out.close()
        server.xend_domain_save(dom, savefile)

xm.prog(ProgSave)

class ProgRestore(Prog):
    group = 'domain'
    name = "restore"
    info = """Create a domain from a saved state."""

    def help(self, args):
        print self.name, "FILE CONFIG"
        print "\nRestore a domain from FILE using configuration CONFIG."
    
    def main(self, help, args):
        if len(args) < 3: self.err("%s: Missing arguments" % self.name)
        savefile =  os.path.abspath(args[1])
        configfile = os.path.abspath(args[2])
        info = server.xend_domain_restore(savefile, configfile)
        PrettyPrint.prettyprint(info)

xm.prog(ProgRestore)

class ProgList(Prog):
    group = 'domain'
    name = "list"
    info = """List info about domains."""

    def help(self, args):
        if help:
            print self.name, '[DOM...]'
            print """\nGet information about domains.
            Either all domains or the domains given."""
            return
        
    def main(self, args):
        n = len(args)
        if n == 1:
            doms = server.xend_domains()
        else:
            doms = map(int, args[1:])
        doms.sort()
        print 'Dom  Name             Mem(MB)  CPU  State  Time(s)'
        for dom in doms:
            info = server.xend_domain(dom)
            d = {}
            d['dom'] = int(dom)
            d['name'] = sxp.child_value(info, 'name', '??')
            d['mem'] = int(sxp.child_value(info, 'memory', '0'))
            d['cpu'] = int(sxp.child_value(info, 'cpu', '0'))
            d['state'] = sxp.child_value(info, 'state', '??')
            d['cpu_time'] = float(sxp.child_value(info, 'cpu_time', '0'))
            print ("%(dom)-4d %(name)-16s %(mem)7d  %(cpu)3d  %(state)5s  %(cpu_time)7.1f" % d)

xm.prog(ProgList)

class ProgDestroy(Prog):
    group = 'domain'
    name = "destroy"
    info = """Terminate a domain immediately."""

    def help(self, args):
        print self.name, 'DOM'
        print '\nTerminate domain DOM immediately.'

    def main(self, args):
        if len(args) < 2: self.err("%s: Missing domain" % self.name)
        dom = args[1]
        server.xend_domain_destroy(dom)

xm.prog(ProgDestroy)

class ProgShutdown(Prog):
    group = 'domain'
    name = "shutdown"
    info = """Shutdown a domain."""

    def help(self, args):
        print self.name, 'DOM'
        print '\nSignal domain DOM to shutdown.'
    
    def main(self, args):
        shutdown.main(args)

xm.prog(ProgShutdown)

class ProgPause(Prog):
    group = 'domain'
    name = "pause"
    info = """Pause execution of a domain."""

    def help(self, args):
        print self.name, 'DOM'
        print '\nPause execution of domain DOM.'

    def main(self, args):
        if len(args) < 2: self.err("%s: Missing domain" % self.name)
        dom = args[1]
        server.xend_domain_pause(dom)

xm.prog(ProgPause)

class ProgUnpause(Prog):
    group = 'domain'
    name = "unpause"
    info = """Unpause a paused domain."""

    def help(self, args):
        print self.name, 'DOM'
        print '\nUnpause execution of domain DOM.'

    def main(self, args):
        if len(args) < 2: self.err("%s: Missing domain" % self.name)
        dom = args[1]
        server.xend_domain_unpause(dom)

xm.prog(ProgUnpause)

class ProgPincpu(Prog):
    group = 'domain'
    name = "pincpu"
    info = """Pin a domain to a cpu. """

    def help(self, args):
        print self.name,'DOM CPU'
        print '\nPin domain DOM to cpu CPU.'

    def main(self, args):
        if len(args) != 3: self.err("%s: Invalid argument(s)" % self.name)
        v = map(int, args[1:3])
        server.xend_domain_pincpu(*v)

xm.prog(ProgPincpu)

class ProgBvt(Prog):
    group = 'scheduler'
    name = "bvt"
    info = """Set BVT scheduler parameters."""
    
    def help(self, args):
        print self.name, "DOM MCUADV WARP WARPL WARPU"
        print '\nSet Borrowed Virtual Time scheduler parameters.'

    def main(self, args):
        if len(args) != 6: self.err("%s: Invalid argument(s)" % self.name)
        v = map(int, args[1:6])
        server.xend_domain_cpu_bvt_set(*v)

xm.prog(ProgBvt)

class ProgBvtslice(Prog):
    group = 'scheduler'
    name = "bvtslice"
    info = """Set the BVT scheduler slice."""

    def help(self, args):
        print self.name, 'SLICE'
        print '\nSet Borrowed Virtual Time scheduler slice.'

    def main(self, args):
        if len(args) < 2: self.err('%s: Missing slice' % self.name)
        server.xend_node_cpu_bvt_slice_set(slice)

xm.prog(ProgBvtslice)

class ProgAtropos(Prog):
    group = 'scheduler'
    name= "atropos"
    info = """Set atropos parameters."""

    def help(self, args):
        print self.name, "DOM PERIOD SLICE LATENCY XTRATIME"
        print "\nSet atropos parameters."

    def main(self, args):
        if len(args) != 5: self.err("%s: Invalid argument(s)" % self.name)
        v = map(int, args[1:5])
        server.xend_domain_cpu_atropos_set(*v)

xm.prog(ProgAtropos)

class ProgRrobin(Prog):
    group = 'scheduler'
    name = "rrobin"
    info = """Set round robin slice."""

    def help(self, args):
        print self.name, "SLICE"
        print "\nSet round robin scheduler slice."

    def main(self, args):
        if len(args) != 2: self.err("%s: Invalid argument(s)" % self.name)
        rrslice = int(args[1])
        server.xend_node_rrobin_set(rrslice)

xm.prog(ProgRrobin)

class ProgInfo(Prog):
    group = 'host'
    name = "info"
    info = """Get information about the xen host."""

    def main(self, args):
        info = server.xend_node()
        for x in info[1:]:
            print "%-23s:" % x[0], x[1]

xm.prog(ProgInfo)

class ProgConsoles(Prog):
    group = 'console'
    name = "consoles"
    info = """Get information about domain consoles."""

    def main(self, args):
        l = server.xend_consoles()
        print "Dom Port  Id"
        for x in l:
            info = server.xend_console(x)
            d = {}
            d['dom'] = sxp.child(info, 'dst', ['dst', '?', '?'])[1]
            d['port'] = sxp.child_value(info, 'port', '?')
            d['id'] = sxp.child_value(info, 'id', '?')
            print "%(dom)3s %(port)4s %(id)3s" % d

xm.prog(ProgConsoles)

class ProgConsole(Prog):
    group = 'console'
    name = "console"
    info = """Open a console to a domain."""
    
    def help(self, args):
        print self.name, "DOM"
        print "\nOpen a console to domain DOM."

    def main(self, args):
        if len(args) < 2: self.err("%s: Missing domain" % self.name)
        dom = args[1]
        info = server.xend_domain(dom)
        console = sxp.child(info, "console")
        if not console:
            self.err("No console information")
        port = sxp.child_value(console, "port")
        from xenctl import console_client
        console_client.connect("localhost", int(port))

xm.prog(ProgConsole)

def main(args):
    xm.main(args)
