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

class Xm:

    def __init__(self):
        self.prog = 'xm'
        pass

    def err(self, msg):
        print >>sys.stderr, "Error:", msg
        sys.exit(1)

    def main(self, args):
        """Main entry point. Dispatches to the xm_ methods.
        """
        self.prog = args[0]
        if len(args) < 2:
            self.err("Missing command\nTry '%s help' for more information."
                     % self.prog)
        prog = 'xm_' + args[1]
        help = self.helparg(args)
        fn = getattr(self, prog, self.unknown)
        fn(help, args[1:])

    def helparg(self, args):
        for a in args:
            if a in ['-h', '--help']:
                return 1
        return 0

    def unknown(self, help, args):
        if help and len(args) == 1:
            self.xm_help(help, args)
        else:
            self.err("Unknown command: %s\nTry '%s help' for more information."
                     % (args[0], self.prog))

    def help(self, meth, args):
        """Print help on an xm_ method.
        Uses the method documentation string if there is one.
        """
        name = meth[3:]
        f = getattr(self, meth)
        print "%-14s %s" % (name, f.__doc__ or '')

    def xm_help(self, help, args):
        """Print help."""
        for k in dir(self):
            if not k.startswith('xm_'): continue
            self.help(k, args)
        print "\nTry '%s CMD -h' for help on CMD" % self.prog
                
    def xm_create(self, help, args):
        """Create a domain."""
        create.main(args)

    def xm_save(self, help, args):
        """Save domain state (and config) to file."""
        if help:
            print args[0], "DOM FILE [CONFIG]"
            print """\nSave domain with id DOM to FILE.
            Optionally save config to CONFIG."""
            return
        if len(args) < 3: self.err("%s: Missing arguments" % args[0])
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
            
    def xm_restore(self, help, args):
        """Create a domain from a saved state."""
        if help:
            print args[0], "FILE CONFIG"
            print "\nRestore a domain from FILE using configuration CONFIG."
            return
        if len(args) < 3: self.err("%s: Missing arguments" % args[0])
        savefile =  os.path.abspath(args[1])
        configfile = os.path.abspath(args[2])
        info = server.xend_domain_restore(savefile, configfile)
        PrettyPrint.prettyprint(info)

    def xm_domains(self, help, args):
        """List domains."""
        if help: self.help('xm_' + args[0], args); return
        doms = server.xend_domains()
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

    def xm_domain(self, help, args):
        """Get information about a domain."""
        if help:
            print args[0], 'DOM'
            print '\nGet information about domain DOM.'
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        info = server.xend_domain(dom)
        PrettyPrint.prettyprint(info)
        print

    def xm_halt(self, help, args):
        """Terminate a domain immediately."""
        if help:
            print args[0], 'DOM'
            print '\nTerminate domain DOM immediately.'
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_halt(dom)

    def xm_shutdown(self, help, args):
        """Shutdown a domain."""
        shutdown.main(args)

    def xm_pause(self, help, args):
        """Pause execution of a domain."""
        if help:
            print args[0], 'DOM'
            print '\nPause execution of domain DOM.'
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_pause(dom)

    def xm_unpause(self, help, args):
        """Unpause a paused domain."""
        if help:
            print args[0], 'DOM'
            print '\nUnpause execution of domain DOM.'
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_unpause(dom)

    def xm_pincpu(self, help, args):
        """Pin a domain to a cpu. """
        if help:
            print args[0],'DOM CPU'
            print '\nPin domain DOM to cpu CPU.'
            return
        if len(args) != 3: self.err("%s: Invalid argument(s)" % args[0])
        v = map(int, args[1:3])
        server.xend_domain_pincpu(*v)

    def xm_bvt(self, help, args):
        """Set BVT scheduler parameters."""
        if help:
            print args[0], "DOM MCUADV WARP WARPL WARPU"
            print '\nSet Borrowed Virtual Time scheduler parameters.'
            return
        if len(args) != 6: self.err("%s: Invalid argument(s)" % args[0])
        v = map(int, args[1:6])
        server.xend_domain_cpu_bvt_set(*v)

    def xm_bvtslice(self, help, args):
        """Set the BVT scheduler slice."""
        if help:
            print args[0], 'SLICE'
            print '\nSet Borrowed Virtual Time scheduler slice.'
            return
        if len(args) < 2: self.err('%s: Missing slice' % args[0])
        server.xend_node_cpu_bvt_slice_set(slice)

    def xm_atropos(self, help, args):
        """Set atropos parameters."""
        if help:
            print args[0], "DOM PERIOD SLICE LATENCY XTRATIME"
            print "\nSet atropos parameters."
            return
        if len(args) != 5: self.err("%s: Invalid argument(s)" % args[0])
        v = map(int, args[1:5])
        server.xend_domain_cpu_atropos_set(*v)

    def xm_rrobin(self, help, args):
        """Set round robin slice."""
        if help:
            print args[0], "SLICE"
            print "\nSet round robin scheduler slice."
            return
        if len(args) != 2: self.err("%s: Invalid argument(s)" % args[0])
        rrslice = int(args[1])
        server.xend_node_rrobin_set(rrslice)

    def xm_info(self, help, args):
        """Get information about the xen host."""
        if help: self.help('xm_' + args[0], args); return
        info = server.xend_node()
        for x in info[1:]:
            print "%-23s:" % x[0], x[1]

    def xm_consoles(self, help, args):
        """Get information about domain consoles."""
        if help: self.help('xm_' + args[0], args); return
        l = server.xend_consoles()
        print "Dom Port  Id"
        for x in l:
            info = server.xend_console(x)
            d = {}
            d['dom'] = sxp.child(info, 'dst', ['dst', '?', '?'])[1]
            d['port'] = sxp.child_value(info, 'port', '?')
            d['id'] = sxp.child_value(info, 'id', '?')
            print "%(dom)3s %(port)4s %(id)3s" % d

    def xm_console(self, help, args):
        """Open a console to a domain."""
        if help:
            print "console DOM"
            print "\nOpen a console to domain DOM."
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        info = server.xend_domain(dom)
        console = sxp.child(info, "console")
        if not console:
            self.err("No console information")
        port = sxp.child_value(console, "port")
        from xenctl import console_client
        console_client.connect("localhost", int(port))

def main(args):
    xm = Xm()
    xm.main(args)
