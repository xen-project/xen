#!/usr/bin/python
import string
import sys

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
        self.err("Unknown command: %s\nTry '%s help' for more information."
                 % (args[0], self.prog))

    def help(self, meth, args):
        name = meth[3:]
        f = getattr(self, meth)
        print "%s\t%s" % (name, f.__doc__ or '')

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
        """Save domain state to file."""
        if help:
            print args[0], "DOM FILE"
            print "\nSave domain with id DOM to FILE."
            return
        if len(args) < 3: self.err("%s: Missing arguments" % args[0])
        dom = args[1]
        filename = args[2]
        server.xend_domain_save(dom, filename)

    def xm_restore(self, help, args):
        """Create a domain from a saved state."""
        if help:
            print args[0], "FILE"
            print "\nRestore a domain from FILE."
        if len(args) < 2: self.err("%s: Missing file" % args[0])
        server.xend_domain_restore(dom, None, filename)

    def xm_ls(self, help, args):
        """List domains."""
        if help: self.help('xm_' + args[0]); return
        doms = server.xend_domains()
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
            print ("%(dom)-4d %(name)-16s %(mem)4d     %(cpu)3d %(state)5s %(cpu_time)10.2f" % d)

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

    def xm_stop(self, help, args):
        """Stop execution of a domain."""
        if help:
            print args[0], 'DOM'
            print '\nStop execution of domain DOM.'
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_stop(dom)

    def xm_start(self, help, args):
        """Start execution of a domain."""
        if help:
            print args[0], 'DOM'
            print '\nStart execution of domain DOM.'
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_start(dom)

    def xm_pincpu(self, help, args):
        """Pin a domain to a cpu. """
        if help:
            print args[0],'DOM CPU'
            print '\nPin domain DOM to cpu CPU.'
            return
        if len(args) != 3: self.err("%s: Invalid argument(s)" % args[0])
        v = map(int, args[1:3])
        server.xend_domain_pincpu(*v)

    def xm_vif_stats(self, help, args):
        """Get stats for a virtual interface."""
        if help:
            print args[0], 'DOM VIF'
            print '\nGet stats for interface VIF on domain DOM.'
            return
        if len(args) != 3: self.err("%s: Invalid argument(s)" % args[0])
        v = map(int, args[1:3])
        print server.xend_domain_vif_stats(*v)

    def xm_vif_rate(self, help, args):
        """Set or get vif rate params."""
        if help:
            print args[0], "DOM VIF [BYTES USECS]"
            print '\nSet or get rate controls for interface VIF on domain DOM.'
            return
        n = len(args)
        if n == 3:
            v = map(int, args[1:n])
            print server.xend_domain_vif_scheduler_get(*v)
        elif n == 5:
            v = map(int, args[1:n])
            server.xend_domain_vif_scheduler_set(*v)
        else:
            self.err("%s: Invalid argument(s)" % args[0])

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
        slice = int(args[1])
        server.xend_node_rrobin_set(slice)

    def xm_info(self, help, args):
        """Get information about the xen host."""
        if help: self.help('xm_info'); return
        info = server.xend_node()
        for x in info[1:]:
            print "%-23s:" % x[0], x[1]

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
