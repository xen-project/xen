#!/usr/bin/python
import string
import sys

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
            print "save DOM FILE"
            print "\nSave domain with id DOM to FILE."
            return
        if len(args) < 3: self.err("%s: Missing arguments" % args[0])
        dom = args[1]
        filename = args[2]
        server.xend_domain_save(dom, filename)

    def xm_restore(self, help, args):
        """Create a domain from a saved state."""
        if help:
            print "restore FILE"
            print "\nRestore a domain from FILE."
        if len(args) < 2: self.err("%s: Missing file" % args[0])
        server.xend_domain_restore(dom, None, filename)

    def xm_ls(self, help, args):
        """List domains."""
        if help: self.help('xm_ls'); return
        doms = server.xend_domains()
        for dom in doms:
            d = server.domain(dom)
            print d

    def xm_halt(self, help, args):
        """Terminate a domain immediately."""
        if help:
            print 'halt DOM'
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
            print 'stop DOM'
            print '\nStop execution of domain DOM.'
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_stop(dom)

    def xm_start(self, help, args):
        """Start execution of a domain."""
        if help:
            print 'start DOM'
            print '\nStart execution of domain DOM.'
            return
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_start(dom)

    def xm_pincpu(self, help, args):
        """Pin a domain to a cpu. """
        if help:
            print 'pincpu DOM CPU'
            print '\nPin domain DOM to cpu CPU.'
            return
        pass

    def xm_bvt(self, help, args):
        pass

    def xm_bvtslice(self, help, args):
        pass

    def xm_atropos(self, help, args):
        pass

    def xm_rrslice(self, help, args):
        pass

    def xm_info(self, help, args):
        """Get information about the xen host."""
        if help: self.help('xm_info'); return
        info = server.xend_node()
        for x in info:
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
