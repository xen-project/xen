# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Grand unified management application for Xen.
"""
import os
import os.path
import sys
from getopt import getopt
import socket

from xen.xend import PrettyPrint
from xen.xend import sxp
from xen.xend.XendClient import XendError, server
from xen.xend.XendClient import main as xend_client_main
from xen.xm import create, destroy, migrate, shutdown
from xen.xm.opts import *

class Group:

    name = ""
    info = ""
    
    def __init__(self, xm):
        self.xm = xm
        self.progs = {}

    def addprog(self, prog):
        self.progs[prog.name] = prog

    def getprog(self, name):
        return self.progs.get(name)

    def proglist(self):
        kl = self.progs.keys()
        kl.sort()
        return [ self.getprog(k) for k in kl ]

    def help(self, args):
        if self.info:
            print 
            print self.info
            print
        else:
            print
        
    def shortHelp(self, args):
        self.help(args)
        for p in self.proglist():
            p.shortHelp(args)

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
        self.groups = {}

    def err(self, msg):
        print >>sys.stderr, "Error:", msg
        sys.exit(1)

    def main(self, args):
        try:
            self.main_call(args)
        except socket.error, ex:
            print >>sys.stderr, ex
            self.err("Error connecting to xend, is xend running?")
        except XendError, ex:
            self.err(str(ex))

    def main_call(self, args):
        """Main entry point. Dispatches to the progs.
        """
        self.name = args[0]
        if len(args) < 2:
        	args.append('help')
	help = self.helparg(args)
        p = self.getprog(args[1], self.unknown)
        if help or len(args) < 2: 
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
        self.getgroup(p.group).addprog(p)
        return p

    def getprog(self, name, val=None):
        """Get a sub-program.
        name  Name of the sub-program (or optionally, an unambiguous
              prefix of its name)
        val   Default return value if no (unique) match is found
        """

        match = None
        for progname in self.progs.keys():
            if progname == name:
                match = progname
                break
            if progname.startswith(name):
                if not match:
                    match = progname
                else:
                    return val # name is ambiguous - bail out

        return self.progs.get(match, val)

    def group(self, klass):
        g = klass(self)
        self.groups[g.name] = g
        return g

    def getgroup(self, name):
        return self.groups[name]

    def grouplist(self):
        kl = self.groups.keys()
        kl.sort()
        return [ self.getgroup(k) for k in kl ]
        
# Create the application object, then add the sub-program classes.
xm = Xm()

class GroupAll(Group):

    name = "all"
    info = ""

xm.group(GroupAll)

class GroupDomain(Group):

    name = "domain"
    info = "Commands on domains:"
    
xm.group(GroupDomain)

class GroupScheduler(Group):

    name = "scheduler"
    info = "Comands controlling scheduling:"

xm.group(GroupScheduler)

class GroupHost(Group):

    name = "host"
    info = "Commands related to the xen host (node):"

xm.group(GroupHost)

class GroupConsole(Group):

    name = "console"
    info = "Commands related to consoles:"

xm.group(GroupConsole)

class GroupVbd(Group):

    name = "vbd"
    info = "Commands related to virtual block devices:"

xm.group(GroupVbd)

class GroupVif(Group):

    name = "vif"
    info = "Commands related to virtual network interfaces:"

xm.group(GroupVif)

class ProgHelp(Prog):

    name = "help"
    info = "Print help."
    
    def help(self, args):
        if len(args) == 2:
            name = args[1]
            p = self.xm.getprog(name)
            if p:
                p.help(args[1:])
            else:
                print '%s: Unknown command: %s' % (self.name, name)
        else:
            for g in self.xm.grouplist():
                g.shortHelp(args)
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
        print args[0], "DOM FILE"
        print """\nSave domain with id DOM to FILE."""
        
    def main(self, args):
        if len(args) < 3: self.err("%s: Missing arguments" % args[0])
        dom = args[1]
        savefile = os.path.abspath(args[2])
        server.xend_domain_save(dom, savefile)

xm.prog(ProgSave)

class ProgRestore(Prog):
    group = 'domain'
    name = "restore"
    info = """Create a domain from a saved state."""

    def help(self, args):
        print args[0], "FILE"
        print "\nRestore a domain from FILE."
    
    def main(self, args):
        if len(args) < 2: self.err("%s: Missing arguments" % args[0])
        savefile = os.path.abspath(args[1])
        info = server.xend_domain_restore(savefile)
        PrettyPrint.prettyprint(info)
        id = sxp.child_value(info, 'id')
        if id is not None:
            server.xend_domain_unpause(id)

xm.prog(ProgRestore)

class ProgMigrate(Prog):
    group = 'domain'
    name = "migrate"
    info = """Migrate a domain to another machine."""

    def help(self, args):
        migrate.help([self.name] + args)
    
    def main(self, args):
        migrate.main(args)

xm.prog(ProgMigrate)

class ProgList(Prog):
    group = 'domain'
    name = "list"
    info = """List information about domains."""

    short_options = 'l'
    long_options = ['long']

    def help(self, args):
        if help:
            print args[0], '[options] [DOM...]'
            print """\nGet information about domains.
            Either all domains or the domains given.

            -l, --long   Get more detailed information.
            """
            return
        
    def main(self, args):
        use_long = 0
        (options, params) = getopt(args[1:],
                                   self.short_options,
                                   self.long_options)
        n = len(params)
        for (k, v) in options:
            if k in ['-l', '--long']:
                use_long = 1
                
        if n == 0:
            doms = server.xend_domains()
            doms.sort()
        else:
            doms = params
            
        if use_long:
            self.long_list(doms)
        else:
            self.brief_list(doms)

    def brief_list(self, doms):
        print 'Name              Id  Mem(MB)  CPU  State  Time(s)  Console'
        for dom in doms:
            info = server.xend_domain(dom)
            d = {}
            d['dom'] = int(sxp.child_value(info, 'id', '-1'))
            d['name'] = sxp.child_value(info, 'name', '??')
            d['mem'] = int(sxp.child_value(info, 'memory', '0'))
            d['cpu'] = int(sxp.child_value(info, 'cpu', '0'))
            d['state'] = sxp.child_value(info, 'state', '??')
            d['cpu_time'] = float(sxp.child_value(info, 'cpu_time', '0'))
            console = sxp.child(info, 'console')
            if console:
                d['port'] = sxp.child_value(console, 'console_port')
            else:
                d['port'] = ''
            print ("%(name)-16s %(dom)3d  %(mem)7d  %(cpu)3d  %(state)5s  %(cpu_time)7.1f    %(port)4s"
                   % d)

    def long_list(self, doms):
        for dom in doms:
            info = server.xend_domain(dom)
            PrettyPrint.prettyprint(info)

xm.prog(ProgList)

class ProgDestroy(Prog):
    group = 'domain'
    name = "destroy"
    info = """Terminate a domain immediately."""

    def help(self, args):
        destroy.main([args[0], '-h'])

    def main(self, args):
        destroy.main(args)

xm.prog(ProgDestroy)

class ProgShutdown(Prog):
    group = 'domain'
    name = "shutdown"
    info = """Shutdown a domain."""

    def help(self, args):
        shutdown.main([args[0], '-h'])
    
    def main(self, args):
        shutdown.main(args)

xm.prog(ProgShutdown)

class ProgPause(Prog):
    group = 'domain'
    name = "pause"
    info = """Pause execution of a domain."""

    def help(self, args):
        print args[0], 'DOM'
        print '\nPause execution of domain DOM.'

    def main(self, args):
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_pause(dom)

xm.prog(ProgPause)

class ProgUnpause(Prog):
    group = 'domain'
    name = "unpause"
    info = """Unpause a paused domain."""

    def help(self, args):
        print args[0], 'DOM'
        print '\nUnpause execution of domain DOM.'

    def main(self, args):
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        server.xend_domain_unpause(dom)

xm.prog(ProgUnpause)

class ProgPincpu(Prog):
    group = 'domain'
    name = "pincpu"
    info = """Pin a domain to a cpu. """

    def help(self, args):
        print args[0],'DOM CPU'
        print '\nPin domain DOM to cpu CPU.'

    def main(self, args):
        if len(args) != 3: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        cpu = int(args[2])
        server.xend_domain_pincpu(dom, cpu)

xm.prog(ProgPincpu)

class ProgMaxmem(Prog):
    group = 'domain'
    name = 'maxmem'
    info = """Set domain memory limit."""

    def help(self, args):
        print args[0], "DOM MEMORY"
        print "\nSet the memory limit for domain DOM to MEMORY megabytes."

    def main(self, args):
        if len(args) != 3: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        mem = int(args[2])
        server.xend_domain_maxmem_set(dom, mem)

xm.prog(ProgMaxmem)

class ProgBalloon(Prog):
    group = 'domain'
    name  = 'balloon'
    info  = """Set the domain's memory footprint using the balloon driver."""

    def help(self, args):
        print args[0], "DOM MEMORY_TARGET"
        print """\nRequest domain DOM to adjust its memory footprint to
MEMORY_TARGET megabytes"""

    def main(self, args):
        if len(args) != 3: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        mem_target = int(args[2])
        server.xend_domain_mem_target_set(dom, mem_target)

xm.prog(ProgBalloon)

class ProgDomid(Prog):
    group = 'domain'
    name = 'domid'
    info = 'Convert a domain name to a domain id.'

    def help(self, args):
        print args[0], "DOM"
        print '\nGet the domain id for the domain with name DOM.'
        
    def main (self, args):
        if len(args) != 2: self.err("%s: Invalid argument(s)" % args[0])
        name = args[1]
        dom = server.xend_domain(name)
        print sxp.child_value(dom, 'id')

xm.prog(ProgDomid)

class ProgDomname(Prog):
    group = 'domain'
    name = 'domname'
    info = 'Convert a domain id to a domain name.'

    def help(self, args):
        print args[0], "DOM"
        print '\nGet the name for the domain with id DOM.'
        
    def main (self, args):
        if len(args) != 2: self.err("%s: Invalid argument(s)" % args[0])
        name = args[1]
        dom = server.xend_domain(name)
        print sxp.child_value(dom, 'name')

xm.prog(ProgDomname)

class ProgBvt(Prog):
    group = 'scheduler'
    name = "bvt"
    info = """Set BVT scheduler parameters."""
    
    def help(self, args):
        print args[0], "DOM MCUADV WARPBACK WARPVALUE WARPL WARPU"
        print '\nSet Borrowed Virtual Time scheduler parameters.'

    def main(self, args):
        if len(args) != 7: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        v = map(long, args[2:7])
        server.xend_domain_cpu_bvt_set(dom, *v)

xm.prog(ProgBvt)

class ProgBvtslice(Prog):
    group = 'scheduler'
    name = "bvt_ctxallow"
    info = """Set the BVT scheduler context switch allowance."""

    def help(self, args):
        print args[0], 'CTX_ALLOW'
        print '\nSet Borrowed Virtual Time scheduler context switch allowance.'

    def main(self, args):
        if len(args) < 2: self.err('%s: Missing context switch allowance'
                                                            % args[0])
        slice = int(args[1])
        server.xend_node_cpu_bvt_slice_set(slice)

xm.prog(ProgBvtslice)


class ProgAtropos(Prog):
    group = 'scheduler'
    name= "atropos"
    info = """Set atropos parameters."""

    def help(self, args):
        print args[0], "DOM PERIOD SLICE LATENCY XTRATIME"
        print "\nSet atropos parameters."

    def main(self, args):
        if len(args) != 6: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        v = map(int, args[2:6])
        server.xend_domain_cpu_atropos_set(dom, *v)

xm.prog(ProgAtropos)

class ProgRrobin(Prog):
    group = 'scheduler'
    name = "rrobin"
    info = """Set round robin slice."""

    def help(self, args):
        print args[0], "SLICE"
        print "\nSet round robin scheduler slice."

    def main(self, args):
        if len(args) != 2: self.err("%s: Invalid argument(s)" % args[0])
        rrslice = int(args[1])
        server.xend_node_rrobin_set(rrslice)

xm.prog(ProgRrobin)

class ProgSedf(Prog):
    group = 'scheduler'
    name= "sedf"
    info = """Set simple EDF parameters."""

    def help(self, args):
        print args[0], "DOM PERIOD SLICE"
        print "\nSet simple EDF parameters."

    def main(self, args):
        if len(args) != 4: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        v = map(int, args[2:4])
        server.xend_domain_cpu_sedf_set(dom, *v)

xm.prog(ProgSedf)

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
        print "Dom Port  Id Connection"
        for x in l:
            info = server.xend_console(x)
            d = {}
            d['dom'] = sxp.child(info, 'domain', '?')[1]
            d['port'] = sxp.child_value(info, 'console_port', '?')
            d['id'] = sxp.child_value(info, 'id', '?')
            connected = sxp.child(info, 'connected')
            if connected:
                d['conn'] = '%s:%s' % (connected[1], connected[2])
            else:
                d['conn'] = ''
            print "%(dom)3s %(port)4s %(id)3s %(conn)s" % d

xm.prog(ProgConsoles)

class ProgConsole(Prog):
    group = 'console'
    name = "console"
    info = """Open a console to a domain."""
    
    def help(self, args):
        print args[0], "DOM"
        print "\nOpen a console to domain DOM."

    def main(self, args):
        if len(args) < 2: self.err("%s: Missing domain" % args[0])
        dom = args[1]
        info = server.xend_domain(dom)
        console = sxp.child(info, "console")
        if not console:
            self.err("No console information")
        port = sxp.child_value(console, "console_port")
        from xen.util import console_client
        console_client.connect("localhost", int(port))

xm.prog(ProgConsole)

class ProgCall(Prog):
    name = "call"
    info = "Call xend api functions."

    def help (self, args):
        print args[0], "function args..."
        print """
        Call a xend HTTP API function. The leading 'xend_' on the function
can be omitted. See xen.xend.XendClient for the API functions.
"""

    def main(self, args):
        xend_client_main(args)

xm.prog(ProgCall)

class ProgDmesg(Prog):
    group = 'host'
    name  =  "dmesg"
    info  = """Read or clear Xen's message buffer."""

    gopts = Opts(use="""[-c|--clear]

Read Xen's message buffer (boot output, warning and error messages) or clear
its contents if the [-c|--clear] flag is specified.
""")

    gopts.opt('clear', short='c',
              fn=set_true, default=0,
              use="Clear the contents of the Xen message buffer.")

    short_options = ['-c']
    long_options = ['--clear']

    def help(self, args):
        self.gopts.argv = args
        self.gopts.usage()

    def main(self, args):
        self.gopts.parse(args)
        if not (1 <= len(args) <=2):
            self.gopts.err('Invalid arguments: ' + str(args))

        if not self.gopts.vals.clear:
            print server.xend_node_get_dmesg()
        else:
            server.xend_node_clear_dmesg()

xm.prog(ProgDmesg)

class ProgLog(Prog):
    group = 'host'
    name  =  "log"
    info  = """Print the xend log."""

    def main(self, args):
        print server.xend_node_log()

xm.prog(ProgLog)

class ProgVifList(Prog):
    group = 'vif'
    name  = 'vif-list'
    info  = """List virtual network interfaces for a domain."""

    def help(self, args):
        print args[0], "DOM"
        print "\nList virtual network interfaces for domain DOM"

    def main(self, args):
        if len(args) != 2: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        for x in server.xend_domain_vifs(dom):
            sxp.show(x)
            print

xm.prog(ProgVifList)

class ProgVbdList(Prog):
    group = 'vbd'
    name  = 'vbd-list'
    info  = """List virtual block devices for a domain."""

    def help(self, args):
        print args[0], "DOM"
        print "\nList virtual block devices for domain DOM"

    def main(self, args):
        if len(args) != 2: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        for x in server.xend_domain_vbds(dom):
            sxp.show(x)
            print

xm.prog(ProgVbdList)

class ProgVbdCreate(Prog):
    group = 'vbd'
    name  = 'vbd-create'
    info = """Create a new virtual block device for a domain"""

    def help(self, args):
        print args[0], "DOM UNAME DEV MODE [BACKEND]"
        print """
Create a virtual block device for a domain.

  UNAME   - device to export, e.g. phy:hda2
  DEV     - device name in the domain, e.g. sda1
  MODE    - access mode: r for read, w for read-write
  BACKEND - backend driver domain
"""

    def main(self, args):
        n = len(args)
        if n < 5 or n > 6: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        vbd = ['vbd',
               ['uname', args[2]],
               ['dev',   args[3]],
               ['mode',  args[4]]]
        if n == 6:
            vbd.append(['backend', args[5]])
        server.xend_domain_device_create(dom, vbd)

xm.prog(ProgVbdCreate)

class ProgVbdDestroy(Prog):
    group = 'vbd'
    name = 'vbd-destroy'
    info = """Destroy a domain's virtual block device"""

    def help(self, args):
        print args[0], "DOM DEV"
        print """
Destroy vbd DEV attached to domain DOM. Detaches the device
from the domain, but does not destroy the device contents.
The device indentifier DEV is the idx field in the device
information. This is visible in 'xm vbd-list'."""

    def main(self, args):
        if len(args) != 3: self.err("%s: Invalid argument(s)" % args[0])
        dom = args[1]
        dev = args[2]
        server.xend_domain_device_destroy(dom, "vbd", dev)

xm.prog(ProgVbdDestroy)

def main(args):
    xm.main(args)
