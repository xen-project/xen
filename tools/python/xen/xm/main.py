# (C) Copyright IBM Corp. 2005
# Copyright (C) 2004 Mike Wray
#
# Authors:
#     Sean Dague <sean at dague dot net>
#     Mike Wray <mike dot wray at hp dot com>
#
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

"""Grand unified management application for Xen.
"""
import os
import os.path
import sys
import commands
import re
from getopt import getopt
import socket
import warnings
warnings.filterwarnings('ignore', category=FutureWarning)
from xen.xend import PrettyPrint
from xen.xend import sxp
from xen.xm.opts import *
shorthelp = """Usage: xm <subcommand> [args]
    Control, list, and manipulate Xen guest instances

xm common subcommands:
    console <DomId>         attach to console of DomId
    create <CfgFile>        create a domain based on Config File
    destroy <DomId>         terminate a domain immediately
    help                    display this message
    list [DomId, ...]       list information about domains
    mem-max <DomId> <Mem>   set the maximum memory reservation for a domain
    mem-set <DomId> <Mem>   adjust the current memory usage for a domain
    migrate <DomId> <Host>  migrate a domain to another machine
    pause <DomId>           pause execution of a domain
    reboot <DomId>          reboot a domain
    restore <File>          create a domain from a saved state file
    save <DomId> <File>     save domain state (and config) to file
    shutdown <DomId>        shutdown a domain
    top                     monitor system and domains in real-time
    unpause <DomId>         unpause a paused domain

For a complete list of subcommands run 'xm help --long'
For more help on xm see the xm(1) man page
For more help on xm create, see the xmdomain.cfg(5) man page"""

longhelp = """Usage: xm <subcommand> [args]
    Control, list, and manipulate Xen guest instances

xm full list of subcommands:

  Domain Commands:
    console <DomId>         attach to console of DomId
    cpus-list <DomId> <VCpu>          get the list of cpus for a VCPU
    cpus-set <DomId> <VCpu> <CPUS>    set which cpus a VCPU can use. 
    create  <ConfigFile>      create a domain
    destroy <DomId>           terminate a domain immediately
    domid   <DomName>         convert a domain name to a domain id
    domname <DomId>           convert a domain id to a domain name
    list                      list information about domains
    mem-max <DomId> <Mem>     set domain maximum memory limit
    mem-set <DomId> <Mem>     set the domain's memory dynamically
    migrate <DomId> <Host>    migrate a domain to another machine
    pause   <DomId>           pause execution of a domain
    reboot   [-w|-a] <DomId>  reboot a domain
    restore <File>            create a domain from a saved state file
    save    <DomId> <File>    save domain state (and config) to file
    shutdown [-w|-a] <DomId>  shutdown a domain
    sysrq   <DomId> <letter>  send a sysrq to a domain
    unpause <DomId>           unpause a paused domain
    vcpu-enable <DomId> <VCPU>        disable VCPU in a domain
    vcpu-disable <DomId> <VCPU>       enable VCPU in a domain
    vcpu-list <DomId>                 get the list of VCPUs for a domain

  Xen Host Commands:
    dmesg   [--clear]         read or clear Xen's message buffer
    info                      get information about the xen host
    log                       print the xend log
    top                       monitor system and domains in real-time

  Scheduler Commands:
    bvt <options>             set BVT scheduler parameters
    bvt_ctxallow <Allow>      set the BVT scheduler context switch allowance
    sedf <options>            set simple EDF parameters

  Virtual Device Commands:
    block-create <DomId> <BackDev> <FrontDev> <Mode> [BackDomId]
        Create a new virtual block device 
    block-destroy <DomId> <DevId>  Destroy a domain's virtual block device
    block-list    <DomId>          List virtual block devices for a domain
    block-refresh <DomId> <DevId>  Refresh a virtual block device for a domain
    network-limit   <DomId> <Vif> <Credit> <Period>
        Limit the transmission rate of a virtual network interface
    network-list    <DomId>        List virtual network interfaces for a domain

For a short list of subcommands run 'xm help'
For more help on xm see the xm(1) man page
For more help on xm create, see the xmdomain.cfg(5) man page"""

####################################################################
#
#  Utility functions
#
####################################################################

def arg_check(args,num,name):
    if len(args) < num:
        err("'xm %s' requires %s argument(s)!\n" % (name, num))
        usage(name)

def unit(c):
    if not c.isalpha():
        return 0
    base = 1
    if c == 'G' or c == 'g': base = 1024 * 1024 * 1024
    elif c == 'M' or c == 'm': base = 1024 * 1024
    elif c == 'K' or c == 'k': base = 1024
    else:
        print 'ignoring unknown unit'
    return base

def int_unit(str, dest):
    base = unit(str[-1])
    if not base:
        return int(str)

    value = int(str[:-1])
    dst_base = unit(dest)
    if dst_base == 0:
        dst_base = 1
    if dst_base > base:
        return value / (dst_base / base)
    else:
        return value * (base / dst_base)

def err(msg):
    print >>sys.stderr, "Error:", msg

def handle_xend_error(cmd, dom, ex):
    error = str(ex)
    if error == "Not found" and dom != None:
        err("Domain '%s' not found when running 'xm %s'" % (dom, cmd))
        sys.exit(1)
    else:
        raise ex
    

#########################################################################
#
#  Main xm functions
#
#########################################################################

def xm_create(args):
    from xen.xm import create
    # ugly hack because the opt parser apparently wants
    # the subcommand name just to throw it away!
    args.insert(0,"bogus")
    create.main(args)

def xm_save(args):
    arg_check(args,2,"save")

    dom = args[0] # TODO: should check if this exists
    savefile = os.path.abspath(args[1])
    
    from xen.xend.XendClient import server
    server.xend_domain_save(dom, savefile)
    
def xm_restore(args):
    arg_check(args,1,"restore")

    savefile = os.path.abspath(args[0])

    from xen.xend.XendClient import server
    info = server.xend_domain_restore(savefile)
    PrettyPrint.prettyprint(info)
    id = sxp.child_value(info, 'id')
    if id is not None:
        server.xend_domain_unpause(id)

def xm_migrate(args):
    # TODO: arg_check
    from xen.xm import migrate
    # ugly hack because the opt parser apparently wants
    # the subcommand name just to throw it away!
    args.insert(0,"bogus")
    migrate.main(args)

def xm_list(args):
    use_long = 0
    show_vcpus = 0
    (options, params) = getopt(args, 'lv', ['long','vcpus'])
    
    n = len(params)
    for (k, v) in options:
        if k in ['-l', '--long']:
            use_long = 1
        if k in ['-v', '--vcpus']:
            show_vcpus = 1

    domsinfo = []
    from xen.xend.XendClient import server
    if n == 0:
        doms = server.xend_domains()
        doms.sort()
    else:
        doms = params
    for dom in doms:
        info = server.xend_domain(dom)
        domsinfo.append(parse_doms_info(info))
               
    if use_long:
        # this actually seems like a bad idea, as it just dumps sexp out
        PrettyPrint.prettyprint(info)
    elif show_vcpus:
        xm_show_vcpus(domsinfo)
    else:
        xm_brief_list(domsinfo)

def parse_doms_info(info):
    dominfo = {}
    dominfo['dom'] = int(sxp.child_value(info, 'id', '-1'))
    dominfo['name'] = sxp.child_value(info, 'name', '??')
    dominfo['mem'] = int(sxp.child_value(info, 'memory', '0'))
    dominfo['cpu'] = str(sxp.child_value(info, 'cpu', '0'))
    dominfo['vcpus'] = int(sxp.child_value(info, 'vcpus', '0'))
    # if there is more than 1 cpu, the value doesn't mean much
    if dominfo['vcpus'] > 1:
        dominfo['cpu'] = '-'
    dominfo['state'] = sxp.child_value(info, 'state', '??')
    dominfo['cpu_time'] = float(sxp.child_value(info, 'cpu_time', '0'))
    # security identifiers
    if ((int(sxp.child_value(info, 'ssidref', '0'))) != 0):
        dominfo['ssidref1'] =  int(sxp.child_value(info, 'ssidref', '0')) & 0xffff
        dominfo['ssidref2'] = (int(sxp.child_value(info, 'ssidref', '0')) >> 16) & 0xffff
    # get out the vcpu information
    dominfo['vcpulist'] = []
    vcpu_to_cpu = sxp.child_value(info, 'vcpu_to_cpu', '-1').split('|')
    cpumap = sxp.child_value(info, 'cpumap', [])
    mask = ((int(sxp.child_value(info, 'vcpus', '0')))**2) - 1
    count = 0
    for cpu in vcpu_to_cpu:
        vcpuinfo = {}
        vcpuinfo['name']   = sxp.child_value(info, 'name', '??')
        vcpuinfo['dom']    = int(sxp.child_value(info, 'id', '-1'))
        vcpuinfo['vcpu']   = int(count)
        vcpuinfo['cpu']    = int(cpu)
        vcpuinfo['cpumap'] = int(cpumap[count])&mask
        count = count + 1
        dominfo['vcpulist'].append(vcpuinfo)
    return dominfo
        
def xm_brief_list(domsinfo):
    print 'Name              Id  Mem(MB)  CPU VCPU(s)  State  Time(s)'
    for dominfo in domsinfo:
        if dominfo.has_key("ssidref1"):
            print ("%(name)-16s %(dom)3d  %(mem)7d  %(cpu)3s  %(vcpus)5d   %(state)5s  %(cpu_time)7.1f     s:%(ssidref2)02x/p:%(ssidref1)02x" % dominfo)
        else:
            print ("%(name)-16s %(dom)3d  %(mem)7d  %(cpu)3s  %(vcpus)5d   %(state)5s  %(cpu_time)7.1f" % dominfo)

def xm_show_vcpus(domsinfo):
    print 'Name              Id  VCPU  CPU  CPUMAP'
    for dominfo in domsinfo:
        for vcpuinfo in dominfo['vcpulist']:
            print ("%(name)-16s %(dom)3d  %(vcpu)4d  %(cpu)3d  0x%(cpumap)x" %
                   vcpuinfo)

def xm_vcpu_list(args):
    args.insert(0,"-v")
    xm_list(args)

def xm_destroy(args):
    arg_check(args,1,"destroy")

    from xen.xm import destroy
    # ugly hack because the opt parser apparently wants
    # the subcommand name just to throw it away!
    args.insert(0,"bogus")
    destroy.main(args)
            
def xm_reboot(args):
    arg_check(args,1,"reboot")
    # ugly hack because the opt parser apparently wants
    # the subcommand name just to throw it away!
    args.insert(0,"bogus")
    args.insert(2,"-R")
    from xen.xm import shutdown
    shutdown.main(args)

def xm_shutdown(args):
    arg_check(args,1,"shutdown")

    # ugly hack because the opt parser apparently wants
    # the subcommand name just to throw it away!
    args.insert(0,"bogus")
    from xen.xm import shutdown
    shutdown.main(args)

def xm_sysrq(args):
    from xen.xm import sysrq
    # ugly hack because the opt parser apparently wants
    # the subcommand name just to throw it away!
    args.insert(0,"bogus")
    sysrq.main(args)

def xm_pause(args):
    arg_check(args, 1, "pause")
    dom = args[0]

    from xen.xend.XendClient import server
    server.xend_domain_pause(dom)

def xm_unpause(args):
    arg_check(args, 1, "unpause")
    dom = args[0]

    from xen.xend.XendClient import server
    server.xend_domain_unpause(dom)

#############################################################

def cpu_make_map(cpulist):
    cpus = []
    cpumap = 0
    for c in cpulist.split(','):
        if c.find('-') != -1:
            (x,y) = c.split('-')
            for i in range(int(x),int(y)+1):
                cpus.append(int(i))
        else:
            cpus.append(int(c))
    cpus.sort()
    for c in cpus:
        cpumap = cpumap | 1<<c

    return cpumap

def xm_cpus_set(args):
    arg_check(args, 3, "cpus-set")
    
    dom  = args[0]
    vcpu = int(args[1])
    cpumap = cpu_make_map(args[2])
    
    from xen.xend.XendClient import server
    server.xend_domain_pincpu(dom, vcpu, cpumap)

def xm_mem_max(args):
    arg_check(args, 2, "mem-max")
    
    dom = args[0]
    mem = int_unit(args[1], 'm')

    from xen.xend.XendClient import server
    server.xend_domain_maxmem_set(dom, mem)
    
def xm_mem_set(args):
    arg_check(args, 2, "mem-set")
    
    dom = args[0]
    mem_target = int_unit(args[1], 'm')

    from xen.xend.XendClient import server
    server.xend_domain_mem_target_set(dom, mem_target)
    
# TODO: why does this lookup by name?  and what if that fails!?
def xm_vcpu_enable(args):
    arg_check(args, 2, "vcpu-enable")
    
    name = args[0]
    vcpu = int(args[1])
    
    from xen.xend.XendClient import server
    dom = server.xend_domain(name)
    id = sxp.child_value(dom, 'id')
    server.xend_domain_vcpu_hotplug(id, vcpu, 1)

def xm_vcpu_disable(args):
    arg_check(args, 2, "vcpu-disable")
    
    name = args[0]
    vcpu = int(args[1])
    
    from xen.xend.XendClient import server
    dom = server.xend_domain(name)
    id = sxp.child_value(dom, 'id')
    server.xend_domain_vcpu_hotplug(id, vcpu, 0)

def xm_domid(args):
    name = args[0]

    from xen.xend.XendClient import server
    dom = server.xend_domain(name)
    print sxp.child_value(dom, 'id')
    
def xm_domname(args):
    name = args[0]

    from xen.xend.XendClient import server
    dom = server.xend_domain(name)
    print sxp.child_value(dom, 'name')

def xm_bvt(args):
    arg_check(args, 6, "bvt")
    dom = args[0]
    v = map(long, args[1:6])
    from xen.xend.XendClient import server
    server.xend_domain_cpu_bvt_set(dom, *v)

def xm_bvt_ctxallow(args):
    arg_check(args, 1, "bvt_ctxallow")

    slice = int(args[0])
    from xen.xend.XendClient import server
    server.xend_node_cpu_bvt_slice_set(slice)

def xm_sedf(args):
    arg_check(args, 6, "sedf")
    
    dom = args[0]
    v = map(int, args[1:5])
    from xen.xend.XendClient import server
    server.xend_domain_cpu_sedf_set(dom, *v)

def xm_info(args):
    from xen.xend.XendClient import server
    info = server.xend_node()
    
    for x in info[1:]:
        print "%-23s:" % x[0], x[1]

# TODO: remove as soon as console server shows up
def xm_console(args):
    arg_check(args,1,"console")

    dom = args[0]
    from xen.xend.XendClient import server
    info = server.xend_domain(dom)
    domid = int(sxp.child_value(info, 'id', '-1'))
    cmd = "/usr/libexec/xen/xenconsole %d" % domid
    os.execvp('/usr/libexec/xen/xenconsole', cmd.split())
    console = sxp.child(info, "console")

def xm_top(args):
    os.execv('/usr/sbin/xentop', ['/usr/sbin/xentop'])

def xm_dmesg(args):
    
    gopts = Opts(use="""[-c|--clear]

Read Xen's message buffer (boot output, warning and error messages) or clear
its contents if the [-c|--clear] flag is specified.
""")

    gopts.opt('clear', short='c',
              fn=set_true, default=0,
              use="Clear the contents of the Xen message buffer.")
    # Work around for gopts
    args.insert(0,"bogus")
    gopts.parse(args)
    if not (1 <= len(args) <= 2):
        err('Invalid arguments: ' + str(args))

    from xen.xend.XendClient import server
    if not gopts.vals.clear:
        print server.xend_node_get_dmesg()
    else:
        server.xend_node_clear_dmesg()

def xm_log(args):
    from xen.xend.XendClient import server
    print server.xend_node_log()

def xm_network_limit(args):
    arg_check(args,4,"network-limit")
    dom = args[0]
    v = map(int, args[1:4])
    from xen.xend.XendClient import server
    server.xend_domain_vif_limit(dom, *v)

def xm_network_list(args):
    arg_check(args,1,"network-list")
    dom = args[0]
    from xen.xend.XendClient import server
    for x in server.xend_domain_devices(dom, 'vif'):
        sxp.show(x)
        print

def xm_block_list(args):
    arg_check(args,1,"block-list")
    dom = args[0]
    from xen.xend.XendClient import server
    for x in server.xend_domain_devices(dom, 'vbd'):
        sxp.show(x)
        print

def xm_block_create(args):
    n = len(args)
    if n < 4 or n > 5:
        err("%s: Invalid argument(s)" % args[0])
        usage("block-create")

    dom = args[0]
    vbd = ['vbd',
           ['uname', args[1]],
           ['dev',   args[2]],
           ['mode',  args[3]]]
    if n == 5:
        vbd.append(['backend', args[4]])

    from xen.xend.XendClient import server
    server.xend_domain_device_create(dom, vbd)

def xm_block_refresh(args):
    arg_check(args,2,"block-refresh")

    dom = args[0]
    dev = args[1]

    from xen.xend.XendClient import server
    server.xend_domain_device_refresh(dom, 'vbd', dev)

def xm_block_destroy(args):
    arg_check(args,2,"block-destroy")

    dom = args[0]
    dev = args[1]

    from xen.xend.XendClient import server
    server.xend_domain_device_destroy(dom, 'vbd', dev)

commands = {
    # console commands
    "console": xm_console,
    # xenstat commands
    "top": xm_top,
    # domain commands
    "domid": xm_domid,
    "domname": xm_domname,
    "create": xm_create,
    "destroy": xm_destroy,
    "restore": xm_restore,
    "save": xm_save,
    "shutdown": xm_shutdown,
    "reboot": xm_reboot,
    "list": xm_list,
    # memory commands
    "mem-max": xm_mem_max,
    "mem-set": xm_mem_set,
    # cpu commands
    "cpus-set": xm_cpus_set,
#    "cpus-list": xm_cpus_list,
    "vcpu-enable": xm_vcpu_enable,
    "vcpu-disable": xm_vcpu_disable,
    "vcpu-list": xm_vcpu_list,
    # migration
    "migrate": xm_migrate,
    # special
    "sysrq": xm_sysrq,
    "pause": xm_pause,
    "unpause": xm_unpause,
    # host commands
    "dmesg": xm_dmesg,
    "info": xm_info,
    "log": xm_log,
    # scheduler
    "bvt": xm_bvt,
    "bvt_ctxallow": xm_bvt_ctxallow,
    "sedf": xm_sedf,
    # block
    "block-create": xm_block_create,
    "block-destroy": xm_block_destroy,
    "block-list": xm_block_list,
    "block-refresh": xm_block_refresh,
    # network
    "network-limit": xm_network_limit,
    "network-list": xm_network_list
    }

aliases = {
    "balloon": "mem-set",
    "vif-list": "network-list",
    "vif-limit": "network-limit",
    "vbd-create": "block-create",
    "vbd-destroy": "block-destroy",
    "vbd-list": "block-list",
    "vbd-refresh": "block-refresh",
    }

help = {
    "--long": longhelp
   }

def xm_lookup_cmd(cmd):
    if commands.has_key(cmd):
        return commands[cmd]
    elif aliases.has_key(cmd):
        deprecated(cmd,aliases[cmd])
        return commands[aliases[cmd]]
    else:
        if len( cmd ) > 1:
            matched_commands = filter( lambda (command, func): command[ 0:len(cmd) ] == cmd, commands.iteritems() )
            if len( matched_commands ) == 1:
		        return matched_commands[0][1]
        err('Sub Command %s not found!' % cmd)
        usage()

def deprecated(old,new):
    err('Option %s is deprecated, and will be removed in future!!!' % old)
    err('Option %s is the new replacement, see "xm help %s" for more info' % (new, new))

def usage(cmd=None):
    if cmd == "full":
        print fullhelp
    elif help.has_key(cmd):
        print help[cmd]
    else:
        print shorthelp
    sys.exit(1)

def main(argv=sys.argv):
    if len(argv) < 2:
        usage()
    
    if re.compile('-*help').match(argv[1]):
	if len(argv) > 2 and help.has_key(argv[2]):
	    usage(argv[2])
	else:
	    usage()
	sys.exit(0)

    cmd = xm_lookup_cmd(argv[1])

    # strip off prog name and subcmd
    args = argv[2:]
    if cmd:
        try:
            from xen.xend.XendClient import XendError
            rc = cmd(args)
            if rc:
                usage()
        except socket.error, ex:
            print >>sys.stderr, ex
            err("Error connecting to xend, is xend running?")
            sys.exit(1)
        except IOError:
            err("Most commands need root access.  Please try again as root")
            sys.exit(1)
        except XendError, ex:
            if len(args) > 0:
                handle_xend_error(argv[1], args[1], ex)
            else:
                print "Unexpected error:", sys.exc_info()[0]
                print
                print "Please report to xen-devel@lists.xensource.com"
                raise
        except SystemExit:
            sys.exit(1)
        except:
            print "Unexpected error:", sys.exc_info()[0]
            print
            print "Please report to xen-devel@lists.xensource.com"
            raise
                
    else:
        usage()

if __name__ == "__main__":
    main()



