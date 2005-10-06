# (C) Copyright IBM Corp. 2005
# Copyright (C) 2004 Mike Wray
# Copyright (c) 2005 XenSource Ltd
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

import xen.xend.XendError
import xen.xend.XendProtocol

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
    vcpu-enable <DomId> <VCPU>        enable VCPU in a domain
    vcpu-disable <DomId> <VCPU>       disable VCPU in a domain
    vcpu-list <DomId>                 get the list of VCPUs for a domain
    vcpu-pin <DomId> <VCpu> <CPUS>    set which cpus a VCPU can use. 

  Xen Host Commands:
    dmesg   [--clear]         read or clear Xen's message buffer
    info                      get information about the xen host
    log                       print the xend log
    top                       monitor system and domains in real-time

  Scheduler Commands:
    sched-bvt <options>       set BVT scheduler parameters
    sched-bvt-ctxallow <Allow>
        Set the BVT scheduler context switch allowance
    sched-sedf <options>      set simple EDF parameters

  Virtual Device Commands:
    block-attach  <DomId> <BackDev> <FrontDev> <Mode> [BackDomId]
        Create a new virtual block device 
    block-detach  <DomId> <DevId>  Destroy a domain's virtual block device,
                                   where <DevId> may either be the device ID
                                   or the device name as mounted in the guest.
    block-list    <DomId>          List virtual block devices for a domain
    network-limit   <DomId> <Vif> <Credit> <Period>
        Limit the transmission rate of a virtual network interface
    network-list    <DomId>        List virtual network interfaces for a domain

  Vnet commands:
    vnet-list   [-l|--long]    list vnets
    vnet-create <config>       create a vnet from a config file
    vnet-delete <vnetid>       delete a vnet

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
    elif error == "Exception: Device not connected":
        err("Device not connected")
        sys.exit(1)
    else:
        raise ex
    

#########################################################################
#
#  Main xm functions
#
#########################################################################

def xm_save(args):
    arg_check(args,2,"save")

    dom = args[0] # TODO: should check if this exists
    savefile = os.path.abspath(args[1])

    if not os.access(os.path.dirname(savefile), os.W_OK):
        err("xm save: Unable to create file %s" % savefile)
        sys.exit(1)
    
    from xen.xend.XendClient import server
    server.xend_domain_save(dom, savefile)
    
def xm_restore(args):
    arg_check(args,1,"restore")

    savefile = os.path.abspath(args[0])

    if not os.access(savefile, os.R_OK):
        err("xm restore: Unable to read file %s" % savefile)
        sys.exit(1)

    from xen.xend.XendClient import server
    info = server.xend_domain_restore(savefile)
    PrettyPrint.prettyprint(info)
    id = sxp.child_value(info, 'domid')
    if id is not None:
        server.xend_domain_unpause(domid)

def xm_list(args):
    use_long = 0
    show_vcpus = 0
    try:
        (options, params) = getopt(args, 'lv', ['long','vcpus'])
    except GetoptError, opterr:
        err(opterr)
        sys.exit(1)
    
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
        for dom in doms:
            info = server.xend_domain(dom)
            PrettyPrint.prettyprint(info)
    elif show_vcpus:
        xm_show_vcpus(domsinfo)
    else:
        xm_brief_list(domsinfo)

def parse_doms_info(info):
    dominfo = {}
    dominfo['dom'] = int(sxp.child_value(info, 'domid', '-1'))
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
        vcpuinfo['dom']    = int(sxp.child_value(info, 'domid', '-1'))
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
    xm_list(["-v"] + args)

def xm_reboot(args):
    arg_check(args,1,"reboot")
    from xen.xm import shutdown
    # ugly hack because the opt parser apparently wants
    # the subcommand name just to throw it away!
    shutdown.main(["bogus", "-R"] + args)

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

def xm_subcommand(command, args):
    cmd = __import__(command, globals(), locals(), 'xen.xm')
    cmd.main(["bogus"] + args)


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

def xm_vcpu_pin(args):
    arg_check(args, 3, "vcpu-pin")
    
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
    id = sxp.child_value(dom, 'domid')
    server.xend_domain_vcpu_hotplug(id, vcpu, 1)

def xm_vcpu_disable(args):
    arg_check(args, 2, "vcpu-disable")
    
    name = args[0]
    vcpu = int(args[1])
    
    from xen.xend.XendClient import server
    dom = server.xend_domain(name)
    id = sxp.child_value(dom, 'domid')
    server.xend_domain_vcpu_hotplug(id, vcpu, 0)

def xm_domid(args):
    name = args[0]

    from xen.xend.XendClient import server
    dom = server.xend_domain(name)
    print sxp.child_value(dom, 'domid')
    
def xm_domname(args):
    name = args[0]

    from xen.xend.XendClient import server
    dom = server.xend_domain(name)
    print sxp.child_value(dom, 'name')

def xm_sched_bvt(args):
    arg_check(args, 6, "sched-bvt")
    dom = args[0]
    v = map(long, args[1:6])
    from xen.xend.XendClient import server
    server.xend_domain_cpu_bvt_set(dom, *v)

def xm_sched_bvt_ctxallow(args):
    arg_check(args, 1, "sched-bvt-ctxallow")

    slice = int(args[0])
    from xen.xend.XendClient import server
    server.xend_node_cpu_bvt_slice_set(slice)

def xm_sched_sedf(args):
    arg_check(args, 6, "sched-sedf")
    
    dom = args[0]
    v = map(int, args[1:6])
    from xen.xend.XendClient import server
    server.xend_domain_cpu_sedf_set(dom, *v)

def xm_info(args):
    from xen.xend.XendClient import server
    info = server.xend_node()
    
    for x in info[1:]:
        if len(x) < 2: 
            print "%-23s: (none)" % x[0]
        else: 
            print "%-23s:" % x[0], x[1]

# TODO: remove as soon as console server shows up
def xm_console(args):
    arg_check(args,1,"console")

    dom = args[0]
    from xen.xend.XendClient import server
    info = server.xend_domain(dom)
    domid = int(sxp.child_value(info, 'domid', '-1'))
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
    myargs = args
    myargs.insert(0, "bogus")
    gopts.parse(myargs)
    if not (1 <= len(myargs) <= 2):
        err('Invalid arguments: ' + str(myargs))

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

def xm_block_attach(args):
    n = len(args)
    if n == 0:
        usage("block-attach")
        
    if n < 4 or n > 5:
        err("%s: Invalid argument(s)" % args[0])
        usage("block-attach")

    dom = args[0]
    vbd = ['vbd',
           ['uname', args[1]],
           ['dev',   args[2]],
           ['mode',  args[3]]]
    if n == 5:
        vbd.append(['backend', args[4]])

    from xen.xend.XendClient import server
    server.xend_domain_device_create(dom, vbd)

def xm_block_detach(args):
    arg_check(args,2,"block-detach")

    dom = args[0]
    dev = args[1]

    from xen.xend.XendClient import server
    server.xend_domain_device_destroy(dom, 'vbd', dev)

def xm_vnet_list(args):
    from xen.xend.XendClient import server
    try:
        (options, params) = getopt(args, 'l', ['long'])
    except GetoptError, opterr:
        err(opterr)
        sys.exit(1)
    
    use_long = 0
    for (k, v) in options:
        if k in ['-l', '--long']:
            use_long = 1
            
    if params:
        use_long = 1
        vnets = params
    else:
        vnets = server.xend_vnets()
    
    for vnet in vnets:
        try:
            if use_long:
                info = server.xend_vnet(vnet)
                PrettyPrint.prettyprint(info)
            else:
                print vnet
        except Exception, ex:
            print vnet, ex

def xm_vnet_create(args):
    arg_check(args, 1, "vnet-create")
    conf = args[0]
    from xen.xend.XendClient import server
    server.xend_vnet_create(conf)

def xm_vnet_delete(args):
    arg_check(args, 1, "vnet-delete")
    vnet = args[0]
    from xen.xend.XendClient import server
    server.xend_vnet_delete(vnet)

commands = {
    # console commands
    "console": xm_console,
    # xenstat commands
    "top": xm_top,
    # domain commands
    "domid": xm_domid,
    "domname": xm_domname,
    "restore": xm_restore,
    "save": xm_save,
    "reboot": xm_reboot,
    "list": xm_list,
    # memory commands
    "mem-max": xm_mem_max,
    "mem-set": xm_mem_set,
    # cpu commands
    "vcpu-pin": xm_vcpu_pin,
#    "cpus-list": xm_cpus_list,
    "vcpu-enable": xm_vcpu_enable,
    "vcpu-disable": xm_vcpu_disable,
    "vcpu-list": xm_vcpu_list,
    # special
    "pause": xm_pause,
    "unpause": xm_unpause,
    # host commands
    "dmesg": xm_dmesg,
    "info": xm_info,
    "log": xm_log,
    # scheduler
    "sched-bvt": xm_sched_bvt,
    "sched-bvt-ctxallow": xm_sched_bvt_ctxallow,
    "sched-sedf": xm_sched_sedf,
    # block
    "block-attach": xm_block_attach,
    "block-detach": xm_block_detach,
    "block-list": xm_block_list,
    # network
    "network-limit": xm_network_limit,
    "network-list": xm_network_list,
    # vnet
    "vnet-list": xm_vnet_list,
    "vnet-create": xm_vnet_create,
    "vnet-delete": xm_vnet_delete,
    }

## The commands supported by a separate argument parser in xend.xm.
subcommands = [
    'create',
    'destroy',
    'migrate',
    'sysrq',
    'shutdown'
    ]

for c in subcommands:
    commands[c] = eval('lambda args: xm_subcommand("%s", args)' % c)

aliases = {
    "balloon": "mem-set",
    "vif-list": "network-list",
    "vif-limit": "network-limit",
    "vbd-create": "block-create",
    "vbd-destroy": "block-destroy",
    "vbd-list": "block-list",
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
    if help.has_key(cmd):
        print help[cmd]
    else:
        print shorthelp
    sys.exit(1)

def main(argv=sys.argv):
    if len(argv) < 2:
        usage()
    
    if re.compile('-*help').match(argv[1]):
	if len(argv) > 2:
	    usage(argv[2])
	else:
	    usage()
	sys.exit(0)

    cmd = xm_lookup_cmd(argv[1])

    # strip off prog name and subcmd
    args = argv[2:]
    if cmd:
        try:
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
        except xen.xend.XendError.XendError, ex:
            if len(args) > 0:
                handle_xend_error(argv[1], args[0], ex)
            else:
                print "Unexpected error:", sys.exc_info()[0]
                print
                print "Please report to xen-devel@lists.xensource.com"
                raise
        except xen.xend.XendProtocol.XendError, ex:
            if len(args) > 0:
                handle_xend_error(argv[1], args[0], ex)
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
