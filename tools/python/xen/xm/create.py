# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Domain creation.
"""
import string
import sys

from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend.XendClient import server

from xen.xm.opts import *

gopts = Opts(use="""[options]

Create a domain.
""")

gopts.opt('help', short='h',
         fn=set_true, default=0,
         use="Print this help.")

gopts.opt('quiet', short='q',
         fn=set_true, default=0,
         use="Quiet.")

gopts.opt('path', val='PATH',
         fn=set_value, default='.:/etc/xen',
         use="Search path for default scripts.")

gopts.opt('defaults', short='f', val='FILE',
         fn=set_value, default='xmdefaults',
         use="Use the given default script.")

gopts.opt('config', short='F', val='FILE',
         fn=set_value, default=None,
         use='Domain configuration to use (SXP).')

gopts.opt('load', short='L', val='FILE',
          fn=set_value, default=None,
          use='Domain saved state to load.')

gopts.opt('define', short='D', val='VAR=VAL',
         fn=set_var, default=None,
         use="""Set a variable before loading defaults, e.g. '-D vmid=3'
         to set vmid. May be repeated to set more thanone variable.""")

gopts.opt('dryrun', short='n',
         fn=set_true, default=0,
         use="Dry run - print the config but don't create the domain.")

gopts.opt('name', short='N', val='NAME',
          fn=set_value, default=None,
          use="Domain name.")

gopts.opt('console', short='c',
         fn=set_true, default=0,
         use="Connect to console after domain is created.")

gopts.opt('kernel', short='k', val='FILE',
         fn=set_value, default=None,
         use="Path to kernel image.")

gopts.opt('ramdisk', short='r', val='FILE',
         fn=set_value, default='',
         use="Path to ramdisk.")

gopts.opt('builder', short='b', val='FUNCTION',
         fn=set_value, default='linux',
         use="Function to use to build the domain.")

gopts.opt('memory', short='m', val='MEMORY',
         fn=set_value, default=128,
         use="Domain memory in MB.")

gopts.opt('blkif',
          fn=set_true, default=0,
          use="Make the domain a block device backend.")

gopts.opt('netif',
          fn=set_true, default=0,
          use="Make the domain a network interface backend.")

gopts.opt('disk', short='d', val='phy:DEV,VDEV,MODE',
         fn=append_value, default=[],
         use="""Add a disk device to a domain. The physical device is DEV, which
         is exported to the domain as VDEV. The disk is read-only if MODE
         is 'r', read-write if MODE is 'w'.
         The option may be repeated to add more than one disk.
         """)

gopts.opt('pci', val='BUS,DEV,FUNC',
         fn=append_value, default=[],
         use="""Add a PCI device to a domain, using given params (in hex).
         For example '-pci c0,02,1a'.
         The option may be repeated to add more than one pci device.
         """)

gopts.opt('ipaddr', short='i', val="IPADDR",
         fn=append_value, default=[],
         use="Add an IP address to the domain.")

gopts.opt('vif', val="mac=MAC,bridge=BRIDGE",
         fn=append_value, default=[],
         use="""Add a network interface with the given MAC address and bridge.
         If mac is not specified a random MAC address is used.
         If bridge is not specified the default bridge is used.
         This option may be repeated to add more than one vif.
         Specifying vifs will increase the number of interfaces as needed.
         """)

gopts.opt('nics', val="NUM",
         fn=set_int, default=1,
         use="""Set the number of network interfaces.
         Use the vif option to define interface parameters, otherwise
         defaults are used. Specifying vifs will increase the
         number of interfaces as needed.
         """)

gopts.opt('root', short='R', val='DEVICE',
         fn=set_value, default='',
         use="""Set the root= parameter on the kernel command line.
         Use a device, e.g. /dev/sda1, or /dev/nfs for NFS root.""")

gopts.opt('extra', short='E', val="ARGS",
         fn=set_value, default='',
         use="Set extra arguments to append to the kernel command line.")

gopts.opt('ip', short='I', val='IPADDR',
         fn=set_value, default='',
         use="Set the kernel IP interface address.")

gopts.opt('gateway', val="IPADDR",
         fn=set_value, default='',
         use="Set the kernel IP gateway.")

gopts.opt('netmask', val="MASK",
         fn=set_value, default = '',
         use="Set the kernel IP netmask.")

gopts.opt('hostname', val="NAME",
         fn=set_value, default='',
         use="Set the kernel IP hostname.")

gopts.opt('interface', val="INTF",
         fn=set_value, default="eth0",
         use="Set the kernel IP interface name.")

gopts.opt('dhcp', val="off|dhcp",
         fn=set_value, default='off',
         use="Set the kernel dhcp option.")

gopts.opt('nfs_server', val="IPADDR",
         fn=set_value, default=None,
         use="Set the address of the NFS server for NFS root.")

gopts.opt('nfs_root', val="PATH",
         fn=set_value, default=None,
         use="Set the path of the root NFS directory.")

def strip(pre, s):
    """Strip prefix 'pre' if present.
    """
    if s.startswith(pre):
        return s[len(pre):]
    else:
        return s

def configure_image(config, opts):
    """Create the image config.
    """
    config_image = [ opts.builder ]
    config_image.append([ 'kernel', os.path.abspath(opts.kernel) ])
    if opts.ramdisk:
        config_image.append([ 'ramdisk', os.path.abspath(opts.ramdisk) ])
    if opts.cmdline_ip:
        cmdline_ip = strip('ip=', opts.cmdline_ip)
        config_image.append(['ip', cmdline_ip])
    if opts.root:
        cmdline_root = strip('root=', opts.root)
        config_image.append(['root', cmdline_root])
    if opts.extra:
        config_image.append(['args', opts.extra])
    config.append(['image', config_image ])
    
def configure_disks(config_devs, opts):
    """Create the config for disks (virtual block devices).
    """
    for (uname, dev, mode) in opts.disk:
        config_vbd = ['vbd',
                      ['uname', uname],
                      ['dev', dev ],
                      ['mode', mode ] ]
        config_devs.append(['device', config_vbd])

def configure_pci(config_devs, opts):
    """Create the config for pci devices.
    """
    for (bus, dev, func) in opts.pci:
        config_pci = ['pci', ['bus', bus], ['dev', dev], ['func', func]]
        config_devs.append(['device', config_pci])

def configure_vifs(config_devs, opts):
    """Create the config for virtual network interfaces.
    """
    vifs = opts.vif
    vifs_n = max(opts.nics, len(vifs))

    for idx in range(0, vifs_n):
        if idx < len(vifs):
            d = vifs[idx]
            mac = d.get('mac')
            bridge = d.get('bridge')
        else:
            mac = None
            bridge = None
        config_vif = ['vif']
        if mac:
            config_vif.append(['mac', mac])
        if bridge:
            config_vif.append(['bridge', bridge])
        config_devs.append(['device', config_vif])

def configure_vfr(config, opts):
     if not opts.ipaddr: return
     config_vfr = ['vfr']
     idx = 0 # No way of saying which IP is for which vif?
     for ip in opts.ipaddr:
         config_vfr.append(['vif', ['id', idx], ['ip', ip]])
     config.append(config_vfr)


def make_config(opts):
    """Create the domain configuration.
    """
    
    config = ['vm',
              ['name', opts.name ],
              ['memory', opts.memory ] ]
    if opts.cpu:
        config.append(['cpu', opts.cpu])
    if opts.blkif:
        config.append(['backend', ['blkif']])
    if opts.netif:
        config.append(['backend', ['netif']])
    
    configure_image(config, opts)
    config_devs = []
    configure_disks(config_devs, opts)
    configure_pci(config_devs, opts)
    configure_vifs(config_devs, opts)
    config += config_devs
    return config

def preprocess_disk(opts):
    if not opts.disk: return
    disk = []
    for v in opts.disk:
        d = v.split(',')
        if len(d) != 3:
            opts.err('Invalid disk specifier: ' + v)
        disk.append(d)
    opts.disk = disk

def preprocess_pci(opts):
    if not opts.pci: return
    pci = []
    for v in opts.pci:
        d = v.split(',')
        if len(d) != 3:
            opts.err('Invalid pci specifier: ' + v)
        # Components are in hex: add hex specifier.
        hexd = map(lambda v: '0x'+v, d)
        pci.append(hexd)
    opts.pci = pci

def preprocess_vifs(opts):
    if not opts.vif: return
    vifs = []
    for vif in opts.vif:
        d = {}
        a = vif.split(',')
        for b in a:
            (k, v) = b.strip().split('=')
            k = k.strip()
            v = v.strip()
            if k not in ['mac', 'bridge']:
                opts.err('Invalid vif specifier: ' + vif)
            d[k] = v
        vifs.append(d)
    opts.vif = vifs

def preprocess_ip(opts):
    setip = (opts.hostname or opts.netmask
             or opts.gateway or opts.dhcp or opts.interface)
    if not setip: return
    #if not opts
    ip = (opts.ip
          + ':'
          + ':' + opts.gateway
          + ':' + opts.netmask
          + ':' + opts.hostname
          + ':' + opts.interface
          + ':' + opts.dhcp)
    opts.cmdline_ip = ip

def preprocess_nfs(opts):
    if (opts.nfs_root or opts.nfs_server):
        if (not opts.nfs_root) or (not opts.nfs_server):
            opts.err('Must set nfs root and nfs server')
    else:
        return
    nfs = 'nfsroot=' + opts.nfs_server + ':' + opts.nfs_root
    opts.extra = nfs + ' ' + opts.extra
    
def preprocess(opts):
    if not opts.kernel:
        opts.err("No kernel specified")
    preprocess_disk(opts)
    preprocess_pci(opts)
    preprocess_vifs(opts)
    preprocess_ip(opts)
    preprocess_nfs(opts)
         
def make_domain(opts, config):
    """Create, build and start a domain.
    Returns: [int] the ID of the new domain.
    """
    if opts.vals.load:
        filename = os.path.abspath(opts.vals.load)
        dominfo = server.xend_domain_restore(filename, config)
    else:
        dominfo = server.xend_domain_create(config)

    dom = int(sxp.child_value(dominfo, 'id'))
    console_info = sxp.child(dominfo, 'console')
    if console_info:
        console_port = int(sxp.child_value(console_info, 'port'))
    else:
        console_port = None
    
    if server.xend_domain_unpause(dom) < 0:
        server.xend_domain_destroy(dom)
        opts.err("Failed to start domain %d" % dom)
    opts.info("Started domain %d, console on port %d"
              % (dom, console_port))
    return (dom, console_port)

def main(argv):
    opts = gopts
    args = opts.parse(argv)
    if opts.vals.help:
        opts.usage()
        return
    if opts.vals.config:
        pass
    else:
        opts.load_defaults()
    preprocess(opts.vals)
    config = make_config(opts.vals)
    if opts.vals.dryrun:
        PrettyPrint.prettyprint(config)
    else:
        make_domain(opts, config)
        
if __name__ == '__main__':
    main(sys.argv)
