# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Domain creation.
"""
import random
import string
import sys

from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend.XendClient import server, XendError

from xen.util import console_client

from xen.xm.opts import *

gopts = Opts(use="""[options] [vars]

Create a domain.

Domain creation parameters can be set by command-line switches, from
a python configuration script or an SXP config file. See documentation
for --defconfig, --config. Configuration variables can be set using
VAR=VAL on the command line. For example vmid=3 sets vmid to 3.

""")

gopts.opt('help', short='h',
          fn=set_true, default=0,
          use="Print this help.")

gopts.opt('help_config',
          fn=set_true, default=0,
          use="Print help for the configuration script.")

gopts.opt('quiet', short='q',
          fn=set_true, default=0,
          use="Quiet.")

gopts.opt('path', val='PATH',
          fn=set_value, default='.:/etc/xen',
          use="""Search path for configuration scripts.
         The value of PATH is a colon-separated directory list.""")

gopts.opt('defconfig', short='f', val='FILE',
          fn=set_value, default='xmdefconfig',
          use="""Use the given Python configuration script.
          The configuration script is loaded after arguments have been processed.
          Each command-line option sets a configuration variable named after
          its long option name, and these variables are placed in the
          environment of the script before it is loaded.
          Variables for options that may be repeated have list values.
          Other variables can be set using VAR=VAL on the command line.
        
          After the script is loaded, option values that were not set on the
          command line are replaced by the values set in the script.""")

gopts.default('defconfig')

gopts.opt('config', short='F', val='FILE',
          fn=set_value, default=None,
          use="""Domain configuration to use (SXP).
          SXP is the underlying configuration format used by Xen.
          SXP configurations can be hand-written or generated from Python configuration
          scripts, using the -n (dryrun) option to print the configuration.""")

gopts.opt('load', short='L', val='FILE',
          fn=set_value, default=None,
          use='Domain saved state to load.')

gopts.opt('dryrun', short='n',
          fn=set_true, default=0,
          use="""Dry run - print the configuration but don't create the domain.
          Loads the configuration script, creates the SXP configuration and prints it.""")

gopts.opt('paused', short='p',
          fn=set_true, default=0,
          use='Leave the domain paused after it is created.')

gopts.opt('console_autoconnect', short='c',
          fn=set_true, default=0,
          use="Connect to the console after the domain is created.")

gopts.var('name', val='NAME',
          fn=set_value, default=None,
          use="Domain name. Must be unique.")

gopts.var('kernel', val='FILE',
          fn=set_value, default=None,
          use="Path to kernel image.")

gopts.var('ramdisk', val='FILE',
          fn=set_value, default='',
          use="Path to ramdisk.")

gopts.var('builder', val='FUNCTION',
          fn=set_value, default='linux',
          use="Function to use to build the domain.")

gopts.var('memory', val='MEMORY',
          fn=set_int, default=128,
          use="Domain memory in MB.")

gopts.var('maxmem', val='MEMORY',
          fn=set_int, default=None,
          use="Maximum domain memory in MB.")

gopts.var('cpu', val='CPU',
          fn=set_int, default=None,
          use="CPU to run the domain on.")

gopts.var('cpu_weight', val='WEIGHT',
          fn=set_float, default=None,
          use="""Set the new domain's cpu weight.
          WEIGHT is a float that controls the domain's share of the cpu.""")

gopts.var('console', val='PORT',
          fn=set_int, default=None,
          use="Console port to use. Default is 9600 + domain id.")

gopts.var('restart', val='onreboot|always|never',
          fn=set_value, default=None,
          use="""Whether the domain should be restarted on exit.
          - onreboot: restart on exit with shutdown code reboot
          - always:   always restart on exit, ignore exit code
          - never:    never restart on exit, ignore exit code""")

gopts.var('blkif', val='no|yes',
          fn=set_bool, default=0,
          use="Make the domain a block device backend.")

gopts.var('netif', val='no|yes',
          fn=set_bool, default=0,
          use="Make the domain a network interface backend.")

gopts.var('disk', val='phy:DEV,VDEV,MODE[,DOM]',
          fn=append_value, default=[],
          use="""Add a disk device to a domain. The physical device is DEV,
          which is exported to the domain as VDEV. The disk is read-only if MODE
          is 'r', read-write if MODE is 'w'. If DOM is specified it defines the
          backend driver domain to use for the disk.
          The option may be repeated to add more than one disk.""")

gopts.var('pci', val='BUS,DEV,FUNC',
          fn=append_value, default=[],
          use="""Add a PCI device to a domain, using given params (in hex).
         For example '-pci c0,02,1a'.
         The option may be repeated to add more than one pci device.""")

gopts.var('ipaddr', val="IPADDR",
          fn=append_value, default=[],
          use="Add an IP address to the domain.")

gopts.var('vif', val="mac=MAC,bridge=BRIDGE,script=SCRIPT,backend=DOM",
          fn=append_value, default=[],
          use="""Add a network interface with the given MAC address and bridge.
          The vif is configured by calling the given configuration script.
          If mac is not specified a random MAC address is used.
          If bridge is not specified the default bridge is used.
          If script is not specified the default script is used.
          If backend is not specified the default backend driver domain is used.
          This option may be repeated to add more than one vif.
          Specifying vifs will increase the number of interfaces as needed.""")

gopts.var('nics', val="NUM",
          fn=set_int, default=1,
          use="""Set the number of network interfaces.
          Use the vif option to define interface parameters, otherwise
          defaults are used. Specifying vifs will increase the
          number of interfaces as needed.""")

gopts.var('root', val='DEVICE',
          fn=set_value, default='',
          use="""Set the root= parameter on the kernel command line.
          Use a device, e.g. /dev/sda1, or /dev/nfs for NFS root.""")

gopts.var('extra', val="ARGS",
          fn=set_value, default='',
          use="Set extra arguments to append to the kernel command line.")

gopts.var('ip', val='IPADDR',
          fn=set_value, default='',
          use="Set the kernel IP interface address.")

gopts.var('gateway', val="IPADDR",
          fn=set_value, default='',
          use="Set the kernel IP gateway.")

gopts.var('netmask', val="MASK",
          fn=set_value, default = '',
          use="Set the kernel IP netmask.")

gopts.var('hostname', val="NAME",
          fn=set_value, default='',
          use="Set the kernel IP hostname.")

gopts.var('interface', val="INTF",
          fn=set_value, default="eth0",
          use="Set the kernel IP interface name.")

gopts.var('dhcp', val="off|dhcp",
          fn=set_value, default='off',
          use="Set the kernel dhcp option.")

gopts.var('nfs_server', val="IPADDR",
          fn=set_value, default=None,
          use="Set the address of the NFS server for NFS root.")

gopts.var('nfs_root', val="PATH",
          fn=set_value, default=None,
          use="Set the path of the root NFS directory.")

gopts.var('memmap', val='FILE',
          fn=set_value, default='',
          use="Path to memap SXP file.")

gopts.var('device_model', val='FILE',
          fn=set_value, default='',
          use="Path to device model program.")

gopts.var('device_config', val='FILE',
          fn=set_value, default='',
          use="Path to device model configuration.")

def strip(pre, s):
    """Strip prefix 'pre' if present.
    """
    if s.startswith(pre):
        return s[len(pre):]
    else:
        return s

def configure_image(config, vals):
    """Create the image config.
    """
    config_image = [ vals.builder ]
    config_image.append([ 'kernel', os.path.abspath(vals.kernel) ])
    if vals.ramdisk:
        config_image.append([ 'ramdisk', os.path.abspath(vals.ramdisk) ])
    if vals.cmdline_ip:
        cmdline_ip = strip('ip=', vals.cmdline_ip)
        config_image.append(['ip', cmdline_ip])
    if vals.root:
        cmdline_root = strip('root=', vals.root)
        config_image.append(['root', cmdline_root])
    if vals.extra:
        config_image.append(['args', vals.extra])
    config.append(['image', config_image ])
    
def configure_disks(config_devs, vals):
    """Create the config for disks (virtual block devices).
    """
    for (uname, dev, mode, backend) in vals.disk:
        config_vbd = ['vbd',
                      ['uname', uname],
                      ['dev', dev ],
                      ['mode', mode ] ]
        if backend:
            config_vbd.append(['backend', backend])
        config_devs.append(['device', config_vbd])

def configure_pci(config_devs, vals):
    """Create the config for pci devices.
    """
    for (bus, dev, func) in vals.pci:
        config_pci = ['pci', ['bus', bus], ['dev', dev], ['func', func]]
        config_devs.append(['device', config_pci])

def randomMAC():
    """Generate a random MAC address.

    Uses OUI (Organizationally Unique Identifier) AA:00:00, an
    unassigned one that used to belong to DEC. The OUI list is
    available at 'standards.ieee.org'.

    The remaining 3 fields are random, with the first bit of the first
    random field set 0.

    @return: MAC address string
    """
    random.seed()
    mac = [ 0xaa, 0x00, 0x00,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def configure_vifs(config_devs, vals):
    """Create the config for virtual network interfaces.
    """
    vifs = vals.vif
    vifs_n = max(vals.nics, len(vifs))

    for idx in range(0, vifs_n):
        if idx < len(vifs):
            d = vifs[idx]
            mac = d.get('mac')
            if not mac:
                mac = randomMAC()
            bridge = d.get('bridge')
            script = d.get('script')
            backend = d.get('backend')
            ip = d.get('ip')
        else:
            mac = randomMAC()
            bridge = None
            script = None
            backend = None
            ip = None
        config_vif = ['vif']
        config_vif.append(['mac', mac])
        if bridge:
            config_vif.append(['bridge', bridge])
        if script:
            config_vif.append(['script', script])
        if backend:
            config_vif.append(['backend', backend])
        if ip:
            config_vif.append(['ip', ip])
        config_devs.append(['device', config_vif])

def configure_vfr(config, vals):
     if not vals.ipaddr: return
     config_vfr = ['vfr']
     idx = 0 # No way of saying which IP is for which vif?
     for ip in vals.ipaddr:
         config_vfr.append(['vif', ['id', idx], ['ip', ip]])
     config.append(config_vfr)

def configure_vmx(config_devs, vals):
    """Create the config for VMX devices.
    """
    memmap = vals.memmap
    device_model = vals.device_model
    device_config = vals.device_config
    config_devs.append(['memmap', memmap])
    config_devs.append(['device_model', device_model])
    config_devs.append(['device_config', device_config])

def make_config(vals):
    """Create the domain configuration.
    """
    
    config = ['vm',
              ['name', vals.name ],
              ['memory', vals.memory ]]
    if vals.maxmem:
        config.append(['maxmem', vals.maxmem])
    if vals.cpu is not None:
        config.append(['cpu', vals.cpu])
    if vals.cpu_weight is not None:
        config.append(['cpu_weight', vals.cpu_weight])
    if vals.blkif:
        config.append(['backend', ['blkif']])
    if vals.netif:
        config.append(['backend', ['netif']])
    if vals.restart:
        config.append(['restart', vals.restart])
    if vals.console:
        config.append(['console', vals.console])
    
    configure_image(config, vals)
    config_devs = []
    configure_disks(config_devs, vals)
    configure_pci(config_devs, vals)
    configure_vifs(config_devs, vals)
    configure_vmx(config_devs, vals)
    config += config_devs
    return config

def preprocess_disk(opts, vals):
    if not vals.disk: return
    disk = []
    for v in vals.disk:
        d = v.split(',')
        n = len(d)
        if n == 3:
            d.append(None)
        elif n == 4:
            pass
        else:
            opts.err('Invalid disk specifier: ' + v)
        disk.append(d)
    vals.disk = disk

def preprocess_pci(opts, vals):
    if not vals.pci: return
    pci = []
    for v in vals.pci:
        d = v.split(',')
        if len(d) != 3:
            opts.err('Invalid pci specifier: ' + v)
        # Components are in hex: add hex specifier.
        hexd = map(lambda v: '0x'+v, d)
        pci.append(hexd)
    vals.pci = pci

def preprocess_vifs(opts, vals):
    if not vals.vif: return
    vifs = []
    for vif in vals.vif:
        d = {}
        a = vif.split(',')
        for b in a:
            (k, v) = b.strip().split('=', 1)
            k = k.strip()
            v = v.strip()
            if k not in ['mac', 'bridge', 'script', 'backend', 'ip']:
                opts.err('Invalid vif specifier: ' + vif)
            d[k] = v
        vifs.append(d)
    vals.vif = vifs

def preprocess_ip(opts, vals):
    if vals.ip or vals.dhcp != 'off':
        dummy_nfs_server = '1.2.3.4'
        ip = (vals.ip
          + ':' + (vals.nfs_server or dummy_nfs_server)
          + ':' + vals.gateway
          + ':' + vals.netmask
          + ':' + vals.hostname
          + ':' + vals.interface
          + ':' + vals.dhcp)
    else:
        ip = ''
    vals.cmdline_ip = ip

def preprocess_nfs(opts, vals):
    if not vals.nfs_root: return
    if not vals.nfs_server:
        opts.err('Must set nfs root and nfs server')
    nfs = 'nfsroot=' + vals.nfs_server + ':' + vals.nfs_root
    vals.extra = nfs + ' ' + vals.extra
    
def preprocess(opts, vals):
    if not vals.kernel:
        opts.err("No kernel specified")
    preprocess_disk(opts, vals)
    preprocess_pci(opts, vals)
    preprocess_vifs(opts, vals)
    preprocess_ip(opts, vals)
    preprocess_nfs(opts, vals)
         
def make_domain(opts, config):
    """Create, build and start a domain.

    @param opts:   options
    @param config: configuration
    @return: domain id, console port
    @rtype:  (int, int)
    """

    try:
        if opts.vals.load:
            filename = os.path.abspath(opts.vals.load)
            dominfo = server.xend_domain_restore(filename, config)
        else:
            dominfo = server.xend_domain_create(config)
    except XendError, ex:
        opts.err(str(ex))

    dom = sxp.child_value(dominfo, 'name')
    console_info = sxp.child(dominfo, 'console')
    if console_info:
        console_port = int(sxp.child_value(console_info, 'console_port'))
    else:
        console_port = None

    if not opts.vals.paused:
        if server.xend_domain_unpause(dom) < 0:
            server.xend_domain_destroy(dom)
            opts.err("Failed to unpause domain %s" % dom)
    opts.info("Started domain %s, console on port %d"
              % (dom, console_port))
    return (dom, console_port)

def main(argv):
    opts = gopts
    args = opts.parse(argv)
    if opts.vals.help:
        opts.usage()
    if opts.vals.help or opts.vals.help_config:
        opts.load_defconfig(help=1)
    if opts.vals.help or opts.vals.help_config:
        return
    # Process remaining args as config variables.
    for arg in args:
        if '=' in arg:
            (var, val) = arg.strip().split('=', 1)
            gopts.setvar(var.strip(), val.strip())
    if opts.vals.config:
        config = opts.vals.config
    else:
        opts.load_defconfig()
        preprocess(opts, opts.vals)
        if not opts.getopt('name') and opts.getopt('defconfig'):
            opts.setopt('name', os.path.basename(opts.getopt('defconfig')))
        config = make_config(opts.vals)
    if opts.vals.dryrun:
        PrettyPrint.prettyprint(config)
    else:
        (dom, console) = make_domain(opts, config)
        if opts.vals.console_autoconnect:
            console_client.connect('localhost', console)
        
if __name__ == '__main__':
    main(sys.argv)
