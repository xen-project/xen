#============================================================================
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
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 Nguyen Anh Quynh <aquynh@gmail.com>
# Copyright (C) 2005 XenSource Ltd
#============================================================================

"""Domain creation.
"""
import os
import os.path
import string
import sys
import socket
import commands
import time

import xen.lowlevel.xc

from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend.XendClient import server, XendError
from xen.xend.XendBootloader import bootloader
from xen.util import blkif

from xen.xm.opts import *

import console


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

gopts.var('vncviewer', val='no|yes',
          fn=set_bool, default=None,
          use="""Spawn a vncviewer listening for a vnc server in the domain.
          The address of the vncviewer is passed to the domain on the kernel command
          line using 'VNC_SERVER=<host>:<port>'. The port used by vnc is 5500 + DISPLAY.
          A display value with a free port is chosen if possible.
          Only valid when vnc=1.
          """)

gopts.var('name', val='NAME',
          fn=set_value, default=None,
          use="Domain name. Must be unique.")

gopts.var('bootloader', val='FILE',
          fn=set_value, default=None,
          use="Path to bootloader.")

gopts.var('bootentry', val='NAME',
          fn=set_value, default=None,
          use="Entry to boot via boot loader")

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

gopts.var('ssidref', val='SSIDREF',
          fn=set_u32, default=0, 
          use="Security Identifier.")

gopts.var('maxmem', val='MEMORY',
          fn=set_int, default=None,
          use="Maximum domain memory in MB.")

gopts.var('cpu', val='CPU',
          fn=set_int, default=None,
          use="CPU to run the domain on.")

gopts.var('lapic', val='LAPIC',
          fn=set_int, default=0,
          use="Disable or enable local APIC of VMX domain.")

gopts.var('vcpus', val='VCPUS',
          fn=set_int, default=1,
          use="# of Virtual CPUS in domain.")

gopts.var('cpu_weight', val='WEIGHT',
          fn=set_float, default=None,
          use="""Set the new domain's cpu weight.
          WEIGHT is a float that controls the domain's share of the cpu.""")

gopts.var('restart', val='onreboot|always|never',
          fn=set_value, default=None,
          use="""Deprecated.  Use on_poweroff, on_reboot, and on_crash
          instead.

          Whether the domain should be restarted on exit.
          - onreboot: restart on exit with shutdown code reboot
          - always:   always restart on exit, ignore exit code
          - never:    never restart on exit, ignore exit code""")

gopts.var('on_poweroff', val='destroy|restart|preserve|rename-restart',
          fn=set_value, default=None,
          use="""Behaviour when a domain exits with reason 'poweroff'.
          - destroy:        the domain is cleaned up as normal;
          - restart:        a new domain is started in place of the old one;
          - preserve:       no clean-up is done until the domain is manually
                            destroyed (using xm destroy, for example);
          - rename-restart: the old domain is not cleaned up, but is
                            renamed and a new domain started in its place.
          """)

gopts.var('on_reboot', val='destroy|restart|preserve|rename-restart',
          fn=set_value, default=None,
          use="""Behaviour when a domain exits with reason 'reboot'.
          - destroy:        the domain is cleaned up as normal;
          - restart:        a new domain is started in place of the old one;
          - preserve:       no clean-up is done until the domain is manually
                            destroyed (using xm destroy, for example);
          - rename-restart: the old domain is not cleaned up, but is
                            renamed and a new domain started in its place.
          """)

gopts.var('on_crash', val='destroy|restart|preserve|rename-restart',
          fn=set_value, default=None,
          use="""Behaviour  when a domain exits with reason 'crash'.
          - destroy:        the domain is cleaned up as normal;
          - restart:        a new domain is started in place of the old one;
          - preserve:       no clean-up is done until the domain is manually
                            destroyed (using xm destroy, for example);
          - rename-restart: the old domain is not cleaned up, but is
                            renamed and a new domain started in its place.
          """)

gopts.var('blkif', val='no|yes',
          fn=set_bool, default=0,
          use="Make the domain a block device backend.")

gopts.var('netif', val='no|yes',
          fn=set_bool, default=0,
          use="Make the domain a network interface backend.")

gopts.var('tpmif', val='frontend=DOM',
          fn=append_value, default=[],
          use="""Make the domain a TPM interface backend. If frontend is given,
          the frontend in that domain is connected to this backend (not
          completely implemented, yet)""")

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

gopts.var('ioports', val='FROM[-TO]',
          fn=append_value, default=[],
          use="""Add a legacy I/O range to a domain, using given params (in hex).
         For example '-ioports 02f8-02ff'.
         The option may be repeated to add more than one i/o range.""")

gopts.var('usb', val='PATH',
          fn=append_value, default=[],
          use="""Add a physical USB port to a domain, as specified by the path
          to that port.  This option may be repeated to add more than one port.""")

gopts.var('ipaddr', val="IPADDR",
          fn=append_value, default=[],
          use="Add an IP address to the domain.")

gopts.var('vif', val="type=TYPE,mac=MAC,be_mac=MAC,bridge=BRIDGE,script=SCRIPT,backend=DOM,vifname=NAME",
          fn=append_value, default=[],
          use="""Add a network interface with the given MAC address and bridge.
          The vif is configured by calling the given configuration script.
          If type is not specified, default is netfront not ioemu device.
          If mac is not specified a random MAC address is used.
          The MAC address of the backend interface can be selected with be_mac.
          If not specified then the network backend chooses it's own MAC address.
          If bridge is not specified the first bridge found is used.
          If script is not specified the default script is used.
          If backend is not specified the default backend driver domain is used.
          If vifname is not specified the backend virtual interface will have name vifD.N
          where D is the domain id and N is the interface id.
          This option may be repeated to add more than one vif.
          Specifying vifs will increase the number of interfaces as needed.""")

gopts.var('vtpm', val="instance=INSTANCE,backend=DOM",
          fn=append_value, default=[],
          use="""Add a tpm interface. On the backend side us the the given
          instance as virtual TPM instance. Use the backend in the given
          domain.""")

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

gopts.var('device_model', val='FILE',
          fn=set_value, default='',
          use="Path to device model program.")

gopts.var('fda', val='FILE',
          fn=set_value, default='',
          use="Path to fda")

gopts.var('fdb', val='FILE',
          fn=set_value, default='',
          use="Path to fdb")

gopts.var('serial', val='FILE',
          fn=set_value, default='',
          use="Path to serial or pty or vc")

gopts.var('localtime', val='no|yes',
          fn=set_bool, default=0,
          use="Is RTC set to localtime?")

gopts.var('stdvga', val='no|yes',
          fn=set_bool, default=0,
          use="Use std vga or cirrhus logic graphics")

gopts.var('isa', val='no|yes',
          fn=set_bool, default=0,
          use="Simulate an ISA only system?")

gopts.var('cdrom', val='FILE',
          fn=set_value, default='',
          use="Path to cdrom")

gopts.var('boot', val="a|b|c|d",
          fn=set_value, default='c',
          use="Default boot device")

gopts.var('nographic', val='no|yes',
          fn=set_bool, default=0,
          use="Should device models use graphics?")

gopts.var('ne2000', val='no|yes',
          fn=set_bool, default=0,
          use="Should device models use ne2000?")

gopts.var('vnc', val='',
          fn=set_value, default=None,
          use="""Should the device model use VNC?""")

gopts.var('sdl', val='',
          fn=set_value, default=None,
          use="""Should the device model use SDL?""")

gopts.var('display', val='DISPLAY',
          fn=set_value, default=None,
          use="X11 display to use")


def err(msg):
    """Print an error to stderr and exit.
    """
    print >>sys.stderr, "Error:", msg
    sys.exit(1)


def warn(msg):
    """Print a warning to stdout.
    """
    print >>sys.stderr, "Warning:", msg


def strip(pre, s):
    """Strip prefix 'pre' if present.
    """
    if s.startswith(pre):
        return s[len(pre):]
    else:
        return s

def configure_image(vals):
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
    if vals.vcpus:
        config_image.append(['vcpus', vals.vcpus])
    return config_image
    
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

def configure_ioports(config_devs, vals):
    """Create the config for legacy i/o ranges.
    """
    for (io_from, io_to) in vals.ioports:
        config_ioports = ['ioports', ['from', io_from], ['to', io_to]]
        config_devs.append(['device', config_ioports])

def configure_usb(config_devs, vals):
    for path in vals.usb:
        config_usb = ['usb', ['path', path]]
        config_devs.append(['device', config_usb])

def configure_vtpm(config_devs, vals):
    """Create the config for virtual TPM interfaces.
    """
    vtpm = vals.vtpm
    vtpm_n = 1
    for idx in range(0, vtpm_n):
        if idx < len(vtpm):
            d = vtpm[idx]
            instance = d.get('instance')
            if instance == "VTPMD":
                instance = "0"
            else:
                try:
                    if int(instance) == 0:
                        err('VM config error: vTPM instance must not be 0.')
                except ValueError:
                    err('Vm config error: could not parse instance number.')
            backend = d.get('backend')
            config_vtpm = ['vtpm']
            if instance:
                config_vtpm.append(['instance', instance])
            if backend:
                config_vtpm.append(['backend', backend])
            config_devs.append(['device', config_vtpm])

def configure_tpmif(config_devs, vals):
    """Create the config for virtual TPM interfaces.
    """
    tpmif = vals.tpmif
    tpmif_n = 1
    for idx in range(0, tpmif_n):
        if idx < len(tpmif):
            d = tpmif[idx]
            frontend = d.get('frontend')
            config_tpmif = ['tpmif']
            if frontend:
                config_tpmif.append(['frontend', frontend])
            config_devs.append(['device', config_tpmif])


def configure_vifs(config_devs, vals):
    """Create the config for virtual network interfaces.
    """
    vifs = vals.vif
    vifs_n = max(vals.nics, len(vifs))

    for idx in range(0, vifs_n):
        if idx < len(vifs):
            d = vifs[idx]
            mac = d.get('mac')
            be_mac = d.get('be_mac')
            bridge = d.get('bridge')
            script = d.get('script')
            backend = d.get('backend')
            ip = d.get('ip')
            vifname = d.get('vifname')
            type = d.get('type')
        else:
            mac = None
            be_mac = None
            bridge = None
            script = None
            backend = None
            ip = None
            vifname = None
            type = None
        config_vif = ['vif']
        if mac:
            config_vif.append(['mac', mac])
        if vifname:
            config_vif.append(['vifname', vifname])
        if be_mac:
            config_vif.append(['be_mac', be_mac])
        if bridge:
            config_vif.append(['bridge', bridge])
        if script:
            config_vif.append(['script', script])
        if backend:
            config_vif.append(['backend', backend])
        if ip:
            config_vif.append(['ip', ip])
        if type:
            config_vif.append(['type', type])
        config_devs.append(['device', config_vif])

def configure_vfr(config, vals):
     if not vals.ipaddr: return
     config_vfr = ['vfr']
     idx = 0 # No way of saying which IP is for which vif?
     for ip in vals.ipaddr:
         config_vfr.append(['vif', ['id', idx], ['ip', ip]])
     config.append(config_vfr)

def configure_vmx(config_image, vals):
    """Create the config for VMX devices.
    """
    args = [ 'device_model', 'vcpus', 'cdrom', 'boot', 'fda', 'fdb',
             'localtime', 'serial', 'stdvga', 'isa', 'nographic',
             'vnc', 'vncviewer', 'sdl', 'display', 'ne2000', 'lapic']
    for a in args:
        if (vals.__dict__[a]):
            config_image.append([a, vals.__dict__[a]])

def run_bootloader(vals):
    if not os.access(vals.bootloader, os.X_OK):
        err("Bootloader isn't executable")
    if len(vals.disk) < 1:
        err("No disks configured and boot loader requested")
    (uname, dev, mode, backend) = vals.disk[0]
    file = blkif.blkdev_uname_to_file(uname)

    return bootloader(vals.bootloader, file, not vals.console_autoconnect,
                      vals.vcpus, vals.bootentry)

def make_config(vals):
    """Create the domain configuration.
    """
    
    config = ['vm']

    def add_conf(n):
        if hasattr(vals, n):
            v = getattr(vals, n)
            if v:
                config.append([n, v])

    map(add_conf, ['name', 'memory', 'ssidref', 'maxmem', 'restart',
                   'on_poweroff', 'on_reboot', 'on_crash'])
    
    if vals.cpu is not None:
        config.append(['cpu', vals.cpu])
    if vals.cpu_weight is not None:
        config.append(['cpu_weight', vals.cpu_weight])
    if vals.blkif:
        config.append(['backend', ['blkif']])
    if vals.netif:
        config.append(['backend', ['netif']])
    if vals.tpmif:
        config.append(['backend', ['tpmif']])

    if vals.bootloader:
        config.append(['bootloader', vals.bootloader])
        config_image = run_bootloader(vals)
    else:
        config_image = configure_image(vals)
    configure_vmx(config_image, vals)
    config.append(['image', config_image])

    config_devs = []
    configure_disks(config_devs, vals)
    configure_pci(config_devs, vals)
    configure_ioports(config_devs, vals)
    configure_vifs(config_devs, vals)
    configure_usb(config_devs, vals)
    configure_vtpm(config_devs, vals)
    config += config_devs

    return config

def preprocess_disk(vals):
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
            err('Invalid disk specifier: ' + v)
        disk.append(d)
    vals.disk = disk

def preprocess_pci(vals):
    if not vals.pci: return
    pci = []
    for v in vals.pci:
        d = v.split(',')
        if len(d) != 3:
            err('Invalid pci specifier: ' + v)
        # Components are in hex: add hex specifier.
        hexd = map(lambda v: '0x'+v, d)
        pci.append(hexd)
    vals.pci = pci

def preprocess_ioports(vals):
    if not vals.ioports: return
    ioports = []
    for v in vals.ioports:
        d = v.split('-')
        if len(d) < 1 or len(d) > 2:
            err('Invalid i/o port range specifier: ' + v)
        if len(d) == 1:
            d.append(d[0])
        # Components are in hex: add hex specifier.
        hexd = map(lambda v: '0x'+v, d)
        ioports.append(hexd)
    vals.ioports = ioports
        
def preprocess_vifs(vals):
    if not vals.vif: return
    vifs = []
    for vif in vals.vif:
        d = {}
        a = vif.split(',')
        for b in a:
            (k, v) = b.strip().split('=', 1)
            k = k.strip()
            v = v.strip()
            if k not in ['type', 'mac', 'be_mac', 'bridge', 'script', 'backend', 'ip', 'vifname']:
                err('Invalid vif specifier: ' + vif)
            d[k] = v
        vifs.append(d)
    vals.vif = vifs

def preprocess_vtpm(vals):
    if not vals.vtpm: return
    vtpms = []
    for vtpm in vals.vtpm:
        d = {}
        a = vtpm.split(',')
        for b in a:
            (k, v) = b.strip().split('=', 1)
            k = k.strip()
            v = v.strip()
            if k not in ['backend', 'instance']:
                err('Invalid vtpm specifier: ' + vtpm)
            d[k] = v
        vtpms.append(d)
    vals.vtpm = vtpms

def preprocess_tpmif(vals):
    if not vals.tpmif: return
    tpmifs = []
    for tpmif in vals.tpmif:
        d = {}
        a = tpmif.split(',')
        for b in a:
            (k, v) = b.strip().split('=', 1)
            k = k.strip()
            v = v.strip()
            if k not in ['frontend']:
                err('Invalid tpmif specifier: ' + vtpm)
            d[k] = v
        tpmifs.append(d)
    vals.tpmif = tpmifs

def preprocess_ip(vals):
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

def preprocess_nfs(vals):
    if not vals.nfs_root: return
    if not vals.nfs_server:
        err('Must set nfs root and nfs server')
    nfs = 'nfsroot=' + vals.nfs_server + ':' + vals.nfs_root
    vals.extra = nfs + ' ' + vals.extra


def get_host_addr():
    host = socket.gethostname()
    addr = socket.gethostbyname(host)
    return addr

VNC_BASE_PORT = 5500

def choose_vnc_display():
    """Try to choose a free vnc display.
    """
    def netstat_local_ports():
        """Run netstat to get a list of the local ports in use.
        """
        l = os.popen("netstat -nat").readlines()
        r = []
        # Skip 2 lines of header.
        for x in l[2:]:
            # Local port is field 3.
            y = x.split()[3]
            # Field is addr:port, split off the port.
            y = y.split(':')[-1]
            r.append(int(y))
        return r

    ports = netstat_local_ports()
    for d in range(1, 100):
        port = VNC_BASE_PORT + d
        if port in ports: continue
        return d
    return None

vncpid = None

def spawn_vnc(display):
    vncargs = (["vncviewer", "-log", "*:stdout:0",
            "-listen", "%d" % (VNC_BASE_PORT + display) ])
    global vncpid    
    vncpid = os.spawnvp(os.P_NOWAIT, "vncviewer", vncargs)

    return VNC_BASE_PORT + display
    
def preprocess_vnc(vals):
    """If vnc was specified, spawn a vncviewer in listen mode
    and pass its address to the domain on the kernel command line.
    """
    if not (vals.vnc and vals.vncviewer) or vals.dryrun: return
    vnc_display = choose_vnc_display()
    if not vnc_display:
        warn("No free vnc display")
        return
    print 'VNC=', vnc_display
    vnc_port = spawn_vnc(vnc_display)
    if vnc_port > 0:
        vnc_host = get_host_addr()
        vnc = 'VNC_VIEWER=%s:%d' % (vnc_host, vnc_port)
        vals.extra = vnc + ' ' + vals.extra
    
def preprocess(vals):
    if not vals.kernel and not vals.bootloader:
        err("No kernel specified")
    preprocess_disk(vals)
    preprocess_pci(vals)
    preprocess_ioports(vals)
    preprocess_vifs(vals)
    preprocess_ip(vals)
    preprocess_nfs(vals)
    preprocess_vnc(vals)
    preprocess_vtpm(vals)
    preprocess_tpmif(vals)
         
def make_domain(opts, config):
    """Create, build and start a domain.

    @param opts:   options
    @param config: configuration
    @return: domain id
    @rtype:  int
    """

    try:
        if opts.vals.load:
            filename = os.path.abspath(opts.vals.load)
            dominfo = server.xend_domain_restore(filename, config)
        else:
            dominfo = server.xend_domain_create(config)
    except XendError, ex:
        import signal
        if vncpid:
            os.kill(vncpid, signal.SIGKILL)
        err(str(ex))

    dom = sxp.child_value(dominfo, 'name')

    if server.xend_domain_wait_for_devices(dom) < 0:
        server.xend_domain_destroy(dom)
        err("Device creation failed for domain %s" % dom)

    if not opts.vals.paused:
        if server.xend_domain_unpause(dom) < 0:
            server.xend_domain_destroy(dom)
            err("Failed to unpause domain %s" % dom)
    opts.info("Started domain %s" % (dom))
    return int(sxp.child_value(dominfo, 'domid'))

def get_dom0_alloc():
    """Return current allocation memory of dom0 (in MB). Return 0 on error"""
    PROC_XEN_BALLOON = "/proc/xen/balloon"

    f = open(PROC_XEN_BALLOON, "r")
    line = f.readline()
    for x in line.split():
        for n in x:
            if not n.isdigit():
                break
        else:
            f.close()
            return int(x)/1024
    f.close()
    return 0

def balloon_out(dom0_min_mem, opts):
    """Balloon out memory from dom0 if necessary"""
    SLACK = 4
    timeout = 20 # 2s
    ret = 1

    xc = xen.lowlevel.xc.new()
    free_mem = xc.physinfo()['free_pages'] / 256
    domU_need_mem = opts.vals.memory + SLACK 

    # we already have enough free memory, return success
    if free_mem >= domU_need_mem:
        del xc
        return 0

    dom0_cur_alloc = get_dom0_alloc()
    dom0_new_alloc = dom0_cur_alloc - (domU_need_mem - free_mem)
    if dom0_new_alloc < dom0_min_mem:
        dom0_new_alloc = dom0_min_mem

    server.xend_domain_mem_target_set(0, dom0_new_alloc)

    while timeout > 0:
        time.sleep(0.1) # sleep 100ms

        free_mem = xc.physinfo()['free_pages'] / 256
        if free_mem >= domU_need_mem:
            ret = 0
            break
        timeout -= 1

    del xc
    return ret


def parseCommandLine(argv):
    opts = gopts
    args = opts.parse(argv)
    if opts.vals.help:
        opts.usage()
    if opts.vals.help or opts.vals.help_config:
        opts.load_defconfig(help=1)
    if opts.vals.help or opts.vals.help_config:
        return (None, None)

    if not opts.vals.display:
        opts.vals.display = os.getenv("DISPLAY")

    # Process remaining args as config variables.
    for arg in args:
        if '=' in arg:
            (var, val) = arg.strip().split('=', 1)
            gopts.setvar(var.strip(), val.strip())
    if opts.vals.config:
        config = opts.vals.config
    else:
        opts.load_defconfig()
        preprocess(opts.vals)
        if not opts.getopt('name') and opts.getopt('defconfig'):
            opts.setopt('name', os.path.basename(opts.getopt('defconfig')))
        config = make_config(opts.vals)

    return (opts, config)


def main(argv):
    (opts, config) = parseCommandLine(argv)

    if not opts:
        return

    if opts.vals.dryrun:
        PrettyPrint.prettyprint(config)
    else:
        from xen.xend import XendRoot

        xroot = XendRoot.instance()

        dom0_min_mem = xroot.get_dom0_min_mem()
        if dom0_min_mem != 0:
            if balloon_out(dom0_min_mem, opts):
                print >>sys.stderr, "error: cannot allocate enough memory for domain"
                sys.exit(1)

        dom = make_domain(opts, config)
        if opts.vals.console_autoconnect:
            console.execConsole(dom)
        
if __name__ == '__main__':
    main(sys.argv)
