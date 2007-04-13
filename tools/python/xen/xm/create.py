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
# Copyright (C) 2005-2006 XenSource Ltd
#============================================================================

"""Domain creation.
"""
import os
import os.path
import sys
import socket
import re
import time
import xmlrpclib

from xen.xend import sxp
from xen.xend import PrettyPrint as SXPPrettyPrint
from xen.xend import osdep
import xen.xend.XendClient
from xen.xend.XendBootloader import bootloader
from xen.util import blkif
from xen.util import security
from xen.xm.main import serverType, SERVER_XEN_API, get_single_vm

from xen.xm.opts import *

from main import server
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
          use="Print the available configuration variables (vars) for the "
          "configuration script.")

gopts.opt('quiet', short='q',
          fn=set_true, default=0,
          use="Quiet.")

gopts.opt('path', val='PATH',
          fn=set_value, default='.:/etc/xen',
          use="Search path for configuration scripts. "
          "The value of PATH is a colon-separated directory list.")

gopts.opt('defconfig', short='f', val='FILE',
          fn=set_value, default='xmdefconfig',
          use="Use the given Python configuration script."
          "The configuration script is loaded after arguments have been "
          "processed. Each command-line option sets a configuration "
          "variable named after its long option name, and these "
          "variables are placed in the environment of the script before "
          "it is loaded. Variables for options that may be repeated have "
          "list values. Other variables can be set using VAR=VAL on the "
          "command line. "     
          "After the script is loaded, option values that were not set "
          "on the command line are replaced by the values set in the script.")

gopts.default('defconfig')

gopts.opt('config', short='F', val='FILE',
          fn=set_value, default=None,
          use="Domain configuration to use (SXP).\n"
          "SXP is the underlying configuration format used by Xen.\n"
          "SXP configurations can be hand-written or generated from Python "
          "configuration scripts, using the -n (dryrun) option to print "
          "the configuration.")

gopts.opt('dryrun', short='n',
          fn=set_true, default=0,
          use="Dry run - prints the resulting configuration in SXP but "
          "does not create the domain.")

gopts.opt('xmldryrun', short='x',
          fn=set_true, default=0,
          use="XML dry run - prints the resulting configuration in XML but "
          "does not create the domain.")

gopts.opt('skipdtd', short='s',
          fn=set_true, default=0,
          use="Skip DTD checking - skips checks on XML before creating. "
          " Experimental.  Can decrease create time." )

gopts.opt('paused', short='p',
          fn=set_true, default=0,
          use='Leave the domain paused after it is created.')

gopts.opt('console_autoconnect', short='c',
          fn=set_true, default=0,
          use="Connect to the console after the domain is created.")

gopts.var('vncpasswd', val='NAME',
          fn=set_value, default=None,
          use="Password for VNC console on HVM domain.")

gopts.var('vncviewer', val='no|yes',
          fn=set_bool, default=None,
           use="Spawn a vncviewer listening for a vnc server in the domain.\n"
           "The address of the vncviewer is passed to the domain on the "
           "kernel command line using 'VNC_SERVER=<host>:<port>'. The port "
           "used by vnc is 5500 + DISPLAY. A display value with a free port "
           "is chosen if possible.\nOnly valid when vnc=1.")

gopts.var('vncconsole', val='no|yes',
          fn=set_bool, default=None,
          use="Spawn a vncviewer process for the domain's graphical console.\n"
          "Only valid when vnc=1.")

gopts.var('name', val='NAME',
          fn=set_value, default=None,
          use="Domain name. Must be unique.")

gopts.var('bootloader', val='FILE',
          fn=set_value, default=None,
          use="Path to bootloader.")

gopts.var('bootargs', val='NAME',
          fn=set_value, default=None,
          use="Arguments to pass to boot loader")

gopts.var('bootentry', val='NAME',
          fn=set_value, default=None,
          use="DEPRECATED.  Entry to boot via boot loader.  Use bootargs.")

gopts.var('kernel', val='FILE',
          fn=set_value, default=None,
          use="Path to kernel image.")

gopts.var('ramdisk', val='FILE',
          fn=set_value, default='',
          use="Path to ramdisk.")

gopts.var('features', val='FEATURES',
          fn=set_value, default='',
          use="Features to enable in guest kernel")

gopts.var('builder', val='FUNCTION',
          fn=set_value, default='linux',
          use="Function to use to build the domain.")

gopts.var('memory', val='MEMORY',
          fn=set_int, default=128,
          use="Domain memory in MB.")

gopts.var('maxmem', val='MEMORY',
          fn=set_int, default=None,
          use="Maximum domain memory in MB.")

gopts.var('shadow_memory', val='MEMORY',
          fn=set_int, default=0,
          use="Domain shadow memory in MB.")

gopts.var('cpu', val='CPU',
          fn=set_int, default=None,
          use="CPU to run the VCPU0 on.")

gopts.var('cpus', val='CPUS',
          fn=set_value, default=None,
          use="CPUS to run the domain on.")

gopts.var('rtc_timeoffset', val='RTC_TIMEOFFSET',
          fn=set_value, default="0",
          use="Set RTC offset.")

gopts.var('pae', val='PAE',
          fn=set_int, default=1,
          use="Disable or enable PAE of HVM domain.")

gopts.var('acpi', val='ACPI',
          fn=set_int, default=1,
          use="Disable or enable ACPI of HVM domain.")

gopts.var('apic', val='APIC',
          fn=set_int, default=1,
          use="Disable or enable APIC mode.")

gopts.var('vcpus', val='VCPUS',
          fn=set_int, default=1,
          use="# of Virtual CPUS in domain.")

gopts.var('vcpu_avail', val='VCPUS',
          fn=set_long, default=None,
          use="Bitmask for virtual CPUs to make available immediately.")

gopts.var('cpu_cap', val='CAP',
          fn=set_int, default=None,
          use="""Set the maximum amount of cpu.
          CAP is a percentage that fixes the maximum amount of cpu.""")

gopts.var('cpu_weight', val='WEIGHT',
          fn=set_int, default=None,
          use="""Set the cpu time ratio to be allocated to the domain.""")

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

gopts.var('tpmif', val='no|yes',
          fn=append_value, default=0,
          use="Make the domain a TPM interface backend.")

gopts.var('disk', val='phy:DEV,VDEV,MODE[,DOM]',
          fn=append_value, default=[],
          use="""Add a disk device to a domain. The physical device is DEV,
          which is exported to the domain as VDEV. The disk is read-only if MODE
          is 'r', read-write if MODE is 'w'. If DOM is specified it defines the
          backend driver domain to use for the disk.
          The option may be repeated to add more than one disk.""")

gopts.var('pci', val='BUS:DEV.FUNC',
          fn=append_value, default=[],
          use="""Add a PCI device to a domain, using given params (in hex).
         For example 'pci=c0:02.1a'.
         The option may be repeated to add more than one pci device.""")

gopts.var('ioports', val='FROM[-TO]',
          fn=append_value, default=[],
          use="""Add a legacy I/O range to a domain, using given params (in hex).
         For example 'ioports=02f8-02ff'.
         The option may be repeated to add more than one i/o range.""")

gopts.var('irq', val='IRQ',
          fn=append_value, default=[],
          use="""Add an IRQ (interrupt line) to a domain.
         For example 'irq=7'.
         This option may be repeated to add more than one IRQ.""")

gopts.var('usbport', val='PATH',
          fn=append_value, default=[],
          use="""Add a physical USB port to a domain, as specified by the path
          to that port.  This option may be repeated to add more than one port.""")

gopts.var('vfb', val="type={vnc,sdl},vncunused=1,vncdisplay=N,vnclisten=ADDR,display=DISPLAY,xauthority=XAUTHORITY,vncpasswd=PASSWORD",
          fn=append_value, default=[],
          use="""Make the domain a framebuffer backend.
          The backend type should be either sdl or vnc.
          For type=vnc, connect an external vncviewer.  The server will listen
          on ADDR (default 127.0.0.1) on port N+5900.  N defaults to the
          domain id.  If vncunused=1, the server will try to find an arbitrary
          unused port above 5900.  vncpasswd overrides the XenD configured
          default password.
          For type=sdl, a viewer will be started automatically using the
          given DISPLAY and XAUTHORITY, which default to the current user's
          ones.""")

gopts.var('vif', val="type=TYPE,mac=MAC,bridge=BRIDGE,ip=IPADDR,script=SCRIPT,backend=DOM,vifname=NAME",
          fn=append_value, default=[],
          use="""Add a network interface with the given MAC address and bridge.
          The vif is configured by calling the given configuration script.
          If type is not specified, default is netfront.
          If mac is not specified a random MAC address is used.
          If not specified then the network backend chooses it's own MAC address.
          If bridge is not specified the first bridge found is used.
          If script is not specified the default script is used.
          If backend is not specified the default backend driver domain is used.
          If vifname is not specified the backend virtual interface will have name vifD.N
          where D is the domain id and N is the interface id.
          This option may be repeated to add more than one vif.
          Specifying vifs will increase the number of interfaces as needed.""")

gopts.var('vtpm', val="instance=INSTANCE,backend=DOM,type=TYPE",
          fn=append_value, default=[],
          use="""Add a TPM interface. On the backend side use the given
          instance as virtual TPM instance. The given number is merely the
          preferred instance number. The hotplug script will determine
          which instance number will actually be assigned to the domain.
          The associtation between virtual machine and the TPM instance
          number can be found in /etc/xen/vtpm.db. Use the backend in the
          given domain.
          The type parameter can be used to select a specific driver type
          that the VM can use. To prevent a fully virtualized domain (HVM)
          from being able to access an emulated device model, you may specify
          'paravirtualized' here.""")

gopts.var('access_control', val="policy=POLICY,label=LABEL",
          fn=append_value, default=[],
          use="""Add a security label and the security policy reference that defines it.
          The local ssid reference is calculated when starting/resuming the domain. At
          this time, the policy is checked against the active policy as well. This way,
          migrating through save/restore is covered and local labels are automatically
          created correctly on the system where a domain is started / resumed.""")

gopts.var('nics', val="NUM",
          fn=set_int, default=-1,
          use="""DEPRECATED.  Use empty vif entries instead.

          Set the number of network interfaces.
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

gopts.var('monitor', val='no|yes',
          fn=set_bool, default=0,
          use="""Should the device model use monitor?""")

gopts.var('localtime', val='no|yes',
          fn=set_bool, default=0,
          use="Is RTC set to localtime?")

gopts.var('keymap', val='FILE',
          fn=set_value, default='',
          use="Set keyboard layout used")

gopts.var('usb', val='no|yes',
          fn=set_bool, default=0,
          use="Emulate USB devices?")

gopts.var('usbdevice', val='NAME',
          fn=set_value, default='',
          use="Name of USB device to add?")

gopts.var('stdvga', val='no|yes',
          fn=set_bool, default=0,
          use="Use std vga or cirrhus logic graphics")

gopts.var('isa', val='no|yes',
          fn=set_bool, default=0,
          use="Simulate an ISA only system?")

gopts.var('boot', val="a|b|c|d",
          fn=set_value, default='c',
          use="Default boot device")

gopts.var('nographic', val='no|yes',
          fn=set_bool, default=0,
          use="Should device models use graphics?")

gopts.var('soundhw', val='audiodev',
          fn=set_value, default='',
          use="Should device models enable audio device?")

gopts.var('vnc', val='',
          fn=set_value, default=None,
          use="""Should the device model use VNC?""")

gopts.var('vncdisplay', val='',
          fn=set_value, default=None,
          use="""VNC display to use""")

gopts.var('vnclisten', val='',
          fn=set_value, default=None,
          use="""Address for VNC server to listen on.""")

gopts.var('vncunused', val='',
          fn=set_bool, default=1,
          use="""Try to find an unused port for the VNC server.
          Only valid when vnc=1.""")

gopts.var('sdl', val='',
          fn=set_value, default=None,
          use="""Should the device model use SDL?""")

gopts.var('display', val='DISPLAY',
          fn=set_value, default=None,
          use="X11 display to use")

gopts.var('xauthority', val='XAUTHORITY',
          fn=set_value, default=None,
          use="X11 Authority to use")

gopts.var('uuid', val='',
          fn=set_value, default=None,
          use="""xenstore UUID (universally unique identifier) to use.  One 
          will be randomly generated if this option is not set, just like MAC 
          addresses for virtual network interfaces.  This must be a unique 
          value across the entire cluster.""")

gopts.var('on_xend_start', val='ignore|start',
          fn=set_value, default='ignore',
          use='Action to perform when xend starts')

gopts.var('on_xend_stop', val='continue|shutdown|suspend',
          fn=set_value, default="ignore",
          use="""Behaviour when Xend stops:
          - ignore:         Domain continues to run;
          - shutdown:       Domain is shutdown;
          - suspend:        Domain is suspended;
          """)

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
    if not vals.builder:
        return None
    config_image = [ vals.builder ]
    if vals.kernel:
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

    if vals.builder == 'hvm':
        configure_hvm(config_image, vals) 
       
    return config_image
    
def configure_disks(config_devs, vals):
    """Create the config for disks (virtual block devices).
    """
    for (uname, dev, mode, backend) in vals.disk:
        if uname.startswith('tap:'):
            cls = 'tap'
        else:
            cls = 'vbd'

        config_vbd = [cls,
                      ['uname', uname],
                      ['dev', dev ],
                      ['mode', mode ] ]
        if backend:
            config_vbd.append(['backend', backend])
        config_devs.append(['device', config_vbd])

def configure_pci(config_devs, vals):
    """Create the config for pci devices.
    """
    config_pci = []
    for (domain, bus, slot, func) in vals.pci:
        config_pci.append(['dev', ['domain', domain], ['bus', bus], \
                        ['slot', slot], ['func', func]])

    if len(config_pci)>0:
        config_pci.insert(0, 'pci')
        config_devs.append(['device', config_pci])

def configure_ioports(config_devs, vals):
    """Create the config for legacy i/o ranges.
    """
    for (io_from, io_to) in vals.ioports:
        config_ioports = ['ioports', ['from', io_from], ['to', io_to]]
        config_devs.append(['device', config_ioports])

def configure_irq(config_devs, vals):
    """Create the config for irqs.
    """
    for irq in vals.irq:
        config_irq = ['irq', ['irq', irq]]
        config_devs.append(['device', config_irq])

def configure_usb(config_devs, vals):
    for path in vals.usbport:
        config_usb = ['usbport', ['path', path]]
        config_devs.append(['device', config_usb])

def configure_vfbs(config_devs, vals):
    for f in vals.vfb:
        d = comma_sep_kv_to_dict(f)
        config = ['vfb']
        if not d.has_key("type"):
            d['type'] = 'sdl'
        for (k,v) in d.iteritems():
            if not k in [ 'vnclisten', 'vncunused', 'vncdisplay', 'display',
                          'xauthority', 'type', 'vncpasswd' ]:
                err("configuration option %s unknown to vfbs" % k)
            config.append([k,v])
        if not d.has_key("keymap"):
            if vals.keymap:
                config.append(['keymap',vals.keymap])
        if not d.has_key("display") and os.environ.has_key("DISPLAY"):
            config.append(["display", os.environ['DISPLAY']])
        if not d.has_key("xauthority"):
            config.append(["xauthority", get_xauthority()])
        config_devs.append(['device', ['vkbd']])
        config_devs.append(['device', config])

def configure_security(config, vals):
    """Create the config for ACM security labels.
    """
    access_control = vals.access_control
    num = len(access_control)
    if num == 1:
        d = access_control[0]
        policy = d.get('policy')
        label = d.get('label')
        if policy != security.active_policy:
            err("Security policy (" + policy + ") incompatible with enforced policy ("
                + security.active_policy + ")." )
        config_access_control = ['access_control',
                                 ['policy', policy],
                                 ['label', label] ]

        #ssidref cannot be specified together with access_control
        if sxp.child_value(config, 'ssidref'):
            err("ERROR: SSIDREF and access_control are mutually exclusive but both specified!")
        #else calculate ssidre from label
        ssidref = security.label2ssidref(label, policy, 'dom')
        if not ssidref :
            err("ERROR calculating ssidref from access_control.")
        security_label = ['security', [ config_access_control, ['ssidref' , ssidref ] ] ]
        config.append(security_label)
    elif num == 0:
        if hasattr(vals, 'ssidref'):
            if not security.on():
                err("ERROR: Security ssidref specified but no policy active.")
            ssidref = getattr(vals, 'ssidref')
            security_label = ['security', [ [ 'ssidref' , int(ssidref) ] ] ]
            config.append(security_label)
    elif num > 1:
        err("VM config error: Multiple access_control definitions!")


def configure_vtpm(config_devs, vals):
    """Create the config for virtual TPM interfaces.
    """
    vtpm = vals.vtpm
    if len(vtpm) > 0:
        d = vtpm[0]
        instance = d.get('instance')
        if instance == "VTPMD":
            instance = "0"
        else:
            if instance != None:
                try:
                    if int(instance) == 0:
                        err('VM config error: vTPM instance must not be 0.')
                except ValueError:
                    err('Vm config error: could not parse instance number.')
        backend = d.get('backend')
        typ = d.get('type')
        config_vtpm = ['vtpm']
        if instance:
            config_vtpm.append(['pref_instance', instance])
        if backend:
            config_vtpm.append(['backend', backend])
        if typ:
            config_vtpm.append(['type', type])
        config_devs.append(['device', config_vtpm])


def configure_vifs(config_devs, vals):
    """Create the config for virtual network interfaces.
    """

    vifs = vals.vif
    vifs_n = len(vifs)

    if hasattr(vals, 'nics'):
        if vals.nics > 0:
            warn("The nics option is deprecated.  Please use an empty vif "
                 "entry instead:\n\n  vif = [ '' ]\n")
            for _ in range(vifs_n, vals.nics):
                vifs.append('')
            vifs_n = len(vifs)
        elif vals.nics == 0:
            warn("The nics option is deprecated.  Please remove it.")

    for c in vifs:
        d = comma_sep_kv_to_dict(c)
        config_vif = ['vif']

        def f(k):
            if k not in ['backend', 'bridge', 'ip', 'mac', 'script', 'type',
                         'vifname', 'rate', 'model']:
                err('Invalid vif option: ' + k)

            config_vif.append([k, d[k]])

        map(f, d.keys())
        config_devs.append(['device', config_vif])


def configure_hvm(config_image, vals):
    """Create the config for HVM devices.
    """
    args = [ 'device_model', 'pae', 'vcpus', 'boot', 'fda', 'fdb',
             'localtime', 'serial', 'stdvga', 'isa', 'nographic', 'soundhw',
             'vnc', 'vncdisplay', 'vncunused', 'vncconsole', 'vnclisten',
             'sdl', 'display', 'xauthority', 'rtc_timeoffset',
             'acpi', 'apic', 'usb', 'usbdevice', 'keymap' ]
    for a in args:
        if a in vals.__dict__ and vals.__dict__[a] is not None:
            config_image.append([a, vals.__dict__[a]])
    config_image.append(['vncpasswd', vals.vncpasswd])


def make_config(vals):
    """Create the domain configuration.
    """
    
    config = ['vm']

    def add_conf(n):
        if hasattr(vals, n):
            v = getattr(vals, n)
            if v:
                config.append([n, v])

    map(add_conf, ['name', 'memory', 'maxmem', 'shadow_memory',
                   'restart', 'on_poweroff',
                   'on_reboot', 'on_crash', 'vcpus', 'vcpu_avail', 'features',
                   'on_xend_start', 'on_xend_stop'])

    if vals.uuid is not None:
        config.append(['uuid', vals.uuid])
    if vals.cpu is not None:
        config.append(['cpu', vals.cpu])
    if vals.cpus is not None:
        config.append(['cpus', vals.cpus])
    if vals.cpu_cap is not None:
        config.append(['cpu_cap', vals.cpu_cap])
    if vals.cpu_weight is not None:
        config.append(['cpu_weight', vals.cpu_weight])
    if vals.blkif:
        config.append(['backend', ['blkif']])
    if vals.netif:
        config.append(['backend', ['netif']])
    if vals.tpmif:
        config.append(['backend', ['tpmif']])
    if vals.localtime:
        config.append(['localtime', vals.localtime])

    config_image = configure_image(vals)
    if vals.bootloader:
        if vals.bootloader == "pygrub":
            vals.bootloader = osdep.pygrub_path

        config.append(['bootloader', vals.bootloader])
        if vals.bootargs:
            config.append(['bootloader_args', vals.bootargs])
        else: 
            config.append(['bootloader_args', '-q'])        
    config.append(['image', config_image])

    config_devs = []
    configure_disks(config_devs, vals)
    configure_pci(config_devs, vals)
    configure_ioports(config_devs, vals)
    configure_irq(config_devs, vals)
    configure_vifs(config_devs, vals)
    configure_usb(config_devs, vals)
    configure_vtpm(config_devs, vals)
    configure_vfbs(config_devs, vals)
    configure_security(config, vals)
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
    for pci_dev_str in vals.pci:
        pci_match = re.match(r"((?P<domain>[0-9a-fA-F]{1,4})[:,])?" + \
                r"(?P<bus>[0-9a-fA-F]{1,2})[:,]" + \
                r"(?P<slot>[0-9a-fA-F]{1,2})[.,]" + \
                r"(?P<func>[0-9a-fA-F])", pci_dev_str)
        if pci_match!=None:
            pci_dev_info = pci_match.groupdict('0')
            try:
                pci.append( ('0x'+pci_dev_info['domain'], \
                        '0x'+pci_dev_info['bus'], \
                        '0x'+pci_dev_info['slot'], \
                        '0x'+pci_dev_info['func']))
            except IndexError:
                err('Error in PCI slot syntax "%s"'%(pci_dev_str))
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
        hexd = ['0x' + x for x in d]
        ioports.append(hexd)
    vals.ioports = ioports
        
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

def preprocess_access_control(vals):
    if not vals.access_control:
        return
    access_controls = []
    num = len(vals.access_control)
    if num == 1:
        access_control = (vals.access_control)[0]
        d = {}
        a = access_control.split(',')
        if len(a) > 2:
            err('Too many elements in access_control specifier: ' + access_control)
        for b in a:
            (k, v) = b.strip().split('=', 1)
            k = k.strip()
            v = v.strip()
            if k not in ['policy','label']:
                err('Invalid access_control specifier: ' + access_control)
            d[k] = v
        access_controls.append(d)
        vals.access_control = access_controls
    elif num > 1:
        err('Multiple access_control definitions.')

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

def daemonize(prog, args):
    """Runs a program as a daemon with the list of arguments.  Returns the PID
    of the daemonized program, or returns 0 on error.
    """
    r, w = os.pipe()
    pid = os.fork()

    if pid == 0:
        os.close(r)
        w = os.fdopen(w, 'w')
        os.setsid()
        try:
            pid2 = os.fork()
        except:
            pid2 = None
        if pid2 == 0:
            os.chdir("/")
            for fd in range(0, 256):
                try:
                    os.close(fd)
                except:
                    pass
            os.open("/dev/null", os.O_RDWR)
            os.dup2(0, 1)
            os.dup2(0, 2)
            os.execvp(prog, args)
            os._exit(1)
        else:
            w.write(str(pid2 or 0))
            w.close()
            os._exit(0)
    os.close(w)
    r = os.fdopen(r)
    daemon_pid = int(r.read())
    r.close()
    os.waitpid(pid, 0)
    return daemon_pid

def spawn_vnc(display):
    """Spawns a vncviewer that listens on the specified display.  On success,
    returns the port that the vncviewer is listening on and sets the global
    vncpid.  On failure, returns 0.  Note that vncviewer is daemonized.
    """
    vncargs = (["vncviewer", "-log", "*:stdout:0",
            "-listen", "%d" % (VNC_BASE_PORT + display) ])
    global vncpid
    vncpid = daemonize("vncviewer", vncargs)
    if vncpid == 0:
        return 0

    return VNC_BASE_PORT + display

def preprocess_vnc(vals):
    """If vnc was specified, spawn a vncviewer in listen mode
    and pass its address to the domain on the kernel command line.
    """
    if vals.dryrun: return
    if vals.vncviewer:
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
    preprocess_disk(vals)
    preprocess_pci(vals)
    preprocess_ioports(vals)
    preprocess_ip(vals)
    preprocess_nfs(vals)
    preprocess_vnc(vals)
    preprocess_vtpm(vals)
    preprocess_access_control(vals)


def comma_sep_kv_to_dict(c):
    """Convert comma-separated, equals-separated key-value pairs into a
    dictionary.
    """
    d = {}
    c = c.strip()
    if len(c) > 0:
        a = c.split(',')
        for b in a:
            if b.find('=') == -1:
                err("%s should be a pair, separated by an equals sign." % b)
            (k, v) = b.split('=', 1)
            k = k.strip()
            v = v.strip()
            d[k] = v
    return d


def make_domain(opts, config):
    """Create, build and start a domain.

    @param opts:   options
    @param config: configuration
    @return: domain id
    @rtype:  int
    """

    try:
        dominfo = server.xend.domain.create(config)
    except xmlrpclib.Fault, ex:
        import signal
        if vncpid:
            os.kill(vncpid, signal.SIGKILL)
        if ex.faultCode == xen.xend.XendClient.ERROR_INVALID_DOMAIN:
            err("the domain '%s' does not exist." % ex.faultString)
        else:
            err("%s" % ex.faultString)
    except Exception, ex:
        # main.py has good error messages that let the user know what failed.
        # unless the error is a create.py specific thing, it should be handled
        # at main. The purpose of this general-case 'Exception' handler is to
        # clean up create.py specific processes/data but since create.py does
        # not know what to do with the error, it should pass it up.
        import signal
        if vncpid:
            os.kill(vncpid, signal.SIGKILL)
        raise

    dom = sxp.child_value(dominfo, 'name')

    try:
        server.xend.domain.waitForDevices(dom)
    except xmlrpclib.Fault, ex:
        server.xend.domain.destroy(dom)
        err("%s" % ex.faultString)
    except:
        server.xend.domain.destroy(dom)
        err("Device creation failed for domain %s" % dom)

    if not opts.vals.paused:
        try:
            server.xend.domain.unpause(dom)
        except:
            server.xend.domain.destroy(dom)
            err("Failed to unpause domain %s" % dom)
    opts.info("Started domain %s" % (dom))
    return int(sxp.child_value(dominfo, 'domid'))


def get_xauthority():
    xauth = os.getenv("XAUTHORITY")
    if not xauth:
        home = os.getenv("HOME")
        if not home:
            import posix, pwd
            home = pwd.getpwuid(posix.getuid())[5]
        xauth = home + "/.Xauthority"
    return xauth


def parseCommandLine(argv):
    gopts.reset()
    args = gopts.parse(argv)

    if gopts.vals.help or gopts.vals.help_config:
        if gopts.vals.help_config:
            print gopts.val_usage()
        return (None, None)

    if not gopts.vals.display:
        gopts.vals.display = os.getenv("DISPLAY")

    if not gopts.vals.xauthority:
        gopts.vals.xauthority = get_xauthority()

    gopts.is_xml = False

    # Process remaining args as config variables.
    for arg in args:
        if '=' in arg:
            (var, val) = arg.strip().split('=', 1)
            gopts.setvar(var.strip(), val.strip())
    if gopts.vals.config:
        config = gopts.vals.config
    else:
        try:
            gopts.load_defconfig()
            preprocess(gopts.vals)
            if not gopts.getopt('name') and gopts.getopt('defconfig'):
                gopts.setopt('name', os.path.basename(gopts.getopt('defconfig')))
            config = make_config(gopts.vals)
        except XMLFileError, ex:
            XMLFile = ex.getFile()
            gopts.is_xml = True
            config = ex.getFile()

    return (gopts, config)


def check_domain_label(config, verbose):
    """All that we need to check here is that the domain label exists and
       is not null when security is on.  Other error conditions are
       handled when the config file is parsed.
    """
    answer = 0
    default_label = None
    secon = 0
    if security.on():
        default_label = security.ssidref2label(security.NULL_SSIDREF)
        secon = 1

    # get the domain acm_label
    dom_label = None
    dom_name = None
    for x in sxp.children(config):
        if sxp.name(x) == 'security':
            dom_label = sxp.child_value(sxp.name(sxp.child0(x)), 'label')
        if sxp.name(x) == 'name':
            dom_name = sxp.child0(x)

    # sanity check on domain label
    if verbose:
        print "Checking domain:"
    if (not secon) and (not dom_label):
        answer = 1
        if verbose:
            print "   %s: PERMITTED" % (dom_name)
    elif (secon) and (dom_label) and (dom_label != default_label):
        answer = 1
        if verbose:
            print "   %s: PERMITTED" % (dom_name)
    else:
        print "   %s: DENIED" % (dom_name)
        if not secon:
            print "   --> Security off, but domain labeled"
        else:
            print "   --> Domain not labeled"
        answer = 0

    return answer

def config_security_check(config, verbose):
    """Checks each resource listed in the config to see if the active
       policy will permit creation of a new domain using the config.
       Returns 1 if the config passes all tests, otherwise 0.
    """
    answer = 1

    # get the domain acm_label
    domain_label = None
    domain_policy = None
    for x in sxp.children(config):
        if sxp.name(x) == 'security':
            domain_label = sxp.child_value(sxp.name(sxp.child0(x)), 'label')
            domain_policy = sxp.child_value(sxp.name(sxp.child0(x)), 'policy')

    # if no domain label, use default
    if not domain_label and security.on():
        try:
            domain_label = security.ssidref2label(security.NULL_SSIDREF)
        except:
            import traceback
            traceback.print_exc(limit=1)
            return 0
        domain_policy = 'NULL'
    elif not domain_label:
        domain_label = ""
        domain_policy = 'NULL'

    if verbose:
        print "Checking resources:"

    # build a list of all resources in the config file
    resources = []
    for x in sxp.children(config):
        if sxp.name(x) == 'device':
            if sxp.name(sxp.child0(x)) == 'vbd':
                resources.append(sxp.child_value(sxp.child0(x), 'uname'))

    # perform a security check on each resource
    for resource in resources:
        try:
            security.res_security_check(resource, domain_label)
            if verbose:
                print "   %s: PERMITTED" % (resource)

        except security.ACMError:
            print "   %s: DENIED" % (resource)
            (res_label, res_policy) = security.get_res_label(resource)
            if not res_label:
                res_label = ""
            print "   --> res: %s (%s)" % (str(res_label),
                                           str(res_policy))
            print "   --> dom: %s (%s)" % (str(domain_label),
                                           str(domain_policy))

            answer = 0

    return answer

def create_security_check(config):
    passed = 0
    try:
        if check_domain_label(config, verbose=0):
            if config_security_check(config, verbose=0):
                passed = 1
        else:
            print "Checking resources: (skipped)"
    except security.ACMError:
        sys.exit(-1)

    return passed
  
def help():
    return str(gopts)

def main(argv):
    is_xml = False
    
    try:
        (opts, config) = parseCommandLine(argv)
    except StandardError, ex:
        err(str(ex))

    if not opts:
        return

    if not opts.is_xml:
        if type(config) == str:
            try:
                config = sxp.parse(file(config))[0]
            except IOError, exn:
                raise OptionError("Cannot read file %s: %s" % (config, exn[1]))
        
        if serverType == SERVER_XEN_API:
            from xen.xm.xenapi_create import sxp2xml
            sxp2xml_inst = sxp2xml()
            doc = sxp2xml_inst.convert_sxp_to_xml(config, transient=True)

        if opts.vals.dryrun and not opts.is_xml:
            SXPPrettyPrint.prettyprint(config)

        if opts.vals.xmldryrun and serverType == SERVER_XEN_API:
            from xml.dom.ext import PrettyPrint as XMLPrettyPrint
            XMLPrettyPrint(doc)

    if opts.vals.dryrun or opts.vals.xmldryrun:
        return                                               

    if opts.vals.console_autoconnect:
        do_console(sxp.child_value(config, 'name', -1))
    
    if serverType == SERVER_XEN_API:        
        from xen.xm.xenapi_create import xenapi_create
        xenapi_create_inst = xenapi_create()
        if opts.is_xml:
            vm_refs = xenapi_create_inst.create(filename = config,
                                                skipdtd = opts.vals.skipdtd)
        else:
            vm_refs = xenapi_create_inst.create(document = doc,
                                                skipdtd = opts.vals.skipdtd)

        map(lambda vm_ref: server.xenapi.VM.start(vm_ref, 0), vm_refs)
    elif not opts.is_xml:
        if not create_security_check(config):
            raise security.ACMError(
                'Security Configuration prevents domain from starting')
        dom = make_domain(opts, config)
        
def do_console(domain_name):
    cpid = os.fork() 
    if cpid != 0:
        for i in range(10):
            # Catch failure of the create process 
            time.sleep(1)
            (p, rv) = os.waitpid(cpid, os.WNOHANG)
            if os.WIFEXITED(rv):
                if os.WEXITSTATUS(rv) != 0:
                    sys.exit(os.WEXITSTATUS(rv))
            try:
                # Acquire the console of the created dom
                if serverType == SERVER_XEN_API:
                    domid = server.xenapi.VM.get_domid(
                               get_single_vm(domain_name))
                else:
                    dom = server.xend.domain(domain_name)
                    domid = int(sxp.child_value(dom, 'domid', '-1'))
                console.execConsole(domid)
            except:
                pass
        print("Could not start console\n");
        sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
