#============================================================================UTO
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
import xen.xend.XendClient
from xen.xend.XendBootloader import bootloader
from xen.xend.XendConstants import *
from xen.xend.server.DevConstants import xenbusState
from xen.util import blkif
from xen.util import vscsi_util
import xen.util.xsm.xsm as security
from xen.xm.main import serverType, SERVER_XEN_API, get_single_vm
from xen.util import utils, auxbin
from xen.util.pci import dev_dict_to_sxp, \
                         parse_pci_name_extended, PciDeviceParseError

from xen.xm.opts import *

from main import server
from main import domain_name_to_domid
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
          fn=set_value, default='.:' + auxbin.xen_configdir(),
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

gopts.opt('vncviewer',
          fn=set_true, default=0,
          use="Connect to the VNC display after the domain is created.")

gopts.opt('vncviewer-autopass',
          fn=set_true, default=0,
          use="Pass VNC password to viewer via stdin and -autopass.")

gopts.var('vncpasswd', val='NAME',
          fn=set_value, default=None,
          use="Password for VNC console on HVM domain.")

gopts.var('vncviewer', val='no|yes',
          fn=set_bool, default=None,
           use="Spawn a vncviewer listening for a vnc server in the domain.\n"
           "The address of the vncviewer is passed to the domain on the "
           "kernel command line using 'VNC_SERVER=<host>:<port>'. The port "
           "used by vnc is 5500 + DISPLAY. A display value with a free port "
           "is chosen if possible.\nOnly valid when vnc=1.\nDEPRECATED")

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

gopts.var('loader', val='FILE',
          fn=set_value, default='',
          use="Path to HVM firmware.")

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
          fn=set_int, default=0,
          use="Set RTC offset.")

gopts.var('pae', val='PAE',
          fn=set_int, default=1,
          use="Disable or enable PAE of HVM domain.")

gopts.var('hpet', val='HPET',
          fn=set_int, default=0,
          use="Enable virtual high-precision event timer.")

gopts.var('timer_mode', val='TIMER_MODE',
          fn=set_int, default=1,
          use="""Timer mode (0=delay virtual time when ticks are missed;
          1=virtual time is always wallclock time.""")

gopts.var('tsc_mode', val='TSC_MODE',
          fn=set_int, default=0,
          use="""TSC mode (0=default, 1=always emulate, 2=never emulate, 3=pvrdtscp).""")

gopts.var('nomigrate', val='NOMIGRATE',
          fn=set_int, default=0,
          use="""migratability (0=migration enabled, 1=migration disabled).""")

gopts.var('vpt_align', val='VPT_ALIGN',
          fn=set_int, default=1,
          use="Enable aligning all periodic vpt to reduce timer interrupts.")

gopts.var('viridian', val='VIRIDIAN',
          fn=set_int, default=0,
          use="""Expose Viridian interface to x86 HVM guest?
          (Default is 0).""")

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

gopts.var('vhpt', val='VHPT',
          fn=set_int, default=0,
          use="Log2 of domain VHPT size for IA64.")

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

gopts.var('on_crash', val='destroy|restart|preserve|rename-restart|coredump-destroy|coredump-restart',
          fn=set_value, default=None,
          use="""Behaviour when a domain exits with reason 'crash'.
          - destroy:          the domain is cleaned up as normal;
          - restart:          a new domain is started in place of the old one;
          - preserve:         no clean-up is done until the domain is manually
                              destroyed (using xm destroy, for example);
          - rename-restart:   the old domain is not cleaned up, but is
                              renamed and a new domain started in its place.
          - coredump-destroy: dump the domain's core, followed by destroy
          - coredump-restart: dump the domain's core, followed by restart
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

gopts.var('pci', val='BUS:DEV.FUNC[@VSLOT][,msitranslate=0|1][,power_mgmt=0|1]',
          fn=append_value, default=[],
          use="""Add a PCI device to a domain, using given params (in hex).
          For example 'pci=c0:02.1'.
          If VSLOT is supplied the device will be inserted into that
          virtual slot in the guest, else a free slot is selected.
          If msitranslate is set, MSI-INTx translation is enabled if possible.
          Guest that doesn't support MSI will get IO-APIC type IRQs
          translated from physical MSI, HVM only. Default is 1.
          The option may be repeated to add more than one pci device.
          If power_mgmt is set, the guest OS will be able to program the power
          states D0-D3hot of the device, HVM only. Default=0.""")

gopts.var('vscsi', val='PDEV,VDEV[,DOM]',
          fn=append_value, default=[],
          use="""Add a SCSI device to a domain. The physical device is PDEV,
          which is exported to the domain as VDEV(X:X:X:X).""")

gopts.var('vusb', val="usbver=USBVER,numports=NUMPORTS," + \
          "port_1=PORT1,port_2=PORT2,port_3=PORT3,port_4=PORT4" + \
          "port_5=PORT5,port_6=PORT6,port_7=PORT7,port_8=PORT8" + \
          "port_9=PORT9,port_10=PORT10,port_11=PORT11,port_12=PORT12" + \
          "port_13=PORT13,port_14=PORT14,port_15=PORT15,port_16=PORT16",
          fn=append_value, default=[],
          use="""Add a Virtual USB Host Controller to a domain.
          The USB Spec Version is usbver (1|2, default: 2).
          usbver=1 means USB1.1, usbver=2 mens USB2.0.
          The number of root ports is numports (1 to 16, default: 8).
          This option may be repeated to add more than one host controller.""")

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

gopts.var('vfb', val="vnc=1,sdl=1,vncunused=1,vncdisplay=N,vnclisten=ADDR,display=DISPLAY,xauthority=XAUTHORITY,vncpasswd=PASSWORD,opengl=1,keymap=FILE,serial=FILE,monitor=FILE",
          fn=append_value, default=[],
          use="""Make the domain a framebuffer backend.
          Both sdl=1 and vnc=1 can be enabled at the same time.
          For vnc=1, connect an external vncviewer.  The server will listen
          on ADDR (default 127.0.0.1) on port N+5900.  N defaults to the
          domain id.  If vncunused=1, the server will try to find an arbitrary
          unused port above 5900.  vncpasswd overrides the XenD configured
          default password.
          For sdl=1, a viewer will be started automatically using the
          given DISPLAY and XAUTHORITY, which default to the current user's
          ones.  OpenGL will be used by default unless opengl is set to 0.
          keymap overrides the XendD configured default layout file.
          Serial adds a second serial support to qemu.
          Monitor adds a backend for the stubdom monitor.""")

gopts.var('vif', val="type=TYPE,mac=MAC,bridge=BRIDGE,ip=IPADDR,script=SCRIPT," + \
          "backend=DOM,vifname=NAME,rate=RATE,model=MODEL,accel=ACCEL",
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
          If rate is not specified the default rate is used.
          If model is not specified the default model is used.
          If accel is not specified an accelerator plugin module is not used.
          This option may be repeated to add more than one vif.
          Specifying vifs will increase the number of interfaces as needed.""")

gopts.var('vif2', val="front_mac=MAC,back_mac=MAC,backend=DOM,pdev=PDEV,max_bypasses=N,bridge=BRIDGE,filter_mac=<0|1>,front_filter_mac=<0|1>",
          fn=append_value, default=[],
          use="""Add a netchannel2 network interface using given front
          and backend MAC addresses.  Randomly generated
          addresses will be used if either address is missing.""")

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
          fn=set_value, default=None,
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

gopts.var('description', val='NAME',
          fn=set_value, default='',
          use="Description of a domain")

gopts.var('guest_os_type', val='NAME',
          fn=set_value, default='default',
          use="Guest OS type running in HVM")

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

gopts.var('videoram', val='MEMORY',
          fn=set_int, default=4,
          use="""Maximum amount of videoram a guest can allocate
          for frame buffer.""")

gopts.var('sdl', val='',
          fn=set_value, default=None,
          use="""Should the device model use SDL?""")

gopts.var('gfx_passthru', val='',
          fn=set_value, default=None,
          use="""Passthrough graphics card?""")

gopts.var('opengl', val='',
          fn=set_value, default=None,
          use="""Enable\Disable OpenGL""")

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

gopts.var('on_xend_stop', val='ignore|shutdown|suspend',
          fn=set_value, default="ignore",
          use="""Behaviour when Xend stops:
          - ignore:         Domain continues to run;
          - shutdown:       Domain is shutdown;
          - suspend:        Domain is suspended;
          """)

gopts.var('target', val='TARGET',
          fn=set_int, default=0,
          use="Set domain target.")

gopts.var('hap', val='HAP',
          fn=set_int, default=1,
          use="""Hap status (0=hap is disabled;
          1=hap is enabled.""")

gopts.var('s3_integrity', val='TBOOT_MEMORY_PROTECT',
          fn=set_int, default=1,
          use="""Should domain memory integrity be verified during S3?
          (0=protection is disabled; 1=protection is enabled.""")

gopts.var('oos', val='OOS',
          fn=set_int, default=1,
          use="""Should out-of-sync shadow page tabled be enabled?
          (0=OOS is disabled; 1=OOS is enabled.""")

gopts.var('cpuid', val="IN[,SIN]:eax=EAX,ebx=EBX,ecx=ECX,edx=EDX",
          fn=append_value, default=[],
          use="""Cpuid description.""")

gopts.var('cpuid_check', val="IN[,SIN]:eax=EAX,ebx=EBX,ecx=ECX,edx=EDX",
          fn=append_value, default=[],
          use="""Cpuid check description.""")

gopts.var('machine_address_size', val='BITS',
          fn=set_int, default=None,
          use="""Maximum machine address size""")

gopts.var('suppress_spurious_page_faults', val='yes|no',
          fn=set_bool, default=None,
          use="""Do not inject spurious page faults into this guest""")

gopts.var('pci_msitranslate', val='TRANSLATE',
          fn=set_int, default=1,
          use="""Global PCI MSI-INTx translation flag (0=disable;
          1=enable.""")

gopts.var('pci_power_mgmt', val='POWERMGMT',
          fn=set_int, default=0,
          use="""Global PCI Power Management flag (0=disable;1=enable).""")

gopts.var('xen_platform_pci', val='0|1',
           fn=set_int, default=1,
           use="Is xen_platform_pci used?")

gopts.var('superpages', val='0|1',
           fn=set_int, default=0,
           use="Create domain with superpages")

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
        if os.path.dirname(vals.kernel) != "" and os.path.exists(vals.kernel):
            config_image.append([ 'kernel', vals.kernel ])
        elif vals.kernel == 'hvmloader':
            # Keep hvmloader w/o a path and let xend find it.
            # This allows guest migration to a Dom0 having different
            # xen install pathes.
            config_image.append([ 'kernel', vals.kernel ])
        elif os.path.exists(os.path.abspath(vals.kernel)):
            # Keep old behaviour, if path is valid.
            config_image.append([ 'kernel', os.path.abspath(vals.kernel) ])
        else:
            raise ValueError('Cannot find kernel "%s"' % vals.kernel)
    if vals.ramdisk:
        if os.path.dirname(vals.ramdisk) != "" and os.path.exists(vals.ramdisk):
            config_image.append([ 'ramdisk', vals.ramdisk ])
        elif os.path.exists(os.path.abspath(vals.ramdisk)):
            # Keep old behaviour, if path is valid.
            config_image.append([ 'ramdisk', os.path.abspath(vals.ramdisk) ])
        else:
            raise ValueError('Cannot find ramdisk "%s"' % vals.ramdisk)
    if vals.loader:
        if os.path.dirname(vals.loader) != "" and os.path.exists(vals.loader):
            config_image.append([ 'loader', vals.loader ])
        elif vals.loader == 'hvmloader':
            # Keep hvmloader w/o a path and let xend find it.
            # This allows guest migration to a Dom0 having different
            # xen install pathes.
            config_image.append([ 'loader', vals.loader ])
        elif os.path.exists(os.path.abspath(vals.loader)):
            # Keep old behaviour, if path is valid.
            config_image.append([ 'loader', os.path.abspath(vals.loader) ])
        else:
            raise ValueError('Cannot find loader "%s"' % vals.loader)
    if vals.cmdline_ip:
        cmdline_ip = strip('ip=', vals.cmdline_ip)
        config_image.append(['ip', cmdline_ip])
    if vals.root:
        cmdline_root = strip('root=', vals.root)
        config_image.append(['root', cmdline_root])
    if vals.videoram:
        config_image.append(['videoram', vals.videoram])
    if vals.extra:
        config_image.append(['args', vals.extra])
    if vals.superpages:
        config_image.append(['superpages', vals.superpages])

    if vals.builder == 'hvm':
        configure_hvm(config_image, vals) 

    if vals.vhpt != 0:
        config_image.append(['vhpt', vals.vhpt])

    if vals.machine_address_size:
        config_image.append(['machine_address_size', vals.machine_address_size])

    if vals.suppress_spurious_page_faults:
        config_image.append(['suppress_spurious_page_faults', vals.suppress_spurious_page_faults])

    if vals.tsc_mode is not None:
        config_image.append(['tsc_mode', vals.tsc_mode])

    if vals.nomigrate is not None:
        config_image.append(['nomigrate', vals.nomigrate])

    return config_image
    
def configure_disks(config_devs, vals):
    """Create the config for disks (virtual block devices).
    """
    for (uname, dev, mode, backend, protocol) in vals.disk:
        if uname.startswith('tap:'):
            cls = 'tap2'
        else:
            cls = 'vbd'

        config_vbd = [cls,
                      ['uname', uname],
                      ['dev', dev ],
                      ['mode', mode ] ]
        if backend:
            config_vbd.append(['backend', backend])
        if protocol:
            config_vbd.append(['protocol', protocol])
        config_devs.append(['device', config_vbd])

def configure_pci(config_devs, vals):
    """Create the config for pci devices.
    """
    config_pci = []
    for pci_tuple in vals.pci:
        pci_dev = pci_tuple_to_dict(pci_tuple)
        config_pci.append(dev_dict_to_sxp(pci_dev))

    if len(config_pci)>0:
        config_pci.insert(0, 'pci')
        config_devs.append(['device', config_pci])

def configure_vscsis(config_devs, vals):
    """Create the config for vscsis (virtual scsi devices).
    """

    def get_devid(hctl):
        return int(hctl.split(':')[0])

    if len(vals.vscsi) == 0:
        return 0

    config_scsi = {}
    pHCTL_list = []
    vHCTL_list = []

    scsi_devices = vscsi_util.vscsi_get_scsidevices()
    for (p_dev, v_dev, backend) in vals.vscsi:
        (p_hctl, devname) = \
            vscsi_util.vscsi_get_hctl_and_devname_by(p_dev, scsi_devices)

        if p_hctl == None:
            raise ValueError('Cannot find device "%s"' % p_dev)

        feature_host = 0
        if v_dev == 'host':
            feature_host = 1
            scsi_info = []
            devid = get_devid(p_hctl)
            for (pHCTL, devname, _, _) in scsi_devices:
                if get_devid(pHCTL) == devid:
                    scsi_info.append([devid, pHCTL, devname, pHCTL])
        else:
            scsi_info = [[get_devid(v_dev), p_hctl, devname, v_dev]]

        devid_key = scsi_info[0][0]
        try:
            config = config_scsi[devid_key]
        except KeyError:
            config = {'feature-host': feature_host, 'backend': backend, 'devs': []}

        devs = config['devs']
        for (devid, pHCTL, devname, vHCTL) in scsi_info:
            if pHCTL in pHCTL_list:
                raise ValueError('The physical device "%s" is already defined' % pHCTL)
            if vHCTL in vHCTL_list:
                raise ValueError('The virtual device "%s" is already defined' % vHCTL)
            pHCTL_list.append(pHCTL)
            vHCTL_list.append(vHCTL)
            devs.append(['dev', \
                         ['state', xenbusState['Initialising']], \
                         ['devid', devid], \
                         ['p-dev', pHCTL], \
                         ['p-devname', devname], \
                         ['v-dev', vHCTL] ])

        if config['feature-host'] != feature_host:
            raise ValueError('The physical device "%s" cannot define '
                             'because mode is different' % scsi_info[0][1])
        if config['backend'] != backend:
            raise ValueError('The physical device "%s" cannot define '
                             'because backend is different' % scsi_info[0][1])

        config['devs'] = devs
        config_scsi[devid_key] = config

    for config in config_scsi.values():
        device = ['vscsi', ['feature-host', config['feature-host']]]
        for dev in config['devs']:
            device.append(dev)
        if config['backend']:
            device.append(['backend', config['backend']])
        config_devs.append(['device', device])

def configure_vusbs(config_devs, vals):
    """Create the config for virtual usb host controllers.
    """
    for f in vals.vusb:
        d = comma_sep_kv_to_dict(f)
        config = ['vusb']

        usbver = 2
        if d.has_key('usbver'):
            usbver = int(d['usbver'])
        if usbver == 1 or usbver == 2:
            config.append(['usb-ver', str(usbver)])
        else:
            err('Invalid vusb option: ' + 'usbver')

        numports = 8
        if d.has_key('numports'):
            numports = d['numports']
        if int(numports) < 1 or int(numports) > 16:
            err('Invalid vusb option: ' + 'numports')
        config.append(['num-ports', str(numports)])

        port_config = []
        for i in range(1, int(numports) + 1):
            if d.has_key('port_%i' % i):
                port_config.append(['%i' % i, str(d['port_%i' % i])])
            else:
                port_config.append(['%i' % i, ""])
        port_config.insert(0, 'port')
        config.append(port_config)
        config_devs.append(['device', config])        

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

def configure_vfbs(config_devs, vals):
    for f in vals.vfb:
        d = comma_sep_kv_to_dict(f)
        config = ['vfb']
        #handle the legacy case
        if d.has_key("type"):
            d[d['type']] = '1'
            del d['type']
        for (k,v) in d.iteritems():
            if not k in [ 'vnclisten', 'vncunused', 'vncdisplay', 'display',
                          'videoram', 'xauthority', 'sdl', 'vnc', 'vncpasswd',
                          'opengl', 'keymap', 'serial', 'monitor' ]:
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

        security_label = ['security', [ config_access_control ] ]
        config.append(security_label)
    elif num > 1:
        err("VM config error: Multiple access_control definitions!")

def configure_mem_prot(config_image, vals):
    """Create the config for S3 memory integrity verification under tboot.
    """
    config_image.append(['s3_integrity', vals.s3_integrity])

def configure_vtpm(config_devs, vals):
    """Create the config for virtual TPM interfaces.
    """
    vtpm = vals.vtpm
    if len(vtpm) > 0:
        d = vtpm[0]
        instance = d.get('instance')
        uuid = d.get('uuid')
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
            config_vtpm.append(['type', typ])
        if uuid:
            config_vtpm.append(['uuid', uuid])
        config_devs.append(['device', config_vtpm])


def configure_vifs(config_devs, vals):
    """Create the config for virtual network interfaces.
    """

    vifs = vals.vif
    vifs_n = len(vifs)
    vifs2 = vals.vif2
    vifs2_n = len(vifs2)

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
                         'vifname', 'rate', 'model', 'accel',
                         'policy', 'label']:
                err('Invalid vif option: ' + k)

            config_vif.append([k, d[k]])

        map(f, d.keys())
        config_devs.append(['device', config_vif])

    for c in vifs2:
        d = comma_sep_kv_to_dict(c)
        config_vif = ['vif2']

        for k in d.keys():
            if k not in ['front_mac', 'back_mac', 'backend', 'trusted',
                         'back_trusted', 'front_filter_mac', 'filter_mac',
                         'bridge', 'pdev', 'max_bypasses' ]:
                err('Invalid vif2 option: ' + k)
            config_vif.append([k, d[k]])
        config_devs.append(['device', config_vif])


def configure_hvm(config_image, vals):
    """Create the config for HVM devices.
    """
    args = [ 'acpi', 'apic',
             'boot',
             'cpuid', 'cpuid_check',
             'device_model', 'display',
             'fda', 'fdb',
             'gfx_passthru', 'guest_os_type',
             'hap', 'hpet',
             'isa',
             'keymap',
             'localtime',
             'monitor',
             'nographic',
             'opengl', 'oos',
             'pae', 'pci', 'pci_msitranslate', 'pci_power_mgmt',
             'rtc_timeoffset',
             'sdl', 'serial', 'soundhw', 'stdvga',
             'timer_mode',
             'usb', 'usbdevice',
             'vcpus', 'vnc', 'vncconsole', 'vncdisplay', 'vnclisten',
             'vncunused', 'viridian', 'vpt_align',
             'xauthority', 'xen_extended_power_mgmt', 'xen_platform_pci' ]

    for a in args:
        if a in vals.__dict__ and vals.__dict__[a] is not None:
            config_image.append([a, vals.__dict__[a]])
    if vals.vncpasswd is not None:
        config_image.append(['vncpasswd', vals.vncpasswd])


def make_config(vals):
    """Create the domain configuration.
    """
    
    config = ['vm']

    def vcpu_conf():
        maxvcpus = False
        vcpus = False
        if hasattr(vals, 'maxvcpus'):
            maxvcpus = getattr(vals, 'maxvcpus')
        if hasattr(vals, 'vcpus'):
            vcpus = getattr(vals, 'vcpus')

        if maxvcpus and not vcpus:
            config.append(['vcpus', maxvcpus])
        if maxvcpus and vcpus:
           config.append(['vcpu_avail', (1 << vcpus) - 1])
           config.append(['vcpus', maxvcpus])

        # For case we don't have maxvcpus set but we have vcpus we preserve
        # old behaviour
        if not maxvcpus and vcpus:
            config.append(['vcpus', vcpus])

    def add_conf(n):
        if hasattr(vals, n):
            v = getattr(vals, n)
            if v:
                config.append([n, v])

    map(add_conf, ['name', 'memory', 'maxmem', 'shadow_memory',
                   'restart', 'on_poweroff',  'tsc_mode', 'nomigrate',
                   'on_reboot', 'on_crash', 'features', 'on_xend_start',
                   'on_xend_stop', 'target', 'cpuid', 'cpuid_check',
                   'machine_address_size', 'suppress_spurious_page_faults',
                   'description'])

    vcpu_conf()
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
    if vals.oos:
        config.append(['oos', vals.oos])

    config_image = configure_image(vals)
    if vals.bootloader:
        if vals.bootloader == "pygrub":
            vals.bootloader = auxbin.pathTo(vals.bootloader)

        config.append(['bootloader', vals.bootloader])
        if vals.bootargs:
            config.append(['bootloader_args', vals.bootargs])
        else:
            if vals.console_autoconnect:
                config.append(['bootloader_args', ''])
            else:
                config.append(['bootloader_args', '-q'])
    config.append(['image', config_image])
    configure_mem_prot(config, vals);

    config_devs = []
    configure_disks(config_devs, vals)
    configure_pci(config_devs, vals)
    configure_vscsis(config_devs, vals)
    configure_vusbs(config_devs, vals)
    configure_ioports(config_devs, vals)
    configure_irq(config_devs, vals)
    configure_vifs(config_devs, vals)
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
            d.append(None)
        elif n == 4:
            d.append(None)
        elif n == 5:
            pass
        else:
            err('Invalid disk specifier: ' + v)
        disk.append(d)
    vals.disk = disk

def preprocess_cpuid(vals, attr_name):
    if not vals.cpuid: return
    cpuid = {} 
    for cpuid_input in getattr(vals, attr_name):
        input_re = "(0x)?[0-9A-Fa-f]+(,(0x)?[0-9A-Fa-f]+)?"
        cpuid_match = re.match(r'(?P<input>%s):(?P<regs>.*)' % \
                               input_re, cpuid_input)
        if cpuid_match != None:
            res_cpuid = cpuid_match.groupdict()
            input = res_cpuid['input']
            regs = res_cpuid['regs'].split(',')
            cpuid[input]= {} # New input
            for reg in regs:
                reg_match = re.match(r"(?P<reg>eax|ebx|ecx|edx)=(?P<val>.*)", reg)
                if reg_match == None:
                    err("cpuid's syntax is (eax|ebx|ecx|edx)=value")
                res = reg_match.groupdict()
                if (res['val'][:2] != '0x' and len(res['val']) != 32):
                    err("cpuid: We should specify all the bits " \
                        "of the register %s for input %s\n"
                        % (res['reg'], input) )
                cpuid[input][res['reg']] = res['val'] # new register
            setattr(vals, attr_name, cpuid)

def pci_dict_to_tuple(dev):
    return (dev['domain'], dev['bus'], dev['slot'], dev['func'],
            dev['vdevfn'], dev.get('opts', []), dev['key'])

def pci_tuple_to_dict((domain, bus, slot, func, vdevfn, opts, key)):
    pci_dev = { 'domain': domain,
                'bus':    bus,
                'slot':   slot,
                'func':   func,
                'vdevfn': vdevfn,
                'key':    key}
    if len(opts) > 0:
        pci_dev['opts'] = opts
    return pci_dev

def preprocess_pci(vals):
    if not vals.pci:
        return
    try:
        vals.pci = map(pci_dict_to_tuple, reduce(lambda x, y: x + y,
                       map(parse_pci_name_extended, vals.pci)))
    except PciDeviceParseError, ex:
        err(str(ex))

def preprocess_vscsi(vals):
    if not vals.vscsi: return
    scsi = []
    for scsi_str in vals.vscsi:
        d = [tmp.strip() for tmp in scsi_str.split(',')]
        n = len(d)
        if n == 2:
            tmp = d[1].split(':')
            if d[1] != 'host' and len(tmp) != 4:
                err('vscsi syntax error "%s"' % d[1])
            else:
                d.append(None)
        elif n == 3:
            pass
        else:
            err('vscsi syntax error "%s"' % scsi_str)
        scsi.append(d)
    vals.vscsi = scsi

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
        
def preprocess_irq(vals):
    if not vals.irq: return
    irq = []
    for v in vals.irq:
        d = repr(v)
        irq.append(d)
    vals.irq = irq

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
            if k not in ['backend', 'instance', 'uuid']:
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
        acc_re = 'policy=(?P<policy>.*),label=(?P<label>.*)'
        acc_match = re.match(acc_re,access_control)
        if acc_match == None:
            err('Invalid access_control specifier: ' + access_control)
        d = acc_match.groupdict();
        access_controls.append(d)
        vals.access_control = access_controls
    elif num > 1:
        err('Multiple access_control definitions.')

def preprocess_ip(vals):
    if vals.ip or vals.dhcp != 'off':
        dummy_nfs_server = '127.0.255.255'
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

def preprocess(vals):
    preprocess_disk(vals)
    preprocess_pci(vals)
    preprocess_vscsi(vals)
    preprocess_ioports(vals)
    preprocess_ip(vals)
    preprocess_irq(vals)
    preprocess_nfs(vals)
    preprocess_vtpm(vals)
    preprocess_access_control(vals)
    preprocess_cpuid(vals, 'cpuid')
    preprocess_cpuid(vals, 'cpuid_check')


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
        if ex.faultCode == xen.xend.XendClient.ERROR_INVALID_DOMAIN:
            err("the domain '%s' does not exist." % ex.faultString)
        else:
            err("%s" % ex.faultString)

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
    domid = int(sxp.child_value(dominfo, 'domid'))
    opts.info("Started domain %s (id=%d)" % (dom, domid))
    return domid


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
        dom = make_domain(opts, config)
        
    if opts.vals.vncconsole:
        domid = domain_name_to_domid(sxp.child_value(config, 'name', -1))
        vncviewer_autopass = getattr(opts.vals,'vncviewer-autopass', False)
        console.runVncViewer(domid, vncviewer_autopass, True)
    
def do_console(domain_name):
    cpid = os.fork() 
    if cpid != 0:
        for i in range(10):
            # Catch failure of the create process 
            time.sleep(1)
            try:
                (p, rv) = os.waitpid(cpid, os.WNOHANG)
            except OSError:
                # Domain has started cleanly and then exiting,
                # the child process used to do this has detached
                print("Domain has already finished");
                break
            if os.WIFEXITED(rv):
                if os.WEXITSTATUS(rv) != 0:
                    sys.exit(os.WEXITSTATUS(rv))
            try:
                domid = domain_name_to_domid(domain_name)
                console.execConsole(domid)
            except:
                pass
        print("Could not start console\n");
        sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
