#!/usr/bin/python
# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Representation of a single domain.
Includes support for domain construction, using
open-ended configurations.

Author: Mike Wray <mike.wray@hpl.hp.com>

"""

import string
import re
import sys
import os

from twisted.internet import defer

import Xc; xc = Xc.new()

import xenctl.ip

import sxp

import XendConsole
xendConsole = XendConsole.instance()

import server.SrvConsoleServer
xend = server.SrvConsoleServer.instance()

SIF_BLK_BE_DOMAIN = (1<<4)
SIF_NET_BE_DOMAIN = (1<<5)

def readlines(fd):
    """Version of readlines safe against EINTR.
    """
    import errno
    
    lines = []
    while 1:
        try:
            line = fd.readline()
        except IOError, ex:
            if ex.errno == errno.EINTR:
                continue
            else:
                raise
        if line == '': break
        lines.append(line)
    return lines

class VmError(ValueError):
    """Vm construction error."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class XendDomainInfo:
    """Virtual machine object."""

    def __init__(self, config, dom, name, memory, image=None, console=None, info=None):
        """Construct a virtual machine object.

        config   configuration
        dom      domain id
        name     name
        memory   memory size (in MB)
        image    image object
        """
        #todo: add info: runtime, state, ...
        self.config = config
        self.id = str(dom)
        self.dom = dom
        self.name = name
        self.memory = memory
        self.image = image
        self.console = console
        self.devices = {}
        self.configs = []
        self.info = info
        self.ipaddrs = []
        self.block_controller = 0
        self.net_controller = 0

        #todo: state: running, suspended
        self.state = 'running'
        #todo: set to migrate info if migrating
        self.migrate = None

    def update(self, info):
        """Update with  info from xc.domain_getinfo().
        """
        self.info = info

    def __str__(self):
        s = "domain"
        s += " id=" + self.id
        s += " name=" + self.name
        s += " memory=" + str(self.memory)
        if self.console:
            s += " console=" + self.console.id
        if self.image:
            s += " image=" + self.image
        s += ""
        return s

    __repr__ = __str__

    def sxpr(self):
        sxpr = ['domain',
                ['id', self.id],
                ['name', self.name],
                ['memory', self.memory] ]
        if self.info:
            run   = (self.info['running'] and 'R') or 'r'
            block = (self.info['blocked'] and 'B') or 'b'
            stop  = (self.info['paused']  and 'P') or 'p'
            susp  = (self.info['shutdown'] and 'S') or 's'
            crash = (self.info['crashed'] and 'C') or 'c'
            state = run + block + stop + susp + crash
            sxpr.append(['state', state])
            if self.info['shutdown']:
                reasons = ["poweroff", "reboot", "suspend"]
                reason = reasons[info['shutdown_reason']]
                sxpr.append(['shutdown_reason', reason])
            sxpr.append(['cpu', self.info['cpu']])
            sxpr.append(['cpu_time', self.info['cpu_time']/1e9])
        if self.console:
            sxpr.append(self.console.sxpr())
        if self.config:
            sxpr.append(['config', self.config])
        return sxpr

    def add_device(self, type, dev):
        """Add a device to a virtual machine.

        dev      device to add
        """
        dl = self.devices.get(type, [])
        dl.append(dev)
        self.devices[type] = dl

    def get_devices(self, type):
        val = self.devices.get(type, [])
        print 'get_devices', type; sxp.show(val); print
        return val

    def get_device_by_id(self, type, id):
        """Get the device with the given id.

        id       device id

        returns  device or None
        """
        return sxp.child_with_id(self.get_devices(type), id)

    def get_device_by_index(self, type, idx):
        """Get the device with the given index.

        idx       device index

        returns  device or None
        """
        dl = self.get_devices(type)
        if 0 <= idx < len(dl):
            return dl[idx]
        else:
            return None

    def add_config(self, val):
        """Add configuration data to a virtual machine.

        val      data to add
        """
        self.configs.append(val)

    def destroy(self):
        if self.dom <= 0:
            return 0
        return xc.domain_destroy(dom=self.dom)

    def show(self):
        """Print virtual machine info.
        """
        print "[VM dom=%d name=%s memory=%d" % (self.dom, self.name, self.memory)
        print "image:"
        sxp.show(self.image)
        print
        for dl in self.devices:
            for dev in dl:
                print "device:"
                sxp.show(dev)
                print
        for val in self.configs:
            print "config:"
            sxp.show(val)
            print
        print "]"

def blkdev_name_to_number(name):
    """Take the given textual block-device name (e.g., '/dev/sda1',
    'hda') and return the device number used by the OS. """

    if not re.match( '/dev/', name ):
        name = '/dev/' + name
        
    return os.stat(name).st_rdev

def lookup_raw_partn(partition):
    """Take the given block-device name (e.g., '/dev/sda1', 'hda')
    and return a dictionary { device, start_sector,
    nr_sectors, type }
        device:       Device number of the given partition
        start_sector: Index of first sector of the partition
        nr_sectors:   Number of sectors comprising this partition
        type:         'Disk' or identifying name for partition type
    """

    if not re.match( '/dev/', partition ):
        partition = '/dev/' + partition

    drive = re.split( '[0-9]', partition )[0]

    if drive == partition:
        fd = os.popen( '/sbin/sfdisk -s ' + drive + ' 2>/dev/null' )
        line = readline(fd)
        if line:
            return [ { 'device' : blkdev_name_to_number(drive),
                       'start_sector' : long(0),
                       'nr_sectors' : long(line) * 2,
                       'type' : 'Disk' } ]
        return None

    # determine position on disk
    fd = os.popen( '/sbin/sfdisk -d ' + drive + ' 2>/dev/null' )

    #['/dev/sda3 : start= 16948575, size=16836120, Id=83, bootable\012']
    lines = readlines(fd)
    for line in lines:
        m = re.search( '^' + partition + '\s*: start=\s*([0-9]+), ' +
                       'size=\s*([0-9]+), Id=\s*(\S+).*$', line)
        if m:
            return [ { 'device' : blkdev_name_to_number(drive),
                       'start_sector' : long(m.group(1)),
                       'nr_sectors' : long(m.group(2)),
                       'type' : m.group(3) } ]
    
    return None

def lookup_disk_uname( uname ):
    """Lookup a list of segments for a physical device.
    uname [string]:  name of the device in the format \'phy:dev\' for a physical device
    returns [list of dicts]: list of extents that make up the named device
    """
    ( type, d_name ) = string.split( uname, ':' )

    if type == "phy":
        segments = lookup_raw_partn( d_name )
    else:
        segments = None
    return segments

def make_disk(dom, uname, dev, mode, sharing):
    """Create a virtual disk device for a domain.

    @returns Deferred
    """
    segments = lookup_disk_uname(uname)
    if not segments:
        raise VmError("vbd: Segments not found: uname=%s" % uname)
    if len(segments) > 1:
        raise VmError("vbd: Multi-segment vdisk: uname=%s" % uname)
    segment = segments[0]
    vdev = blkdev_name_to_number(dev)
    ctrl = xend.blkif_create(dom)
    
    def fn(ctrl):
        return xend.blkif_dev_create(dom, vdev, mode, segment)
    ctrl.addCallback(fn)
    return ctrl
        
def make_vif(dom, vif, vmac):
    """Create a virtual network device for a domain.

    
    @returns Deferred
    """
    xend.netif_create(dom)
    d = xend.netif_dev_create(dom, vif, vmac)
    return d

def vif_up(iplist):
    """send an unsolicited ARP reply for all non link-local IP addresses.

    iplist IP addresses
    """

    IP_NONLOCAL_BIND = '/proc/sys/net/ipv4/ip_nonlocal_bind'
    
    def get_ip_nonlocal_bind():
        return int(open(IP_NONLOCAL_BIND, 'r').read()[0])

    def set_ip_nonlocal_bind(v):
        print >> open(IP_NONLOCAL_BIND, 'w'), str(v)

    def link_local(ip):
        return xenctl.ip.check_subnet(ip, '169.254.0.0', '255.255.0.0')

    def arping(ip, gw):
        cmd = '/usr/sbin/arping -A -b -I eth0 -c 1 -s %s %s' % (ip, gw)
        print cmd
        os.system(cmd)
        
    gateway = xenctl.ip.get_current_ipgw() or '255.255.255.255'
    nlb = get_ip_nonlocal_bind()
    if not nlb: set_ip_nonlocal_bind(1)
    try:
        for ip in iplist:
            if not link_local(ip):
                arping(ip, gateway)
    finally:
        if not nlb: set_ip_nonlocal_bind(0)

def xen_domain_create(config, ostype, name, memory, kernel, ramdisk, cmdline, vifs_n):
    """Create a domain. Builds the image but does not configure it.

    config  configuration
    ostype  OS type
    name    domain name
    memory  domain memory (MB)
    kernel  kernel image
    ramdisk kernel ramdisk
    cmdline kernel commandline
    vifs_n  number of network interfaces
    returns vm
    """
    flags = 0
    if not os.path.isfile(kernel):
        raise VmError('Kernel image does not exist: %s' % kernel)
    if ramdisk and not os.path.isfile(ramdisk):
        raise VMError('Kernel ramdisk does not exist: %s' % ramdisk)

    cpu = int(sxp.child_value(config, 'cpu', '-1'))
    print 'xen_domain_create> create ', memory, name, cpu
    dom = xc.domain_create(mem_kb= memory * 1024, name= name, cpu= cpu)
    if dom <= 0:
        raise VmError('Creating domain failed: name=%s memory=%d kernel=%s'
                      % (name, memory, kernel))
    console = xendConsole.console_create(dom)
    buildfn = getattr(xc, '%s_build' % ostype)
    
    print 'xen_domain_create> build ', ostype, dom, kernel, cmdline, ramdisk
    if len(cmdline) >= 256:
        print 'Warning: kernel cmdline too long'
    err = buildfn(dom            = dom,
                  image          = kernel,
                  control_evtchn = console.port2,
                  cmdline        = cmdline,
                  ramdisk        = ramdisk,
                  flags          = flags)
    if err != 0:
        raise VmError('Building domain failed: type=%s dom=%d err=%d'
                      % (ostype, dom, err))
    vm = XendDomainInfo(config, dom, name, memory, kernel, console)
    return vm

config_handlers = {}

def add_config_handler(name, h):
    """Add a handler for a config field.

    name     field name
    h        handler: fn(vm, config, field, index)
    """
    config_handlers[name] = h

def get_config_handler(name):
    """Get a handler for a config field.

    returns handler or None
    """
    return config_handlers.get(name)

"""Table of handlers for virtual machine images.
Indexed by image type.
"""
image_handlers = {}

def add_image_handler(name, h):
    """Add a handler for an image type
    name     image type
    h        handler: fn(config, name, memory, image)
    """
    image_handlers[name] = h

def get_image_handler(name):
    """Get the handler for an image type.
    name     image type

    returns handler or None
    """
    return image_handlers.get(name)

"""Table of handlers for devices.
Indexed by device type.
"""
device_handlers = {}

def add_device_handler(name, h):
    """Add a handler for a device type.

    name      device type
    h         handler: fn(vm, dev)
    """
    device_handlers[name] = h

def get_device_handler(name):
    """Get the handler for a device type.

    name      device type

    returns handler or None
    """
    return device_handlers.get(name)

def vm_create(config):
    """Create a VM from a configuration.
    If a vm has been partially created and there is an error it
    is destroyed.

    config    configuration

    returns Deferred
    raises VmError for invalid configuration
    """
    # todo - add support for scheduling params?
    print 'vm_create>'
    vm = None
    try:
        name = sxp.child_value(config, 'name')
        memory = int(sxp.child_value(config, 'memory', '128'))
        image = sxp.child_value(config, 'image')
        
        image_name = sxp.name(image)
        image_handler = get_image_handler(image_name)
        if image_handler is None:
            raise VmError('unknown image type: ' + image_name)
        vm = image_handler(config, name, memory, image)
        deferred = vm_configure(vm, config)
    except StandardError, ex:
        # Catch errors, cleanup and re-raise.
        if vm:
            vm.destroy()
        raise
    def cbok(x):
        print 'vm_create> cbok', x
        return x
    deferred.addCallback(cbok)
    print 'vm_create<'
    return deferred

def vm_restore(src, config, progress=0):
    """Restore a VM.

    src      saved state to restore
    config   configuration
    progress progress reporting flag
    returns  deferred
    raises   VmError for invalid configuration
    """
    ostype = "linux" #todo set from config
    restorefn = getattr(xc, "%s_restore" % ostype)
    dom = restorefn(state_file=src, progress=progress)
    if dom < 0: return dom
    deferred = dom_configure(dom, config)
    def vifs_cb(val, vm):
        vif_up(vm.ipaddrs)
    deferred.addCallback(vifs_cb, vm)
    return deferred
    
def dom_get(dom):
    domlist = xc.domain_getinfo(dom=dom)
    if domlist and dom == domlist[0]['dom']:
        return domlist[0]
    return None
    
def dom_configure(dom, config):
    """Configure a domain.

    dom    domain id
    config configuration
    returns deferred
    """
    d = dom_get(dom)
    if not d:
        raise VMError("Domain not found: %d" % dom)
    try:
        name = d['name']
        memory = d['memory']/1024
        image = None
        vm = VM(config, dom, name, memory, image)
        deferred = vm_configure(vm, config)
    except StandardError, ex:
        if vm:
            vm.destroy()
        raise
    return deferred

def append_deferred(dlist, v):
    if isinstance(v, defer.Deferred):
        dlist.append(v)

def vm_create_devices(vm, config):
    """Create the devices for a vm.

    vm         virtual machine
    config     configuration

    returns Deferred
    raises VmError for invalid devices
    """
    print '>vm_create_devices'
    dlist = []
    devices = sxp.children(config, 'device')
    index = {}
    for d in devices:
        dev = sxp.child0(d)
        if dev is None:
            raise VmError('invalid device')
        dev_name = sxp.name(dev)
        dev_index = index.get(dev_name, 0)
        dev_handler = get_device_handler(dev_name)
        if dev_handler is None:
            raise VmError('unknown device type: ' + dev_name)
        v = dev_handler(vm, dev, dev_index)
        append_deferred(dlist, v)
        index[dev_name] = dev_index + 1
    deferred = defer.DeferredList(dlist, fireOnOneErrback=1)
    print '<vm_create_devices'
    return deferred

def config_controllers(vm, config):
    for c in sxp.children(config, 'controller'):
        name = sxp.name(c)
        if name == 'block':
            vm.block_controller = 1
            xend.blkif_set_control_domain(vm.dom)
        elif name == 'net':
            vm.net_controller = 1
            xend.netif_set_control_domain(vm.dom)
        else:
            raise VmError('invalid controller type:' + str(name))
    
def vm_configure(vm, config):
    """Configure a vm.

    vm         virtual machine
    config     configuration

    returns Deferred - calls callback with vm
    """
    config_controllers(vm, config)
    if vm.block_controller:
        d = defer.Deferred()
        d.callback(1)
    else:
        d = xend.blkif_create(vm.dom)
    d.addCallback(_vm_configure1, vm, config)
    return d

def _vm_configure1(val, vm, config):
    d = vm_create_devices(vm, config)
    print '_vm_configure1> made devices...'
    def cbok(x):
        print '_vm_configure1> cbok', x
        return x
    d.addCallback(cbok)
    d.addCallback(_vm_configure2, vm, config)
    print '_vm_configure1<'
    return d

def _vm_configure2(val, vm, config):
    print '>callback _vm_configure2...'
    dlist = []
    index = {}
    for field in sxp.children(config):
        field_name = sxp.name(field)
        field_index = index.get(field_name, 0)
        field_handler = get_config_handler(field_name)
        # Ignore unknown fields. Warn?
        if field_handler:
            v = field_handler(vm, config, field, field_index)
            append_deferred(dlist, v)
        index[field_name] = field_index + 1
    d = defer.DeferredList(dlist, fireOnOneErrback=1)
    def cbok(results):
        print '_vm_configure2> cbok', results
        return vm
    def cberr(err):
        print '_vm_configure2> cberr', err
        vm.destroy()
        return err
    d.addCallback(cbok)
    d.addErrback(cberr)
    print '<_vm_configure2'
    return d

def config_devices(config, name):
    """Get a list of the 'device' nodes of a given type from a config.

    config	configuration
    name	device type
    return list of device configs
    """
    devices = []
    for d in sxp.children(config, 'device'):
        dev = sxp.child0(d)
        if dev is None: continue
        if name == sxp.name(dev):
            devices.append(dev)
    return devices
        
def vm_image_linux(config, name, memory, image):
    """Create a VM for a linux image.

    name      vm name
    memory    vm memory
    image     image config

    returns vm
    """
    kernel = sxp.child_value(image, "kernel")
    cmdline = ""
    ip = sxp.child_value(image, "ip", "dhcp")
    if ip:
        cmdline += " ip=" + ip
    root = sxp.child_value(image, "root")
    if root:
        cmdline += " root=" + root
    args = sxp.child_value(image, "args")
    if args:
        cmdline += " " + args
    ramdisk = sxp.child_value(image, "ramdisk", '')
    vifs = config_devices(config, "vif")
    vm = xen_domain_create(config, "linux", name, memory, kernel,
                           ramdisk, cmdline, len(vifs))
    return vm

def vm_image_netbsd(config, name, memory, image):
    """Create a VM for a bsd image.

    name      vm name
    memory    vm memory
    image     image config

    returns vm
    """
    #todo: Same as for linux. Is that right? If so can unify them.
    kernel = sxp.child_value(image, "kernel")
    cmdline = ""
    ip = sxp.child_value(image, "ip", "dhcp")
    if ip:
        cmdline += "ip=" + ip
    root = sxp.child_value(image, "root")
    if root:
        cmdline += "root=" + root
    args = sxp.child_value(image, "args")
    if args:
        cmdline += " " + args
    ramdisk = sxp.child_value(image, "ramdisk")
    vifs = config_devices(config, "vif")
    vm = xen_domain_create(config, "netbsd", name, memory, kernel,
                           ramdisk, cmdline, len(vifs))
    return vm


def vm_dev_vif(vm, val, index):
    """Create a virtual network interface (vif).

    vm        virtual machine
    val       vif config
    index     vif index
    """
    if vm.net_controller:
        raise VmError('vif: vif in control domain')
    vif = index #todo
    vmac = sxp.child_value(val, "mac")
    bridge = sxp.child_value(val, "bridge") # todo
    defer = make_vif(vm.dom, vif, vmac)
    def fn(id):
        dev = val + ['vif', vif]
        vm.add_device('vif', dev)
        print 'vm_dev_vif> created', dev
        return id
    defer.addCallback(fn)
    return defer

def vm_dev_vbd(vm, val, index):
    """Create a virtual block device (vbd).

    vm        virtual machine
    val       vbd config
    index     vbd index
    """
    if vm.block_controller:
        raise VmError('vbd: vbd in control domain')
    uname = sxp.child_value(val, 'uname')
    if not uname:
        raise VMError('vbd: Missing uname')
    dev = sxp.child_value(val, 'dev')
    if not dev:
        raise VMError('vbd: Missing dev')
    mode = sxp.child_value(val, 'mode', 'r')
    sharing = sxp.child_value(val, 'sharing', 'rr')
    defer = make_disk(vm.dom, uname, dev, mode, sharing)
    def fn(vbd):
        vm.add_device('vbd', val)
        return vbd
    defer.addCallback(fn)
    return defer

def parse_pci(val):
    if isinstance(val, StringType):
        radix = 10
        if val.startswith('0x') or val.startswith('0X'):
            radix = 16
        v = int(val, radix)
    else:
        v = val
    return v

def vm_dev_pci(vm, val, index):
    bus = sxp.child_value(val, 'bus')
    if not bus:
        raise VMError('pci: Missing bus')
    dev = sxp.child_value(val, 'dev')
    if not dev:
        raise VMError('pci: Missing dev')
    func = sxp.child_value(val, 'func')
    if not func:
        raise VMError('pci: Missing func')
    try:
        bus = parse_pci(bus)
        dev = parse_pci(dev)
        func = parse_pci(func)
    except:
        raise VMError('pci: invalid parameter')
    rc = xc.physdev_pci_access_modify(dom=vm.dom, bus=bus, dev=dev, func=func, enable=1)
    if rc < 0:
        #todo non-fatal
        raise VMError('pci: Failed to configure device: bus=%s dev=%s func=%s' %
                      (bus, dev, func))
    return rc
    

def vm_field_vfr(vm, config, val, index):
    """Handle a vfr field in a config.

    vm        virtual machine
    config    vm config
    val       vfr field
    """
    # Get the rules and add them.
    # (vfr (vif (id foo) (ip x.x.x.x)) ... ) 
    list = sxp.children(val, 'vif')
    ipaddrs = []
    for v in list:
        id = sxp.child_value(v, 'id')
        if id is None:
            raise VmError('vfr: missing vif id')
        id = int(id)
        dev = vm.get_device_by_index('vif', id)
        if not dev:
            raise VmError('vfr: invalid vif id %d' % id)
        vif = sxp.child_value(dev, 'vif')
        ip = sxp.child_value(v, 'ip')
        if not ip:
            raise VmError('vfr: missing ip address')
        ipaddrs.append(ip);
        #Don't do this in new i/o model.
        #print 'vm_field_vfr> add rule', 'dom=', vm.dom, 'vif=', vif, 'ip=', ip
        #xenctl.ip.setup_vfr_rules_for_vif(vm.dom, vif, ip)
    vm.ipaddrs = ipaddrs

def vnet_bridge(vnet, vmac, dom, idx):
    """Add the device for the vif to the bridge for its vnet.
    """
    vif = "vif%d.%d" % (dom, idx)
    try:
        cmd = "(vif.conn (vif %s) (vnet %s) (vmac %s))" % (vif, vnet, vmac)
        print "*** vnet_bridge>", cmd
        out = file("/proc/vnet/policy", "wb")
        out.write(cmd)
        err = out.close()
        print "vnet_bridge>", "err=", err
    except IOError, ex:
        print "vnet_bridge>", ex
    
def vm_field_vnet(vm, config, val, index):
    """Handle a vnet field in a config.

    vm        virtual machine
    config    vm config
    val       vnet field
    index     index
    """
    # Get the vif children. For each vif look up the vif device
    # with the given id and configure its vnet.
    # (vnet (vif (id foo) (vnet 2) (mac x:x:x:x:x:x)) ... )
    vif_vnets = sxp.children(val, 'vif')
    for v in vif_vnets:
        id = sxp.child_value(v, 'id')
        if id is None:
            raise VmError('vnet: missing vif id')
        dev = vm.get_device_by_id('vif', id)
        if not sxp.elementp(dev, 'vif'):
            raise VmError('vnet: invalid vif id %s' % id)
        vnet = sxp.child_value(v, 'vnet', 1)
        mac = sxp.child_value(dev, 'mac')
        vif = sxp.child_value(dev, 'vif')
        vnet_bridge(vnet, mac, vm.dom, 0)
        vm.add_config([ 'vif.vnet', ['id', id], ['vnet', vnet], ['mac', mac]])

# Register image handlers for linux and bsd.
add_image_handler('linux',  vm_image_linux)
add_image_handler('netbsd', vm_image_netbsd)

# Register device handlers for vifs and vbds.
add_device_handler('vif',  vm_dev_vif)
add_device_handler('vbd',  vm_dev_vbd)
add_device_handler('pci',  vm_dev_pci)

# Register config handlers for vfr and vnet.
add_config_handler('vfr',  vm_field_vfr)
add_config_handler('vnet', vm_field_vnet)
