# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Representation of a single domain.
Includes support for domain construction, using
open-ended configurations.

Author: Mike Wray <mike.wray@hpl.hp.com>

"""

import string
import types
import re
import sys
import os
import time

from twisted.internet import defer

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()
import xen.util.ip
from xen.util.ip import _readline, _readlines

import sxp

import XendConsole
xendConsole = XendConsole.instance()
from XendLogging import log
from XendRoot import get_component

import server.SrvDaemon
xend = server.SrvDaemon.instance()

from XendError import VmError

"""The length of domain names that Xen can handle.
The names stored in Xen itself are not used for much, and
xend can handle domain names of any length.
"""
MAX_DOMAIN_NAME = 15

"""Flag for a block device backend domain."""
SIF_BLK_BE_DOMAIN = (1<<4)

"""Flag for a net device backend domain."""
SIF_NET_BE_DOMAIN = (1<<5)

"""Shutdown code for poweroff."""
DOMAIN_POWEROFF = 0
"""Shutdown code for reboot."""
DOMAIN_REBOOT   = 1
"""Shutdown code for suspend."""
DOMAIN_SUSPEND  = 2

"""Map shutdown codes to strings."""
shutdown_reasons = {
    DOMAIN_POWEROFF: "poweroff",
    DOMAIN_REBOOT  : "reboot",
    DOMAIN_SUSPEND : "suspend" }

RESTART_ALWAYS   = 'always'
RESTART_ONREBOOT = 'onreboot'
RESTART_NEVER    = 'never'

restart_modes = [
    RESTART_ALWAYS,
    RESTART_ONREBOOT,
    RESTART_NEVER,
    ]

STATE_RESTART_PENDING = 'pending'
STATE_RESTART_BOOTING = 'booting'

STATE_VM_OK         = "ok"
STATE_VM_TERMINATED = "terminated"


def domain_exists(name):
    # See comment in XendDomain constructor.
    xd = get_component('xen.xend.XendDomain')
    return xd.domain_exists(name)

def shutdown_reason(code):
    """Get a shutdown reason from a code.

    @param code: shutdown code
    @type  code: int
    @return: shutdown reason
    @rtype:  string
    """
    return shutdown_reasons.get(code, "?")

def vif_up(iplist):
    """send an unsolicited ARP reply for all non link-local IP addresses.

    @param iplist: IP addresses
    """

    IP_NONLOCAL_BIND = '/proc/sys/net/ipv4/ip_nonlocal_bind'
    
    def get_ip_nonlocal_bind():
        return int(open(IP_NONLOCAL_BIND, 'r').read()[0])

    def set_ip_nonlocal_bind(v):
        print >> open(IP_NONLOCAL_BIND, 'w'), str(v)

    def link_local(ip):
        return xen.util.ip.check_subnet(ip, '169.254.0.0', '255.255.0.0')

    def arping(ip, gw):
        cmd = '/usr/sbin/arping -A -b -I eth0 -c 1 -s %s %s' % (ip, gw)
        log.debug(cmd)
        os.system(cmd)
        
    gateway = xen.util.ip.get_current_ipgw() or '255.255.255.255'
    nlb = get_ip_nonlocal_bind()
    if not nlb: set_ip_nonlocal_bind(1)
    try:
        for ip in iplist:
            if not link_local(ip):
                arping(ip, gateway)
    finally:
        if not nlb: set_ip_nonlocal_bind(0)

config_handlers = {}

def add_config_handler(name, h):
    """Add a handler for a config field.

    @param name:     field name
    @param h:        handler: fn(vm, config, field, index)
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
    @param name:     image type
    @param h:        handler: fn(config, name, memory, image)
    """
    image_handlers[name] = h

def get_image_handler(name):
    """Get the handler for an image type.
    @param name:     image type
    @return: handler or None
    """
    return image_handlers.get(name)

"""Table of handlers for devices.
Indexed by device type.
"""
device_handlers = {}

def add_device_handler(name, h):
    """Add a handler for a device type.

    @param name:     device type
    @param h:        handler: fn(vm, dev)
    """
    device_handlers[name] = h

def get_device_handler(name):
    """Get the handler for a device type.

    @param name :     device type
    @return; handler or None
    """
    return device_handlers.get(name)

def vm_create(config):
    """Create a VM from a configuration.
    If a vm has been partially created and there is an error it
    is destroyed.

    @param config    configuration
    @return: Deferred
    @raise: VmError for invalid configuration
    """
    vm = XendDomainInfo()
    return vm.construct(config)

def vm_recreate(savedinfo, info):
    """Create the VM object for an existing domain.

    @param savedinfo: saved info from the domain DB
    @type  savedinfo: sxpr
    @param info:      domain info from xc
    @type  info:      xc domain dict
    @return: deferred
    """
    vm = XendDomainInfo()
    vm.recreate = 1
    vm.savedinfo = savedinfo
    vm.setdom(info['dom'])
    #vm.name = info['name']
    vm.memory = info['mem_kb']/1024
    start_time = sxp.child_value(savedinfo, 'start_time')
    if start_time is not None:
        vm.start_time = float(start_time)
    vm.restart_state = sxp.child_value(savedinfo, 'restart_state')
    restart_time = sxp.child_value(savedinfo, 'restart_time')
    if restart_time is not None:
        vm.restart_time = float(restart_time)
    config = sxp.child_value(savedinfo, 'config')
    if config:
        d = vm.construct(config)
    else:
        vm.name = sxp.child_value(savedinfo, 'name', "Domain-%d" % info['dom'])
        d = defer.succeed(vm)
    vm.recreate = 0
    vm.savedinfo = None
    return d

def vm_restore(src, progress=0):
    """Restore a VM from a disk image.

    src      saved state to restore
    progress progress reporting flag
    returns  deferred
    raises   VmError for invalid configuration
    """
    vm = XendDomainInfo()
    ostype = "linux" #todo Set from somewhere (store in the src?).
    restorefn = getattr(xc, "%s_restore" % ostype)
    d = restorefn(state_file=src, progress=progress)
    dom = int(d['dom'])
    if dom < 0:
        raise VmError('restore failed')
    try:
        vmconfig = sxp.from_string(d['vmconfig'])
        config = sxp.child_value(vmconfig, 'config')
    except Exception, ex:
        raise VmError('config error: ' + str(ex))
    deferred = vm.dom_construct(dom, config)
    def vifs_cb(val, vm):
        vif_up(vm.ipaddrs)
        return vm
    deferred.addCallback(vifs_cb, vm)
    return deferred
    
def dom_get(dom):
    """Get info from xen for an existing domain.

    @param dom: domain id
    @return: info or None
    """
    domlist = xc.domain_getinfo(dom, 1)
    if domlist and dom == domlist[0]['dom']:
        return domlist[0]
    return None
    
def append_deferred(dlist, v):
    """Append a value to a deferred list if it is a deferred.

    @param dlist: list of deferreds
    @param v: value to add
    """
    if isinstance(v, defer.Deferred):
        dlist.append(v)

def dlist_err(val):
    """Error callback suitable for a deferred list.
    In a deferred list the error callback is called with with Failure((error, index)).
    This callback extracts the error and returns it.

    @param val: Failure containing (error, index)
    @type val: twisted.internet.failure.Failure 
    """
    
    (error, index) = val.value
    return error

class XendDomainInfo:
    """Virtual machine object."""

    """Minimum time between domain restarts in seconds.
    """
    MINIMUM_RESTART_TIME = 20

    def __init__(self):
        self.recreate = 0
        self.restore = 0
        self.config = None
        self.id = None
        self.dom = None
        self.cpu_weight = 1
        self.start_time = None
        self.name = None
        self.memory = None
        self.image = None
        self.ramdisk = None
        self.cmdline = None
        self.console = None
        self.devices = {}
        self.device_index = {}
        self.configs = []
        self.info = None
        self.ipaddrs = []
        self.blkif_backend = 0
        self.netif_backend = 0
        #todo: state: running, suspended
        self.state = STATE_VM_OK
        #todo: set to migrate info if migrating
        self.migrate = None
        self.restart_mode = RESTART_ONREBOOT
        self.restart_state = None
        self.restart_time = None
        self.console_port = None
        self.savedinfo = None

    def setdom(self, dom):
        """Set the domain id.

        @param dom: domain id
        """
        self.dom = int(dom)
        self.id = str(dom)

    def update(self, info):
        """Update with  info from xc.domain_getinfo().
        """
        self.info = info
        self.memory = self.info['mem_kb'] / 1024

    def __str__(self):
        s = "domain"
        s += " id=" + self.id
        s += " name=" + self.name
        s += " memory=" + str(self.memory)
        if self.console:
            s += " console=" + str(self.console.console_port)
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
            sxpr.append(['maxmem', self.info['maxmem_kb']/1024 ])
            run   = (self.info['running']  and 'r') or '-'
            block = (self.info['blocked']  and 'b') or '-'
            pause = (self.info['paused']   and 'p') or '-'
            shut  = (self.info['shutdown'] and 's') or '-'
            crash = (self.info['crashed']  and 'c') or '-'
            state = run + block + pause + shut + crash
            sxpr.append(['state', state])
            if self.info['shutdown']:
                reason = shutdown_reason(self.info['shutdown_reason'])
                sxpr.append(['shutdown_reason', reason])
            sxpr.append(['cpu', self.info['cpu']])
            sxpr.append(['cpu_time', self.info['cpu_time']/1e9])    
            
        if self.start_time:
            up_time =  time.time() - self.start_time  
            sxpr.append(['up_time', str(up_time) ])
            sxpr.append(['start_time', str(self.start_time) ])

        if self.console:
            sxpr.append(self.console.sxpr())
        if self.restart_state:
            sxpr.append(['restart_state', self.restart_state])
        if self.restart_time:
            sxpr.append(['restart_time', str(self.restart_time)])
        devs = self.sxpr_devices()
        if devs:
            sxpr.append(devs)
        if self.config:
            sxpr.append(['config', self.config])
        return sxpr

    def sxpr_devices(self):
        sxpr = ['devices']
        for devs in self.devices.values():
            for dev in devs:
                if hasattr(dev, 'sxpr'):
                    sxpr.append(dev.sxpr())
        return sxpr

    def check_name(self, name):
        """Check if a vm name is valid. Valid names start with a non-digit
        and contain alphabetic characters, digits, or characters in '_-.:/+'.
        The same name cannot be used for more than one vm at the same time.

        @param name: name
        @raise: VMerror if invalid
        """
        if self.recreate: return
        if name is None or name == '':
            raise VmError('missing vm name')
        if name[0] in string.digits:
            raise VmError('invalid vm name')
        for c in name:
            if c in string.digits: continue
            if c in '_-.:/+': continue
            if c in string.ascii_letters: continue
            raise VmError('invalid vm name')
        dominfo = domain_exists(name)
        # When creating or rebooting, a domain with my name should not exist.
        # When restoring, a domain with my name will exist, but it should have
        # my domain id.
        if not dominfo:
            return
        if dominfo.is_terminated():
            return
        if not self.dom or (dominfo.dom != self.dom):
            raise VmError('vm name clash: ' + name)
        
    def construct(self, config):
        """Construct the vm instance from its configuration.

        @param config: configuration
        @return: deferred
        @raise: VmError on error
        """
        # todo - add support for scheduling params?
        self.config = config
        try:
            self.name = sxp.child_value(config, 'name')
            self.check_name(self.name)
            try:
                self.cpu_weight = float(sxp.child_value(config, 'cpu_weight', '1'))
            except:
                raise VmError('invalid cpu weight')
            self.memory = int(sxp.child_value(config, 'memory'))
            if self.memory is None:
                raise VmError('missing memory size')
            cpu = sxp.child_value(config, 'cpu')
            if self.recreate and self.dom and cpu is not None:
                xc.domain_pincpu(self.dom, int(cpu))

            self.init_domain()
            self.configure_console()
            self.construct_image()
            self.configure_restart()
            self.configure_backends()
            deferred = self.configure()
            def cberr(err):
                self.destroy()
                return err
            deferred.addErrback(cberr)
        except StandardError, ex:
            # Catch errors, cleanup and re-raise.
            self.destroy()
            raise
        return deferred

    def construct_image(self):
        """Construct the boot image for the domain.

        @return vm
        """
        image = sxp.child_value(self.config, 'image')
        if image is None:
            raise VmError('missing image')
        image_name = sxp.name(image)
        if image_name is None:
            raise VmError('missing image name')
        image_handler = get_image_handler(image_name)
        if image_handler is None:
            raise VmError('unknown image type: ' + image_name)
        image_handler(self, image)
        return self

    def config_devices(self, name):
        """Get a list of the 'device' nodes of a given type from the config.

        @param name: device type
        @type  name: string
        @return: device configs
        @rtype: list
        """
        devices = []
        for d in sxp.children(self.config, 'device'):
            dev = sxp.child0(d)
            if dev is None: continue
            if name == sxp.name(dev):
                devices.append(dev)
        return devices

    def config_device(self, type, idx):
        """Get a device config from the device nodes of a given type
        from the config.

        @param type: device type
        @type  type: string
        @param idx: index
        @type  idx: int
        @return config or None
        """
        devs = self.config_devices(type)
        if 0 <= idx < len(devs):
            return devs[idx]
        else:
            return None

    def next_device_index(self, type):
        """Get the next index for a given device type.

        @param type: device type
        @type  type: string
        @return device index
        @rtype: int
        """
        idx = self.device_index.get(type, 0)
        self.device_index[type] = idx + 1
        return idx

    def add_device(self, type, dev):
        """Add a device to a virtual machine.

        @param type: device type
        @param dev:  device to add
        """
        dl = self.devices.get(type, [])
        dl.append(dev)
        self.devices[type] = dl

    def remove_device(self, type, dev):
        """Remove a device from a virtual machine.

        @param type: device type
        @param dev:  device
        """
        dl = self.devices.get(type, [])
        if dev in dl:
            dl.remove(dev)

    def get_devices(self, type):
        """Get a list of the devices of a given type.

        @param type: device type
        @return: devices
        """
        val = self.devices.get(type, [])
        return val

    def get_device_by_id(self, type, id):
        """Get the device with the given id.

        @param id:       device id
        @return:  device or None
        """
        dl = self.get_devices(type)
        for d in dl:
            if d.getprop('id') == id:
                return d
        return None

    def get_device_by_index(self, type, idx):
        """Get the device with the given index.

        @param idx: device index
        @return:  device or None
        """
        idx = str(idx)
        dl = self.get_devices(type)
        for d in dl:
            if d.getidx() == idx:
                return d
        return None

    def get_device_savedinfo(self, type, index):
        val = None
        if self.savedinfo is None:
            return val
        index = str(index)
        devinfo = sxp.child(self.savedinfo, 'devices')
        if devinfo is None:
            return val
        for d in sxp.children(devinfo, type):
            dindex = sxp.child_value(d, 'index')
            if dindex is None: continue
            if str(dindex) == index:
                val = d
                break
        return val

    def get_device_recreate(self, type, index):
        return self.get_device_savedinfo(type, index) or self.recreate

    def add_config(self, val):
        """Add configuration data to a virtual machine.

        @param val: data to add
        """
        self.configs.append(val)

    def destroy(self):
        """Completely destroy the vm.
        """
        self.cleanup()
        return self.destroy_domain()

    def destroy_domain(self):
        """Destroy the vm's domain.
        The domain will not finally go away unless all vm
        devices have been released.
        """
        if self.dom is None: return 0
        self.destroy_console()
        chan = xend.getDomChannel(self.dom)
        if chan:
            log.debug("Closing channel to domain %d", self.dom)
            chan.close()
        try:
            return xc.domain_destroy(dom=self.dom)
        except Exception, err:
            log.exception("Domain destroy failed: %s", self.name)

    def destroy_console(self):
        if self.console:
            if self.restart_pending():
                self.console.deregisterChannel()
            else:
                log.debug('Closing console, domain %s', self.id)
                self.console.close()

    def cleanup(self):
        """Cleanup vm resources: release devices.
        """
        self.state = STATE_VM_TERMINATED
        self.release_devices()

    def is_terminated(self):
        """Check if a domain has been terminated.
        """
        return self.state == STATE_VM_TERMINATED

    def release_devices(self):
        """Release all vm devices.
        """
        self.release_vifs()
        self.release_vbds()
        
        self.devices = {}
        self.device_index = {}
        self.configs = []
        self.ipaddrs = []

    def release_vifs(self):
        """Release vm virtual network devices (vifs).
        """
        if self.dom is None: return
        ctrl = xend.netif_get(self.dom)
        if ctrl:
            log.debug("Destroying vifs for domain %d", self.dom)
            ctrl.destroy()

    def release_vbds(self):
        """Release vm virtual block devices (vbds).
        """
        if self.dom is None: return
        ctrl = xend.blkif_get(self.dom)
        if ctrl:
            log.debug("Destroying vbds for domain %d", self.dom)
            ctrl.destroy()

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

    def init_domain(self):
        """Initialize the domain memory.
        """
        if self.recreate:
            return
        if self.start_time is None:
            self.start_time = time.time()
        if self.restore:
            return
        dom = self.dom or 0
        memory = self.memory
        name = self.name
        # If the name is over the xen limit, use the end of it.
        if len(name) > MAX_DOMAIN_NAME:
            name = name[-MAX_DOMAIN_NAME:]
        try:
            cpu = int(sxp.child_value(self.config, 'cpu', '-1'))
        except:
            raise VmError('invalid cpu')
        cpu_weight = self.cpu_weight
        dom = xc.domain_create(dom= dom, mem_kb= memory * 1024,
                               cpu= cpu, cpu_weight= cpu_weight)
        if dom <= 0:
            raise VmError('Creating domain failed: name=%s memory=%d'
                          % (name, memory))
        log.debug('init_domain> Created domain=%d name=%s memory=%d', dom, name, memory)
        self.setdom(dom)

    def build_domain(self, ostype, kernel, ramdisk, cmdline):
        """Build the domain boot image.
        """
        if self.recreate or self.restore: return
        if not os.path.isfile(kernel):
            raise VmError('Kernel image does not exist: %s' % kernel)
        if ramdisk and not os.path.isfile(ramdisk):
            raise VmError('Kernel ramdisk does not exist: %s' % ramdisk)
        if len(cmdline) >= 256:
            log.warning('kernel cmdline too long, domain %d', self.dom)
        dom = self.dom
        buildfn = getattr(xc, '%s_build' % ostype)
        flags = 0
        if self.netif_backend: flags |= SIF_NET_BE_DOMAIN
        if self.blkif_backend: flags |= SIF_BLK_BE_DOMAIN
        err = buildfn(dom            = dom,
                      image          = kernel,
                      control_evtchn = self.console.getRemotePort(),
                      cmdline        = cmdline,
                      ramdisk        = ramdisk,
                      flags          = flags)
        if err != 0:
            raise VmError('Building domain failed: type=%s dom=%d err=%d'
                          % (ostype, dom, err))

    def create_domain(self, ostype, kernel, ramdisk, cmdline):
        """Create a domain. Builds the image but does not configure it.

        @param ostype:  OS type
        @param kernel:  kernel image
        @param ramdisk: kernel ramdisk
        @param cmdline: kernel commandline
        """
        #self.init_domain()
        if self.console:
            self.console.registerChannel()
        else:
            self.console = xendConsole.console_create(
                self.dom, console_port=self.console_port, remote_port=1)
        self.build_domain(ostype, kernel, ramdisk, cmdline)
        self.image = kernel
        self.ramdisk = ramdisk
        self.cmdline = cmdline

    def create_devices(self):
        """Create the devices for a vm.

        @return: Deferred
        @raise: VmError for invalid devices
        """
        dlist = []
        devices = sxp.children(self.config, 'device')
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
            v = dev_handler(self, dev, dev_index)
            append_deferred(dlist, v)
            index[dev_name] = dev_index + 1
        deferred = defer.DeferredList(dlist, fireOnOneErrback=1)
        deferred.addErrback(dlist_err)
        return deferred

    def device_create(self, dev_config):
        """Create a new device.

        @param dev_config: device configuration
        @return: deferred
        """
        dev_name = sxp.name(dev_config)
        dev_handler = get_device_handler(dev_name)
        if dev_handler is None:
            raise VmError('unknown device type: ' + dev_name)
        devs = self.get_devices(dev_name)
        dev_index = len(devs)
        self.config.append(['device', dev_config])
        d = dev_handler(self, dev_config, dev_index, change=1)
        def cbok(dev):
            return dev.sxpr()
        d.addCallback(cbok)
        return d

    def device_configure(self, dev_config, idx):
        """Configure an existing device.

        @param dev_config: device configuration
        @param idx:  device index
        """
        type = sxp.name(dev_config)
        dev = self.get_device_by_index(type, idx)
        if not dev:
            raise VmError('invalid device: %s %s' % (type, idx))
        new_config = dev.configure(dev_config, change=1)
        devs = self.devices.get(type)
        index = devs.index(dev)
        # Patch new config into device configs.
        dev_configs = self.config_devices(type)
        old_config = dev_configs[index]
        dev_configs[index] = new_config
        # Patch new config into vm config.
        new_full_config = ['device', new_config]
        old_full_config = ['device', old_config]
        old_index = self.config.index(old_full_config)
        self.config[old_index] = new_full_config
        return new_config
        
    def device_destroy(self, type, idx):
        """Destroy a device.

        @param type: device type
        @param idx:  device index
        """
        dev = self.get_device_by_index(type, idx)
        if not dev:
            raise VmError('invalid device: %s %s' % (type, idx))
        devs = self.devices.get(type)
        index = devs.index(dev)
        dev_config = self.config_device(type, index)
        if dev_config:
            self.config.remove(['device', dev_config])
        dev.destroy(change=1)
        self.remove_device(type, dev)

    def configure_memory(self):
        """Configure vm memory limit.
        """
        maxmem = sxp.child_value(self.config, "maxmem")
        if maxmem is None:
            maxmem = self.memory
        xc.domain_setmaxmem(self.dom, maxmem_kb = maxmem * 1024)

    def configure_console(self):
        """Configure the vm console port.
        """
        x = sxp.child_value(self.config, 'console')
        if x:
            try:
                port = int(x)
            except:
                raise VmError('invalid console:' + str(x))
            self.console_port = port

    def configure_restart(self):
        """Configure the vm restart mode.
        """
        r = sxp.child_value(self.config, 'restart', RESTART_ONREBOOT)
        if r not in restart_modes:
            raise VmError('invalid restart mode: ' + str(r))
        self.restart_mode = r;

    def restart_needed(self, reason):
        """Determine if the vm needs to be restarted when shutdown
        for the given reason.

        @param reason: shutdown reason
        @return 1 if needs restaert, 0 otherwise
        """
        if self.restart_mode == RESTART_NEVER:
            return 0
        if self.restart_mode == RESTART_ALWAYS:
            return 1
        if self.restart_mode == RESTART_ONREBOOT:
            return reason == 'reboot'
        return 0

    def restart_cancel(self):
        """Cancel a vm restart.
        """
        self.restart_state = None

    def restarting(self):
        """Put the vm into restart mode.
        """
        self.restart_state = STATE_RESTART_PENDING

    def restart_pending(self):
        """Test if the vm has a pending restart.
        """
        return self.restart_state == STATE_RESTART_PENDING

    def restart_check(self):
        """Check if domain restart is OK.
        To prevent restart loops, raise an error if it is
        less than MINIMUM_RESTART_TIME seconds since the last restart.
        """
        tnow = time.time()
        if self.restart_time is not None:
            tdelta = tnow - self.restart_time
            if tdelta < self.MINIMUM_RESTART_TIME:
                self.restart_cancel()
                msg = 'VM %s restarting too fast' % self.name
                log.error(msg)
                raise VmError(msg)
        self.restart_time = tnow

    def restart(self):
        """Restart the domain after it has exited.
        Reuses the domain id and console port.

        @return: deferred
        """
        try:
            self.restart_check()
            self.restart_state = STATE_RESTART_BOOTING
            d = self.construct(self.config)
        finally:
            self.restart_state = None
        return d

    def configure_backends(self):
        """Set configuration flags if the vm is a backend for netif or blkif.
        Configure the backends to use for vbd and vif if specified.
        """
        for c in sxp.children(self.config, 'backend'):
            v = sxp.child0(c)
            name = sxp.name(v)
            if name == 'blkif':
                self.blkif_backend = 1
            elif name == 'netif':
                self.netif_backend = 1
            else:
                raise VmError('invalid backend type:' + str(name))

    def configure(self):
        """Configure a vm.

        @return: deferred - calls callback with vm
        """
        d = self.create_blkif()
        d.addCallback(lambda x: self.create_devices())
        d.addCallback(self._configure)
        return d

    def _configure(self, val):
        d = self.configure_fields()
        def cbok(results):
            return self
        def cberr(err):
            self.destroy()
            return err
        d.addCallback(cbok)
        d.addErrback(cberr)
        return d

    def create_blkif(self):
        """Create the block device interface (blkif) for the vm.
        The vm needs a blkif even if it doesn't have any disks
        at creation time, for example when it uses NFS root.

        @return: deferred
        """
        ctrl = xend.blkif_create(self.dom, recreate=self.recreate)
        back = ctrl.getBackendInterface(0)
        return back.connect(recreate=self.recreate)
    
    def dom_construct(self, dom, config):
        """Construct a vm for an existing domain.

        @param dom: domain id
        @param config: domain configuration
        @return: deferred
        """
        d = dom_get(dom)
        if not d:
            raise VmError("Domain not found: %d" % dom)
        try:
            self.restore = 1
            self.setdom(dom)
            #self.name = d['name']
            self.memory = d['mem_kb']/1024
            deferred = self.construct(config)
        finally:
            self.restore = 0
        return deferred

    def configure_fields(self):
        """Process the vm configuration fields using the registered handlers.
        """
        dlist = []
        index = {}
        for field in sxp.children(self.config):
            field_name = sxp.name(field)
            field_index = index.get(field_name, 0)
            field_handler = get_config_handler(field_name)
            # Ignore unknown fields. Warn?
            if field_handler:
                v = field_handler(self, self.config, field, field_index)
                append_deferred(dlist, v)
            else:
                log.warning("Unknown config field %s", field_name)
            index[field_name] = field_index + 1
        d = defer.DeferredList(dlist, fireOnOneErrback=1)
        d.addErrback(dlist_err)
        return d


def vm_image_linux(vm, image):
    """Create a VM for a linux image.

    @param name:      vm name
    @param memory:    vm memory
    @param image:     image config
    @return: vm
    """
    kernel = sxp.child_value(image, "kernel")
    cmdline = ""
    ip = sxp.child_value(image, "ip", None)
    if ip:
        cmdline += " ip=" + ip
    root = sxp.child_value(image, "root")
    if root:
        cmdline += " root=" + root
    args = sxp.child_value(image, "args")
    if args:
        cmdline += " " + args
    ramdisk = sxp.child_value(image, "ramdisk", '')
    vm.create_domain("linux", kernel, ramdisk, cmdline)
    return vm

def vm_dev_vif(vm, val, index, change=0):
    """Create a virtual network interface (vif).

    @param vm:        virtual machine
    @param val:       vif config
    @param index:     vif index
    @return: deferred
    """
    vif = vm.next_device_index('vif')
    vmac = sxp.child_value(val, "mac")
    ctrl = xend.netif_create(vm.dom, recreate=vm.recreate)
    log.debug("Creating vif dom=%d vif=%d mac=%s", vm.dom, vif, str(vmac))
    recreate = vm.get_device_recreate('vif', index)
    defer = ctrl.attachDevice(vif, val, recreate=recreate)
    def cbok(dev):
        dev.vifctl('up', vmname=vm.name)
        dev.setIndex(index)
        vm.add_device('vif', dev)
        if change:
            dev.interfaceChanged()
        return dev
    defer.addCallback(cbok)
    return defer

def vm_dev_vbd(vm, val, index, change=0):
    """Create a virtual block device (vbd).

    @param vm:        virtual machine
    @param val:       vbd config
    @param index:     vbd index
    @return: deferred
    """
    idx = vm.next_device_index('vbd')
    uname = sxp.child_value(val, 'uname')
    log.debug("Creating vbd dom=%d uname=%s", vm.dom, uname)
    ctrl = xend.blkif_create(vm.dom, recreate=vm.recreate)
    recreate = vm.get_device_recreate('vbd', index)
    defer = ctrl.attachDevice(idx, val, recreate=recreate)
    def cbok(dev):
        dev.setIndex(index)
        vm.add_device('vbd', dev)
        if change:
            dev.interfaceChanged()
        return dev
    defer.addCallback(cbok)
    return defer

def parse_pci(val):
    """Parse a pci field.
    """
    if isinstance(val, types.StringType):
        radix = 10
        if val.startswith('0x') or val.startswith('0X'):
            radix = 16
        v = int(val, radix)
    else:
        v = val
    return v

def vm_dev_pci(vm, val, index, change=0):
    """Add a pci device.

    @param vm: virtual machine
    @param val: device configuration
    @param index: device index
    @return: 0 on success
    """
    bus = sxp.child_value(val, 'bus')
    if not bus:
        raise VmError('pci: Missing bus')
    dev = sxp.child_value(val, 'dev')
    if not dev:
        raise VmError('pci: Missing dev')
    func = sxp.child_value(val, 'func')
    if not func:
        raise VmError('pci: Missing func')
    try:
        bus = parse_pci(bus)
        dev = parse_pci(dev)
        func = parse_pci(func)
    except:
        raise VmError('pci: invalid parameter')
    log.debug("Creating pci device dom=%d bus=%x dev=%x func=%x", vm.dom, bus, dev, func)
    rc = xc.physdev_pci_access_modify(dom=vm.dom, bus=bus, dev=dev,
                                      func=func, enable=1)
    if rc < 0:
        #todo non-fatal
        raise VmError('pci: Failed to configure device: bus=%s dev=%s func=%s' %
                      (bus, dev, func))
    return rc
    

def vm_field_ignore(vm, config, val, index):
    """Dummy config field handler used for fields with built-in handling.

    @param vm:        virtual machine
    @param config:    vm config
    @param val:       config field
    @param index:     field index
    """
    pass

def vm_field_maxmem(vm, config, val, index):
    """Configure vm memory limit.

    @param vm:        virtual machine
    @param config:    vm config
    @param val:       config field
    @param index:     field index
    """
    maxmem = sxp.child0(val)
    if maxmem is None:
        maxmem = vm.memory
    try:
        maxmem = int(maxmem)
    except:
        raise VmError("invalid maxmem: " + str(maxmem))
    xc.domain_setmaxmem(vm.dom, maxmem_kb = maxmem * 1024)

# Register image handlers.
add_image_handler('linux',  vm_image_linux)

# Register device handlers.
add_device_handler('vif',  vm_dev_vif)
add_device_handler('vbd',  vm_dev_vbd)
add_device_handler('pci',  vm_dev_pci)

# Ignore the fields we already handle.
add_config_handler('name',       vm_field_ignore)
add_config_handler('memory',     vm_field_ignore)
add_config_handler('cpu',        vm_field_ignore)
add_config_handler('cpu_weight', vm_field_ignore)
add_config_handler('console',    vm_field_ignore)
add_config_handler('image',      vm_field_ignore)
add_config_handler('device',     vm_field_ignore)
add_config_handler('backend',    vm_field_ignore)

# Register other config handlers.
add_config_handler('maxmem',     vm_field_maxmem)
