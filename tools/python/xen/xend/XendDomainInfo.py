# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Representation of a single domain.
Includes support for domain construction, using
open-ended configurations.

Author: Mike Wray <mike.wray@hp.com>

"""

import string
import os
import time

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()
import xen.util.ip
from xen.util.ip import _readline, _readlines
from xen.xend.server import channel, controller
from xen.util.blkif import blkdev_uname_to_file

from server.channel import channelFactory
import server.SrvDaemon; xend = server.SrvDaemon.instance()
from server import messages

from xen.xend.XendBootloader import bootloader
import sxp
from XendLogging import log
from XendError import VmError
from XendRoot import get_component

from PrettyPrint import prettyprintstring

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

"""Map shutdown reasons to the message type to use.
"""
shutdown_messages = {
    'poweroff' : 'shutdown_poweroff_t',
    'reboot'   : 'shutdown_reboot_t',
    'suspend'  : 'shutdown_suspend_t',
    'sysrq'    : 'shutdown_sysrq_t',
    }

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

def add_device_handler(name, type):
    device_handlers[name] = type

def get_device_handler(name):
    return device_handlers[name]
    

def vm_create(config):
    """Create a VM from a configuration.
    If a vm has been partially created and there is an error it
    is destroyed.

    @param config    configuration
    @raise: VmError for invalid configuration
    """
    vm = XendDomainInfo()
    vm.construct(config)
    return vm

def vm_recreate(savedinfo, info):
    """Create the VM object for an existing domain.

    @param savedinfo: saved info from the domain DB
    @type  savedinfo: sxpr
    @param info:      domain info from xc
    @type  info:      xc domain dict
    """
    log.debug('savedinfo=' + prettyprintstring(savedinfo))
    log.debug('info=' + str(info))
    vm = XendDomainInfo()
    vm.recreate = True
    vm.savedinfo = savedinfo
    vm.setdom(info['dom'])
    vm.memory = info['mem_kb']/1024
    start_time = sxp.child_value(savedinfo, 'start_time')
    if start_time is not None:
        vm.start_time = float(start_time)
    vm.restart_state = sxp.child_value(savedinfo, 'restart_state')
    vm.restart_count = int(sxp.child_value(savedinfo, 'restart_count', 0))
    restart_time = sxp.child_value(savedinfo, 'restart_time')
    if restart_time is not None:
        vm.restart_time = float(restart_time)
    config = sxp.child_value(savedinfo, 'config')
    if config:
        vm.construct(config)
    else:
        vm.name = sxp.child_value(savedinfo, 'name', "Domain-%d" % info['dom'])
    vm.recreate = False
    vm.savedinfo = None
    return vm

def vm_restore(src, progress=False):
    """Restore a VM from a disk image.

    src      saved state to restore
    progress progress reporting flag
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
    vm.dom_construct(dom, config)
    vif_up(vm.ipaddrs)
    return vm
    
def dom_get(dom):
    """Get info from xen for an existing domain.

    @param dom: domain id
    @return: info or None
    """
    domlist = xc.domain_getinfo(dom, 1)
    if domlist and dom == domlist[0]['dom']:
        return domlist[0]
    return None
    
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

        self.channel = None
        self.controllers = {}
        
        self.configs = []
        
        self.info = None
        self.ipaddrs = []
        self.blkif_backend = False
        self.netif_backend = False
        #todo: state: running, suspended
        self.state = STATE_VM_OK
        #todo: set to migrate info if migrating
        self.migrate = None
        
        self.restart_mode = RESTART_ONREBOOT
        self.restart_state = None
        self.restart_time = None
        self.restart_count = 0
        
        self.console_port = None
        self.savedinfo = None
        self.image_handler = None
        self.is_vmx = False
        self.vcpus = 1
        self.bootloader = None

    def setdom(self, dom):
        """Set the domain id.

        @param dom: domain id
        """
        self.dom = int(dom)
        self.id = str(dom)

    def getDomain(self):
        return self.dom

    def getName(self):
        return self.name

    def getChannel(self):
        return self.channel

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
        console = self.getConsole()
        if console:
            s += " console=" + str(console.console_port)
        if self.image:
            s += " image=" + self.image
        s += ""
        return s

    __repr__ = __str__

    def getDeviceTypes(self):
        return self.controllers.keys()

    def getDeviceControllers(self):
        return self.controllers.values()

    def getDeviceController(self, type, error=True):
        ctrl = self.controllers.get(type)
        if not ctrl and error:
            raise XendError("invalid device type:" + type)
        return ctrl
    
    def findDeviceController(self, type):
        return (self.getDeviceController(type, error=False)
                or self.createDeviceController(type))

    def createDeviceController(self, type):
        ctrl = controller.createDevController(type, self, recreate=self.recreate)
        self.controllers[type] = ctrl
        return ctrl

    def createDevice(self, type, devconfig, recreate=False):
        ctrl = self.findDeviceController(type)
        return ctrl.createDevice(devconfig, recreate=self.recreate)

    def configureDevice(self, type, id, devconfig):
        ctrl = self.getDeviceController(type)
        return ctrl.configureDevice(id, devconfig)

    def destroyDevice(self, type, id, change=False, reboot=False):
        ctrl = self.getDeviceController(type)
        return ctrl.destroyDevice(id, change=change, reboot=reboot)

    def deleteDevice(self, type, id):
        ctrl = self.getDeviceController(type)
        return ctrl.deleteDevice(id)

    def getDevice(self, type, id):
        ctrl = self.getDeviceController(type)
        return ctrl.getDevice(id)
        
    def getDeviceByIndex(self, type, idx):
        ctrl = self.getDeviceController(type)
        return ctrl.getDeviceByIndex(idx)

    def getDeviceConfig(self, type, id):
        ctrl = self.getDeviceController(type)
        return ctrl.getDeviceConfig(id)

    def getDeviceIds(self, type):
        ctrl = self.getDeviceController(type)
        return ctrl.getDeviceIds()
    
    def getDeviceIndexes(self, type):
        ctrl = self.getDeviceController(type)
        return ctrl.getDeviceIndexes()
    
    def getDeviceConfigs(self, type):
        ctrl = self.getDeviceController(type)
        return ctrl.getDeviceConfigs()

    def getDeviceSxprs(self, type):
        ctrl = self.getDeviceController(type)
        return ctrl.getDeviceSxprs()

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
            sxpr.append(['cpu', self.info['vcpu_to_cpu'][0]])
            sxpr.append(['cpu_time', self.info['cpu_time']/1e9])    
            sxpr.append(['vcpus', self.info['vcpus']])
            sxpr.append(['cpumap', self.info['cpumap']])
            sxpr.append(['vcpu_to_cpu', ''.join(map(lambda x: str(x),
                        self.info['vcpu_to_cpu'][0:self.info['vcpus']]))])
            
        if self.start_time:
            up_time =  time.time() - self.start_time  
            sxpr.append(['up_time', str(up_time) ])
            sxpr.append(['start_time', str(self.start_time) ])

        if self.channel:
            sxpr.append(self.channel.sxpr())
        console = self.getConsole()
        if console:
            sxpr.append(console.sxpr())
        if self.restart_count:
            sxpr.append(['restart_count', self.restart_count])
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
        sxpr = []
        for ty in self.getDeviceTypes():
            devs = self.getDeviceSxprs(ty)
            sxpr += devs
        if sxpr:
            sxpr.insert(0, 'devices')
        else:
            sxpr = None
        return sxpr

    def check_name(self, name):
        """Check if a vm name is valid. Valid names contain alphabetic characters,
        digits, or characters in '_-.:/+'.
        The same name cannot be used for more than one vm at the same time.

        @param name: name
        @raise: VMerror if invalid
        """
        if self.recreate: return
        if name is None or name == '':
            raise VmError('missing vm name')
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
        @raise: VmError on error
        """
        # todo - add support for scheduling params?
        self.config = config
        try:
            # Initial domain create.
            self.name = sxp.child_value(config, 'name')
            self.check_name(self.name)
            self.configure_cpus(config)
            self.find_image_handler()
            self.init_domain()
            self.register_domain()
            self.configure_bootloader()

            # Create domain devices.
            self.configure_backends()
            self.configure_console()
            self.configure_restart()
            self.construct_image()
            self.configure()
        except Exception, ex:
            # Catch errors, cleanup and re-raise.
            print 'Domain construction error:', ex
            import traceback
            traceback.print_exc()
            self.destroy()
            raise

    def register_domain(self):
        xd = get_component('xen.xend.XendDomain')
        xd._add_domain(self)

    def configure_cpus(self, config):
        try:
            self.cpu_weight = float(sxp.child_value(config, 'cpu_weight', '1'))
        except:
            raise VmError('invalid cpu weight')
        self.memory = int(sxp.child_value(config, 'memory'))
        if self.memory is None:
            raise VmError('missing memory size')
        cpu = sxp.child_value(config, 'cpu')
        if self.recreate and self.dom and cpu is not None:
            #xc.domain_pincpu(self.dom, int(cpu))
            xc.domain_pincpu(self.dom, 0, 1<<int(cpu))
        try:
            image = sxp.child_value(self.config, 'image')
            vcpus = sxp.child_value(image, 'vcpus')
            if vcpus:
                self.vcpus = int(vcpus)
        except:
            raise VmError('invalid vcpus value')

    def find_image_handler(self):
        """Construct the boot image for the domain.

        @return vm
        """
        image = sxp.child_value(self.config, 'image')
        if image is None:
            raise VmError('missing image')
        image_name = sxp.name(image)
        if image_name is None:
            raise VmError('missing image name')
        if image_name == "vmx":
            self.is_vmx = True
        image_handler = get_image_handler(image_name)
        if image_handler is None:
            raise VmError('unknown image type: ' + image_name)
        self.image_handler = image_handler
        return self

    def construct_image(self):
        image = sxp.child_value(self.config, 'image')
        self.image_handler(self, image)
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

    def get_device_savedinfo(self, type, index):
        val = None
        if self.savedinfo is None:
            return val
        devices = sxp.child(self.savedinfo, 'devices')
        if devices is None:
            return val
        index = str(index)
        for d in sxp.children(devices, type):
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
        if self.channel:
            self.channel.close()
            self.channel = None
        if self.dom is None: return 0
        try:
            return xc.domain_destroy(dom=self.dom)
        except Exception, err:
            log.exception("Domain destroy failed: %s", self.name)

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
        reboot = self.restart_pending()
        for ctrl in self.getDeviceControllers():
            if ctrl.isDestroyed(): continue
            ctrl.destroyController(reboot=reboot)
        if not reboot:
            self.configs = []
            self.ipaddrs = []

    def show(self):
        """Print virtual machine info.
        """
        print "[VM dom=%d name=%s memory=%d" % (self.dom, self.name, self.memory)
        print "image:"
        sxp.show(self.image)
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
        try:
            cpu = int(sxp.child_value(self.config, 'cpu', '-1'))
        except:
            raise VmError('invalid cpu')
        cpu_weight = self.cpu_weight
        memory = memory * 1024 + self.pgtable_size(memory)
        dom = xc.domain_create(dom= dom, mem_kb= memory,
                               cpu= cpu, cpu_weight= cpu_weight)
        if self.bootloader:
            try:
                if kernel: os.unlink(kernel)
                if ramdisk: os.unlink(ramdisk)
            except OSError, e:
                log.warning('unable to unlink kernel/ramdisk: %s' %(e,))

        if dom <= 0:
            raise VmError('Creating domain failed: name=%s memory=%d'
                          % (self.name, memory))
        log.debug('init_domain> Created domain=%d name=%s memory=%d', dom, self.name, memory)
        self.setdom(dom)

    def build_domain(self, ostype, kernel, ramdisk, cmdline, memmap):
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
        #todo generalise this
        if ostype == "vmx":
            err = buildfn(dom            = dom,
                          image          = kernel,
                          control_evtchn = 0,
                          memsize        = self.memory,
                          memmap         = memmap,
                          cmdline        = cmdline,
                          ramdisk        = ramdisk,
                          flags          = flags)
        else:
            log.warning('building dom with %d vcpus', self.vcpus)
            err = buildfn(dom            = dom,
                          image          = kernel,
                          control_evtchn = self.channel.getRemotePort(),
                          cmdline        = cmdline,
                          ramdisk        = ramdisk,
                          flags          = flags,
                          vcpus          = self.vcpus)
            if err != 0:
                raise VmError('Building domain failed: type=%s dom=%d err=%d'
                              % (ostype, dom, err))
            
    def create_domain(self, ostype, kernel, ramdisk, cmdline, memmap=''):
        """Create a domain. Builds the image but does not configure it.

        @param ostype:  OS type
        @param kernel:  kernel image
        @param ramdisk: kernel ramdisk
        @param cmdline: kernel commandline
        """

        self.create_channel()
        self.build_domain(ostype, kernel, ramdisk, cmdline, memmap)
        self.image = kernel
        self.ramdisk = ramdisk
        self.cmdline = cmdline

    def create_channel(self):
        """Create the control channel to the domain.
        If saved info is available recreate the channel using the saved ports.
        """
        local = 0
        remote = 1
        if self.savedinfo:
            info = sxp.child(self.savedinfo, "channel")
            if info:
                local = int(sxp.child_value(info, "local_port", 0))
                remote = int(sxp.child_value(info, "remote_port", 1))
        self.channel = channelFactory().openChannel(self.dom,
                                                    local_port=local,
                                                    remote_port=remote)

    def create_configured_devices(self):
        devices = sxp.children(self.config, 'device')
        indexes = {}
        for d in devices:
            dev_config = sxp.child0(d)
            if dev_config is None:
                raise VmError('invalid device')
            dev_type = sxp.name(dev_config)
            ctrl_type = get_device_handler(dev_type)
            if ctrl_type is None:
                raise VmError('unknown device type: ' + dev_type)
            # Keep track of device indexes by type, so we can fish
            # out saved info for recreation.
            idx = indexes.get(dev_type, -1)
            idx += 1
            indexes[ctrl_type] = idx
            recreate = self.get_device_recreate(dev_type, idx)
            self.createDevice(ctrl_type, dev_config, recreate=recreate)
        
    def create_devices(self):
        """Create the devices for a vm.

        @raise: VmError for invalid devices
        """
        if self.rebooting():
            for ctrl in self.getDeviceControllers():
                ctrl.initController(reboot=True)
        else:
            self.create_configured_devices()
        if self.is_vmx:
            self.create_vmx_model()

    def create_vmx_model(self):
        #todo: remove special case for vmx
        device_model = sxp.child_value(self.config, 'device_model')
        if not device_model:
            raise VmError("vmx: missing device model")
        device_config = sxp.child_value(self.config, 'device_config')
        if not device_config:
            raise VmError("vmx: missing device config")
        #todo: self.memory?
        memory = sxp.child_value(self.config, "memory")
        # Create an event channel
        device_channel = channel.eventChannel(0, self.dom)
        # Execute device model.
        #todo: Error handling
        os.system(device_model
                  + " -f %s" % device_config
                  + " -d %d" % self.dom
                  + " -p %d" % device_channel['port1']
                  + " -m %s" % memory)

    def device_create(self, dev_config):
        """Create a new device.

        @param dev_config: device configuration
        """
        dev_type = sxp.name(dev_config)
        dev = self.createDevice(self, dev_config, change=True)
        self.config.append(['device', dev.getConfig()])
        return dev.sxpr()

    def device_configure(self, dev_config, idx):
        """Configure an existing device.

        @param dev_config: device configuration
        @param idx:  device index
        """
        type = sxp.name(dev_config)
        dev = self.getDeviceByIndex(type, idx)
        if not dev:
            raise VmError('invalid device: %s %s' % (type, idx))
        old_config = dev.getConfig()
        new_config = dev.configure(dev_config, change=True)
        # Patch new config into vm config.
        new_full_config = ['device', new_config]
        old_full_config = ['device', old_config]
        old_index = self.config.index(old_full_config)
        self.config[old_index] = new_full_config
        return new_config

    def device_refresh(self, type, idx):
        """Refresh a device.

        @param type: device type
        @param idx:  device index
        """
        dev = self.getDeviceByIndex(type, idx)
        if not dev:
            raise VmError('invalid device: %s %s' % (type, idx))
        dev.refresh()
        
    def device_delete(self, type, idx):
        """Destroy and remove a device.

        @param type: device type
        @param idx:  device index
        """
        dev = self.getDeviceByIndex(type, idx)
        if not dev:
            raise VmError('invalid device: %s %s' % (type, idx))
        dev_config = dev.getConfig()
        if dev_config:
            self.config.remove(['device', dev_config])
        self.deleteDevice(type, dev.getId())

    def configure_bootloader(self):
        """Configure boot loader.
        """
        bl = sxp.child_value(self.config, "bootloader")
        if bl is not None:
            self.bootloader = bl

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
        @return True if needs restart, False otherwise
        """
        if self.restart_mode == RESTART_NEVER:
            return False
        if self.restart_mode == RESTART_ALWAYS:
            return True
        if self.restart_mode == RESTART_ONREBOOT:
            return reason == 'reboot'
        return False

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

    def rebooting(self):
        return self.restart_state == STATE_RESTART_BOOTING

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
        self.restart_count += 1

    def restart(self):
        """Restart the domain after it has exited.
        Reuses the domain id and console port.

        """
        try:
            self.state = STATE_VM_OK
            self.restart_check()
            self.restart_state = STATE_RESTART_BOOTING
            if self.bootloader:
                self.config = self.bootloader_config()
            self.construct(self.config)
        finally:
            self.restart_state = None

    def bootloader_config(self):
        # if we're restarting with a bootloader, we need to run it
        # FIXME: this assumes the disk is the first device and
        # that we're booting from the first disk
        blcfg = None
        # FIXME: this assumes that we want to use the first disk
        dev = sxp.child_value(self.config, "device")
        if dev:
            disk = sxp.child_value(dev, "uname")
            fn = blkdev_uname_to_file(disk)
            blcfg = bootloader(self.bootloader, fn, 1, self.vcpus)
        if blcfg is None:
            msg = "Had a bootloader specified, but can't find disk"
            log.error(msg)
            raise VmError(msg)
        config = sxp.merge(['vm', blconfig ], self.config)
        return config

    def configure_backends(self):
        """Set configuration flags if the vm is a backend for netif or blkif.
        Configure the backends to use for vbd and vif if specified.
        """
        for c in sxp.children(self.config, 'backend'):
            v = sxp.child0(c)
            name = sxp.name(v)
            if name == 'blkif':
                self.blkif_backend = True
            elif name == 'netif':
                self.netif_backend = True
            elif name == 'usbif':
                self.usbif_backend = True
            else:
                raise VmError('invalid backend type:' + str(name))

    def configure(self):
        """Configure a vm.

        """
        self.configure_fields()
        self.create_console()
        self.create_devices()
        self.create_blkif()

    def create_console(self):
        console = self.getConsole()
        if not console:
            config = ['console']
            if self.console_port:
                config.append(['console_port', self.console_port])
            console = self.createDevice('console', config)
        return console

    def getConsole(self):
        console_ctrl = self.getDeviceController("console", error=False)
        if console_ctrl:
            return console_ctrl.getDevice(0)
        return None

    def create_blkif(self):
        """Create the block device interface (blkif) for the vm.
        The vm needs a blkif even if it doesn't have any disks
        at creation time, for example when it uses NFS root.

        """
        blkif = self.getDeviceController("vbd", error=False)
        if not blkif:
            blkif = self.createDeviceController("vbd")
            backend = blkif.getBackend(0)
            backend.connect(recreate=self.recreate)

    def dom_construct(self, dom, config):
        """Construct a vm for an existing domain.

        @param dom: domain id
        @param config: domain configuration
        """
        d = dom_get(dom)
        if not d:
            raise VmError("Domain not found: %d" % dom)
        try:
            self.restore = True
            self.setdom(dom)
            self.memory = d['mem_kb']/1024
            self.construct(config)
        finally:
            self.restore = False

    def configure_fields(self):
        """Process the vm configuration fields using the registered handlers.
        """
        index = {}
        for field in sxp.children(self.config):
            field_name = sxp.name(field)
            field_index = index.get(field_name, 0)
            field_handler = get_config_handler(field_name)
            # Ignore unknown fields. Warn?
            if field_handler:
                v = field_handler(self, self.config, field, field_index)
            else:
                log.warning("Unknown config field %s", field_name)
            index[field_name] = field_index + 1

    def pgtable_size(self, memory):
        """Return the size of memory needed for 1:1 page tables for physical
           mode.

        @param memory: size in MB
        @return size in KB
        """
        if self.is_vmx:
            # Logic x86-32 specific. 
            # 1 page for the PGD + 1 pte page for 4MB of memory (rounded)
            return (1 + ((memory + 3) >> 2)) * 4
        return 0

    def mem_target_set(self, target):
        """Set domain memory target in pages.
        """
        if self.channel:
            msg = messages.packMsg('mem_request_t', { 'target' : target * (1 << 8)} )
            self.channel.writeRequest(msg)

    def shutdown(self, reason, key=0):
        msgtype = shutdown_messages.get(reason)
        if not msgtype:
            raise XendError('invalid reason:' + reason)
        extra = {}
        if reason == 'sysrq':
            extra['key'] = key
        if self.channel:
            msg = messages.packMsg(msgtype, extra)
            self.channel.writeRequest(msg)


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
    log.debug("creating linux domain with cmdline: %s" %(cmdline,))
    vm.create_domain("linux", kernel, ramdisk, cmdline)
    return vm

def vm_image_plan9(vm, image):
    """Create a VM for a Plan 9 image.

    name      vm name
    memory    vm memory
    image     image config

    returns vm 
    """
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
    ramdisk = sxp.child_value(image, "ramdisk", '')
    vm.create_domain("plan9", kernel, ramdisk, cmdline)
    return vm
    
def vm_image_vmx(vm, image):
    """Create a VM for the VMX environment.

    @param name:      vm name
    @param memory:    vm memory
    @param image:     image config
    @return: vm
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
    memmap = sxp.child_value(vm.config, "memmap", '')
    memmap = sxp.parse(open(memmap))[0]
    from xen.util.memmap import memmap_parse
    memmap = memmap_parse(memmap)
    vm.create_domain("vmx", kernel, ramdisk, cmdline, memmap)
    return vm

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

#============================================================================
# Register image handlers.
add_image_handler('linux', vm_image_linux)
add_image_handler('plan9', vm_image_plan9)
add_image_handler('vmx',   vm_image_vmx)

# Ignore the fields we already handle.
add_config_handler('name',       vm_field_ignore)
add_config_handler('memory',     vm_field_ignore)
add_config_handler('cpu',        vm_field_ignore)
add_config_handler('cpu_weight', vm_field_ignore)
add_config_handler('console',    vm_field_ignore)
add_config_handler('restart',    vm_field_ignore)
add_config_handler('image',      vm_field_ignore)
add_config_handler('device',     vm_field_ignore)
add_config_handler('backend',    vm_field_ignore)
add_config_handler('vcpus',      vm_field_ignore)
add_config_handler('bootloader', vm_field_ignore)

# Register other config handlers.
add_config_handler('maxmem',     vm_field_maxmem)

#============================================================================
# Register device controllers and their device config types.

from server import console
controller.addDevControllerClass("console", console.ConsoleController)

from server import blkif
controller.addDevControllerClass("vbd", blkif.BlkifController)
add_device_handler("vbd", "vbd")

from server import netif
controller.addDevControllerClass("vif", netif.NetifController)
add_device_handler("vif", "vif")

from server import pciif
controller.addDevControllerClass("pci", pciif.PciController)
add_device_handler("pci", "pci")

from xen.xend.server import usbif
controller.addDevControllerClass("usb", usbif.UsbifController)
add_device_handler("usb", "usb")

#============================================================================
