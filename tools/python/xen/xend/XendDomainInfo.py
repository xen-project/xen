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
#============================================================================

"""Representation of a single domain.
Includes support for domain construction, using
open-ended configurations.

Author: Mike Wray <mike.wray@hp.com>

"""

import string
import os
import time
import threading

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()
from xen.util.ip import check_subnet, get_current_ipgw
from xen.util.blkif import blkdev_uname_to_file

from xen.xend.server import controller
from xen.xend.server import SrvDaemon; xend = SrvDaemon.instance()
from xen.xend.server import messages
from xen.xend.server.channel import EventChannel, channelFactory

from xen.xend import sxp
from xen.xend.PrettyPrint import prettyprintstring
from xen.xend.XendBootloader import bootloader
from xen.xend.XendLogging import log
from xen.xend.XendError import XendError, VmError
from xen.xend.XendRoot import get_component

from xen.xend.uuid import getUuid
from xen.xend.xenstore import DBVar

"""Shutdown code for poweroff."""
DOMAIN_POWEROFF = 0

"""Shutdown code for reboot."""
DOMAIN_REBOOT   = 1

"""Shutdown code for suspend."""
DOMAIN_SUSPEND  = 2

"""Shutdown code for crash."""
DOMAIN_CRASH    = 3

"""Map shutdown codes to strings."""
shutdown_reasons = {
    DOMAIN_POWEROFF: "poweroff",
    DOMAIN_REBOOT  : "reboot",
    DOMAIN_SUSPEND : "suspend",
    DOMAIN_CRASH   : "crash",
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
STATE_VM_SUSPENDED  = "suspended"


def domain_exists(name):
    # See comment in XendDomain constructor.
    xd = get_component('xen.xend.XendDomain')
    return xd.domain_lookup_by_name(name)

def shutdown_reason(code):
    """Get a shutdown reason from a code.

    @param code: shutdown code
    @type  code: int
    @return: shutdown reason
    @rtype:  string
    """
    return shutdown_reasons.get(code, "?")

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

"""Table of handlers for devices.
Indexed by device type.
"""
device_handlers = {}

def add_device_handler(name, type):
    device_handlers[name] = type

def get_device_handler(name):
    return device_handlers[name]

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

    def create(cls, parentdb, config):
        """Create a VM from a configuration.

        @param parentdb:  parent db
        @param config    configuration
        @raise: VmError for invalid configuration
        """
        uuid = getUuid()
        db = parentdb.addChild(uuid)
        vm = cls(db)
        vm.construct(config)
        vm.saveToDB(sync=True)

        return vm

    create = classmethod(create)

    def recreate(cls, db, info):
        """Create the VM object for an existing domain.

        @param db:        domain db
        @param info:      domain info from xc
        """
        dom = info['dom']
        vm = cls(db)
        vm.setdom(dom)
        db.readDB()
        vm.importFromDB()
        config = vm.config
        log.debug('info=' + str(info))
        log.debug('config=' + prettyprintstring(config))

        vm.memory = info['mem_kb']/1024
        vm.target = info['mem_kb'] * 1024

        if config:
            try:
                vm.recreate = True
                vm.construct(config)
            finally:
                vm.recreate = False
        else:
            vm.setName("Domain-%d" % dom)

        vm.exportToDB(save=True)
        return vm

    recreate = classmethod(recreate)

    def restore(cls, parentdb, config, uuid):
        """Create a domain and a VM object to do a restore.

        @param parentdb:  parent db
        @param config:    domain configuration
        @param uuid:      uuid to use
        """
        db = parentdb.addChild(uuid)
        vm = cls(db)
        ssidref = int(sxp.child_value(config, 'ssidref'))
        log.debug('restoring with ssidref='+str(ssidref))
        id = xc.domain_create(ssidref = ssidref)
        vm.setdom(id)
        try:
            vm.restore = True
            vm.construct(config)
        finally:
            vm.restore = False
        vm.exportToDB(save=True, sync=True)
        return vm

    restore = classmethod(restore)

    __exports__ = [
        DBVar('id',            ty='int'),
        DBVar('name',          ty='str'),
        DBVar('uuid',          ty='str'),
        DBVar('config',        ty='sxpr'),
        DBVar('start_time',    ty='float'),
        DBVar('state',         ty='str'),
        DBVar('store_mfn',     ty='long'),
        DBVar('restart_mode',  ty='str'),
        DBVar('restart_state', ty='str'),
        DBVar('restart_time',  ty='float'),
        DBVar('restart_count', ty='int'),
        DBVar('target',        ty='long', path="memory/target"),
        DBVar('device_model_pid', ty='int'),
        ]
    
    def __init__(self, db):
        self.db = db
        self.uuid = db.getName()

        self.recreate = 0
        self.restore = 0
        
        self.config = None
        self.id = None
        self.cpu_weight = 1
        self.start_time = None
        self.name = None
        self.memory = None
        self.ssidref = None
        self.image = None

        self.target = None

        self.channel = None
        self.store_channel = None
        self.store_mfn = None
        self.controllers = {}
        
        self.info = None
        self.blkif_backend = False
        self.netif_backend = False
        #todo: state: running, suspended
        self.state = STATE_VM_OK
        self.state_updated = threading.Condition()
        self.shutdown_pending = None

        #todo: set to migrate info if migrating
        self.migrate = None
        
        self.restart_mode = RESTART_ONREBOOT
        self.restart_state = None
        self.restart_time = None
        self.restart_count = 0
        
        self.vcpus = 1
        self.vcpusdb = {}
        self.bootloader = None
        self.device_model_pid = 0

    def setDB(self, db):
        self.db = db

    def saveToDB(self, save=False, sync=False):
        self.db.saveDB(save=save, sync=sync)

    def exportToDB(self, save=False, sync=False):
        if self.channel:
            self.channel.saveToDB(self.db.addChild("channel"), save=save)
        if self.store_channel:
            self.store_channel.saveToDB(self.db.addChild("store_channel"),
                                        save=save)
        if self.image:
            self.image.exportToDB(save=save, sync=sync)
        self.db.exportToDB(self, fields=self.__exports__, save=save, sync=sync)

    def importFromDB(self):
        self.db.importFromDB(self, fields=self.__exports__)
        self.store_channel = self.eventChannel("store_channel")

    def setdom(self, dom):
        """Set the domain id.

        @param dom: domain id
        """
        self.id = int(dom)
        #self.db.id = self.id

    def getDomain(self):
        return self.id

    def setName(self, name):
        self.name = name
        self.db.name = self.name

    def getName(self):
        return self.name

    def getChannel(self):
        return self.channel

    def getStoreChannel(self):
        return self.store_channel

    def update(self, info):
        """Update with  info from xc.domain_getinfo().
        """
        self.info = info
        self.memory = self.info['mem_kb'] / 1024
        self.ssidref = self.info['ssidref']
        self.target = self.info['mem_kb'] * 1024

    def state_set(self, state):
        self.state_updated.acquire()
        if self.state != state:
            self.state = state
            self.state_updated.notifyAll()
        self.state_updated.release()
        self.saveToDB()

    def state_wait(self, state):
        self.state_updated.acquire()
        while self.state != state:
            self.state_updated.wait()
        self.state_updated.release()

    def __str__(self):
        s = "<domain"
        s += " id=" + str(self.id)
        s += " name=" + self.name
        s += " memory=" + str(self.memory)
        s += " ssidref=" + str(self.ssidref)
        s += ">"
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

    def createDevice(self, type, devconfig, change=False):
        ctrl = self.findDeviceController(type)
        return ctrl.createDevice(devconfig, recreate=self.recreate,
                                 change=change)

    def configureDevice(self, type, id, devconfig):
        ctrl = self.getDeviceController(type)
        return ctrl.configureDevice(id, devconfig)

    def destroyDevice(self, type, id, change=False, reboot=False):
        ctrl = self.getDeviceController(type)
        return ctrl.destroyDevice(id, change=change, reboot=reboot)

    def deleteDevice(self, type, id):
        ctrl = self.getDeviceController(type)
        return ctrl.deleteDevice(id)

    def getDevice(self, type, id, error=True):
        ctrl = self.getDeviceController(type)
        return ctrl.getDevice(id, error=error)
        
    def getDeviceIds(self, type):
        ctrl = self.getDeviceController(type)
        return ctrl.getDeviceIds()
    
    def getDeviceSxprs(self, type):
        ctrl = self.getDeviceController(type)
        return ctrl.getDeviceSxprs()

    def sxpr(self):
        sxpr = ['domain',
                ['id', self.id],
                ['name', self.name],
                ['memory', self.memory],
                ['ssidref', self.ssidref],
                ['target', self.target] ]
        if self.uuid:
            sxpr.append(['uuid', self.uuid])
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
            # build a string, using '|' to seperate items, show only up
            # to number of vcpus in domain, and trim the trailing '|'
            sxpr.append(['vcpu_to_cpu', ''.join(map(lambda x: str(x)+'|',
                        self.info['vcpu_to_cpu'][0:self.info['vcpus']]))[:-1]])
            
        if self.start_time:
            up_time =  time.time() - self.start_time  
            sxpr.append(['up_time', str(up_time) ])
            sxpr.append(['start_time', str(self.start_time) ])

        if self.channel:
            sxpr.append(self.channel.sxpr())
        if self.store_channel:
            sxpr.append(self.store_channel.sxpr())
        if self.store_mfn:
            sxpr.append(['store_mfn', self.store_mfn])

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
        if self.device_model_pid:
            sxpr.append(['device_model_pid',self.device_model_pid])
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
        if not self.id or (dominfo.id != self.id):
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
            self.setName(sxp.child_value(config, 'name'))
            self.check_name(self.name)
            self.init_image()
            self.configure_cpus(config)
            self.init_domain()
            self.register_domain()
            self.configure_bootloader()

            # Create domain devices.
            self.configure_backends()
            self.configure_restart()
            self.construct_image()
            self.configure()
            self.exportToDB(save=True)
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
        self.exportToDB(save=True)

    def configure_cpus(self, config):
        try:
            self.cpu_weight = float(sxp.child_value(config, 'cpu_weight', '1'))
        except:
            raise VmError('invalid cpu weight')
        self.memory = int(sxp.child_value(config, 'memory'))
        if self.memory is None:
            raise VmError('missing memory size')
        self.target = self.memory * (1 << 20)
        self.ssidref = int(sxp.child_value(config, 'ssidref'))
        cpu = sxp.child_value(config, 'cpu')
        if self.recreate and self.id and cpu is not None and int(cpu) >= 0:
            xc.domain_pincpu(self.id, 0, 1<<int(cpu))
        try:
            image = sxp.child_value(self.config, 'image')
            vcpus = sxp.child_value(image, 'vcpus')
            if vcpus:
                self.vcpus = int(vcpus)
        except:
            raise VmError('invalid vcpus value')

    def exportVCPUSToDB(self, vcpus):
        for v in range(0,vcpus):
            path = "/cpu/%d"%(v)
            if not self.vcpusdb.has_key(path):
                self.vcpusdb[path] = self.db.addChild(path)
            db = self.vcpusdb[path]
            log.debug("writing key availability=online to path %s in store"%(path))
            db['availability'] = "online"
            db.saveDB(save=True)

    def init_image(self):
        """Create boot image handler for the domain.
        """
        image = sxp.child_value(self.config, 'image')
        if image is None:
            raise VmError('missing image')
        self.image = ImageHandler.create(self, image)

    def construct_image(self):
        """Construct the boot image for the domain.
        """
        self.create_channel()
        self.image.createImage()
        self.exportToDB()
        if self.store_channel:
            self.db.introduceDomain(self.id,
                                    self.store_mfn,
                                    self.store_channel)
        # get the configured value of vcpus and update store
        self.exportVCPUSToDB(self.vcpus)

    def delete(self):
        """Delete the vm's db.
        """
        if dom_get(self.id):
            return
        self.id = None
        self.saveToDB(sync=True)
        try:
            # Todo: eventually will have to wait for devices to signal
            # destruction before can delete the db.
            if self.db:
                self.db.delete()
        except Exception, ex:
            log.warning("error in domain db delete: %s", ex)
            pass

    def destroy_domain(self):
        """Destroy the vm's domain.
        The domain will not finally go away unless all vm
        devices have been released.
        """
        if self.id is None:
            return
        try:
            xc.domain_destroy(dom=self.id)
        except Exception, err:
            log.exception("Domain destroy failed: %s", self.name)

    def cleanup(self):
        """Cleanup vm resources: release devices.
        """
        self.state = STATE_VM_TERMINATED
        self.release_devices()
        if self.channel:
            try:
                self.channel.close()
                self.channel = None
            except:
                pass
        if self.store_channel:
            try:
                self.store_channel.close()
                self.store_channel = None
            except:
                pass
            try:
                self.db.releaseDomain(self.id)
            except Exception, ex:
                log.warning("error in domain release on xenstore: %s", ex)
                pass
        if self.image:
            try:
                self.device_model_pid = 0
                self.image.destroy()
                self.image = None
            except:
                pass

    def destroy(self):
        """Clenup vm and destroy domain.
        """
        self.cleanup()
        self.destroy_domain()
        self.saveToDB()
        return 0

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

    def show(self):
        """Print virtual machine info.
        """
        print "[VM dom=%d name=%s memory=%d ssidref=%d" % (self.id, self.name, self.memory, self.ssidref)
        print "image:"
        sxp.show(self.image)
        print "]"

    def init_domain(self):
        """Initialize the domain memory.
        """
        if self.recreate:
            return
        if self.start_time is None:
            self.start_time = time.time()
        try:
            cpu = int(sxp.child_value(self.config, 'cpu', '-1'))
        except:
            raise VmError('invalid cpu')
        id = self.image.initDomain(self.id, self.memory, self.ssidref, cpu, self.cpu_weight)
        log.debug('init_domain> Created domain=%d name=%s memory=%d',
                  id, self.name, self.memory)
        self.setdom(id)

    def openChannel(self, key, local, remote):
        """Create a control channel to the domain.
        If saved info is available recreate the channel.
        
        @param key db key for the saved data (if any)
        @param local default local port
        @param remote default remote port
        """
        db = self.db.addChild(key)
        chan = channelFactory().restoreFromDB(db, self.id, local, remote)
        #todo: save here?
        #chan.saveToDB(db)
        return chan

    def eventChannel(self, key):
        """Create an event channel to the domain.
        If saved info is available recreate the channel.
        
        @param key db key for the saved data (if any)
        """
        db = self.db.addChild(key)
        return EventChannel.restoreFromDB(db, 0, self.id)
        
    def create_channel(self):
        """Create the channels to the domain.
        """
        self.channel = self.openChannel("channel", 0, 1)
        self.store_channel = self.eventChannel("store_channel")

    def create_configured_devices(self):
        devices = sxp.children(self.config, 'device')
        for d in devices:
            dev_config = sxp.child0(d)
            if dev_config is None:
                raise VmError('invalid device')
            dev_type = sxp.name(dev_config)
            ctrl_type = get_device_handler(dev_type)
            if ctrl_type is None:
                raise VmError('unknown device type: ' + dev_type)
            self.createDevice(ctrl_type, dev_config)
        
    def create_devices(self):
        """Create the devices for a vm.

        @raise: VmError for invalid devices
        """
        if self.rebooting():
            for ctrl in self.getDeviceControllers():
                ctrl.initController(reboot=True)
        else:
            self.create_configured_devices()
        if not self.device_model_pid:
            self.device_model_pid = self.image.createDeviceModel()

    def device_create(self, dev_config):
        """Create a new device.

        @param dev_config: device configuration
        """
        dev_type = sxp.name(dev_config)
        dev = self.createDevice(dev_type, dev_config, change=True)
        self.config.append(['device', dev.getConfig()])
        return dev.sxpr()

    def device_configure(self, dev_config, id):
        """Configure an existing device.

        @param dev_config: device configuration
        @param id:         device id
        """
        type = sxp.name(dev_config)
        dev = self.getDevice(type, id)
        old_config = dev.getConfig()
        new_config = dev.configure(dev_config, change=True)
        # Patch new config into vm config.
        new_full_config = ['device', new_config]
        old_full_config = ['device', old_config]
        old_index = self.config.index(old_full_config)
        self.config[old_index] = new_full_config
        return new_config

    def device_refresh(self, type, id):
        """Refresh a device.

        @param type: device type
        @param id:   device id
        """
        dev = self.getDevice(type, id)
        dev.refresh()
        
    def device_delete(self, type, id):
        """Destroy and remove a device.

        @param type: device type
        @param id:   device id
        """
        dev = self.getDevice(type, id)
        dev_config = dev.getConfig()
        if dev_config:
            self.config.remove(['device', dev_config])
        self.deleteDevice(type, dev.getId())

    def configure_bootloader(self):
        """Configure boot loader.
        """
        self.bootloader = sxp.child_value(self.config, "bootloader")

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
        Reuses the domain id

        """
        try:
            self.state = STATE_VM_OK
            self.shutdown_pending = None
            self.restart_check()
            self.exportToDB()
            self.restart_state = STATE_RESTART_BOOTING
            if self.bootloader:
                self.config = self.bootloader_config()
            self.construct(self.config)
            self.saveToDB()
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
        self.create_devices()
	if self.image.ostype != 'vmx':
            self.create_blkif()

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

    def mem_target_set(self, target):
        """Set domain memory target in bytes.
        """
        if target:
            self.target = target * (1 << 20)
            # Commit to XenStore immediately
            self.exportToDB()

    def vcpu_hotplug(self, vcpu, state):
        """Disable or enable VCPU in domain.
        """
        db = ""
        try:
            db = self.vcpusdb['/cpu/%d'%(vcpu)]
        except:
            log.error("Invalid VCPU")
            return

        if self.store_channel:
            if int(state) == 0:
                db['availability'] = "offline"
            else:
                db['availability'] = "online"

        db.saveDB(save=True)

    def shutdown(self, reason):
        if not reason in shutdown_reasons.values():
            raise XendError('invalid reason:' + reason)
        db = self.db.addChild("/control");
        db['shutdown'] = reason;
        db.saveDB(save=True);
        if not reason in ['suspend']:
            self.shutdown_pending = {'start':time.time(), 'reason':reason}

    def send_sysrq(self, key=0):
        db = self.db.addChild("/control");
        db['sysrq'] = '%c' % key;
        db.saveDB(save=True);        

    def shutdown_time_left(self, timeout):
        if not self.shutdown_pending:
            return 0
        return timeout - (time.time() - self.shutdown_pending['start'])

    def dom0_init_store(self):
        if not self.store_channel:
            self.store_channel = self.eventChannel("store_channel")
        self.store_mfn = xc.init_store(self.store_channel.port2)
        if self.store_mfn >= 0:
            self.db.introduceDomain(self.id, self.store_mfn,
                                    self.store_channel)
        self.exportToDB(save=True, sync=True)
        # get run-time value of vcpus and update store
        self.exportVCPUSToDB(dom_get(self.id)['vcpus'])

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
    xc.domain_setmaxmem(vm.id, maxmem_kb = maxmem * 1024)

#============================================================================
# Register image handlers.
from image import          \
     addImageHandlerClass, \
     ImageHandler,         \
     LinuxImageHandler,    \
     VmxImageHandler

addImageHandlerClass(LinuxImageHandler)
addImageHandlerClass(VmxImageHandler)

# Ignore the fields we already handle.
add_config_handler('name',       vm_field_ignore)
add_config_handler('memory',     vm_field_ignore)
add_config_handler('ssidref',    vm_field_ignore)
add_config_handler('cpu',        vm_field_ignore)
add_config_handler('cpu_weight', vm_field_ignore)
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
