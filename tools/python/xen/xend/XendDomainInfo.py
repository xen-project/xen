#===========================================================================
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
import time
import threading
import errno

import xen.lowlevel.xc
from xen.util.blkif import blkdev_uname_to_file

from xen.xend.server import SrvDaemon
from xen.xend.server.channel import EventChannel

from xen.xend import sxp
from xen.xend.PrettyPrint import prettyprintstring
from xen.xend.XendBootloader import bootloader
from xen.xend.XendLogging import log
from xen.xend.XendError import XendError, VmError
from xen.xend.XendRoot import get_component

from xen.xend.uuid import getUuid
from xen.xend.xenstore import DBVar
from xen.xend.xenstore.xstransact import xstransact
from xen.xend.xenstore.xsutil import IntroduceDomain

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

"""Flag for a block device backend domain."""
SIF_BLK_BE_DOMAIN = (1<<4)

"""Flag for a net device backend domain."""
SIF_NET_BE_DOMAIN = (1<<5)

"""Flag for a TPM device backend domain."""
SIF_TPM_BE_DOMAIN = (1<<7)


xc = xen.lowlevel.xc.new()


xend = SrvDaemon.instance()


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

def dom_get(dom):
    """Get info from xen for an existing domain.

    @param dom: domain id
    @return: info or None
    """
    try:
        domlist = xc.domain_getinfo(dom, 1)
        if domlist and dom == domlist[0]['dom']:
            return domlist[0]
    except Exception, err:
        # ignore missing domain
        log.exception("domain_getinfo(%d) failed, ignoring", dom)
    return None

class XendDomainInfo:
    """Virtual machine object."""

    """Minimum time between domain restarts in seconds.
    """
    MINIMUM_RESTART_TIME = 20


    def create(cls, parentdbpath, config):
        """Create a VM from a configuration.

        @param parentdbpath:  parent db path
        @param config    configuration
        @raise: VmError for invalid configuration
        """

        log.debug("XendDomainInfo.create(%s, ...)", parentdbpath)
        
        vm = cls(getUuid(), parentdbpath, cls.parseConfig(config))
        vm.construct()
        return vm

    create = classmethod(create)


    def recreate(cls, uuid, dompath, info):
        """Create the VM object for an existing domain.

        @param dompath:   The path to all domain information
        @param info:      domain info from xc
        """

        log.debug("XendDomainInfo.recreate(%s, %s, ...)", uuid, dompath)

        # ??? vm.setDomid(domid)
#        vm.name, vm.start_time = vm.gatherVm(("name", str),
#                                             ("start-time", float))
#        config = vm.config
#        log.debug('info=' + str(info))
#        log.debug('config=' + prettyprintstring(config))

#        vm.memory = info['mem_kb'] / 1024
#        vm.target = info['mem_kb'] * 1024


        # Parse the configuration in the store, but allow the info we've
        # been given (from xc) to override it.
        path = "%s/%s" % (dompath, uuid)
        
        config = xstransact.Read(path, 'config')
        if config:
            temp_info = cls.parseConfig(config)
            temp_info.update(info)
            info = temp_info
            
        return cls(uuid, dompath, info)

    recreate = classmethod(recreate)


    def restore(cls, parentdbpath, config, uuid = None):
        """Create a domain and a VM object to do a restore.

        @param parentdbpath:  parent db
        @param config:    domain configuration
        @param uuid:      uuid to use
        """
        
        log.debug("XendDomainInfo.restore(%s, ..., %s)", parentdbpath, uuid)

        if not uuid:
            uuid = getUuid()

        try:
            ssidref = int(sxp.child_value(config, 'ssidref'))
        except TypeError, exn:
            raise VmError('Invalid ssidref in config: %s' % exn)

        log.debug('restoring with ssidref = %d' % ssidref)

        vm = cls(uuid, parentdbpath, cls.parseConfig(config),
                 xc.domain_create(ssidref = ssidref))
        vm.clear_shutdown()
        return vm

    restore = classmethod(restore)


    def parseConfig(cls, config):
        def get_cfg(name, default = None):
            return sxp.child_value(config, name, default)

        def int_get_cfg(name):
            val = get_cfg(name)
            if val:
                return int(val)
            else:
                return None

        def flo_get_cfg(name):
            val = get_cfg(name)
            if val:
                return float(val)
            else:
                return None


        log.debug("parseConfig: config is %s" % str(config))


        result = {}
        imagecfg = "()"
        try:
            result['name']         =     get_cfg('name')
            result['ssidref']      = int_get_cfg('ssidref')
            result['memory']       = int_get_cfg('memory')
            result['maxmem']       = int_get_cfg('maxmem')
            result['cpu']          = int_get_cfg('cpu')
            result['cpu_weight']   = flo_get_cfg('cpu_weight')
            result['bootloader']   =     get_cfg('bootloader')
            result['restart_mode'] =     get_cfg('restart')

            imagecfg = get_cfg('image')

            if imagecfg:
                result['image'] = imagecfg
                result['vcpus'] = int(sxp.child_value(imagecfg, 'vcpus', 1))
            else:
                result['vcpus'] = 1

            result['backend'] = []
            for c in sxp.children(config, 'backend'):
                result['backend'].append(sxp.name(sxp.child0(c)))

            result['device'] = []
            for d in sxp.children(config, 'device'):
                c = sxp.child0(d)
                result['device'].append((sxp.name(c), c))


            log.debug("parseConfig: result is %s" % str(result))
            return result

        except TypeError, exn:
            raise VmError(
                'Invalid ssidref / memory / cpu / cpu_weight / vcpus value: %s %s %s %s %s: %s' %
                (get_cfg('ssidref'),
                 get_cfg('memory'),
                 get_cfg('cpu'),
                 get_cfg('cpu_weight'),
                 sxp.child_value(imagecfg, 'vcpus', 1),
                 str(exn)))

    parseConfig = classmethod(parseConfig)

    
    def __init__(self, uuid, parentpath, info, domid = None):

        self.uuid = uuid
        self.info = info

        self.path = parentpath + "/" + uuid

        if domid:
            self.domid = domid
        elif 'dom' in info:
            self.domid = int(info['dom'])
        else:
            self.domid = None

        self.validateInfo()

        self.start_time = None
        self.image = None

        self.store_channel = None
        self.store_mfn = None
        self.console_channel = None
        self.console_mfn = None
        
        #todo: state: running, suspended
        self.state = STATE_VM_OK
        self.state_updated = threading.Condition()
        self.shutdown_pending = None

        #todo: set to migrate info if migrating
        self.migrate = None
        
        self.restart_state = None
        self.restart_time = None
        self.restart_count = 0
        
        self.device_model_pid = 0

        self.writeVm("uuid", self.uuid)
        self.storeDom("vm", self.path)


    def validateInfo(self):
        """Validate and normalise the info block.  This has either been parsed
        by parseConfig, or received from xc through recreate.
        """
        def defaultInfo(name, val):
            if name not in self.info or self.info[name] is None:
                self.info[name] = val()

    
        try:
            defaultInfo('name',         lambda: "Domain-%d" % self.domid)
            defaultInfo('memory',       lambda: self.info['mem_kb'] / 1024)
            defaultInfo('maxmem',       lambda: self.info['memory'])
            defaultInfo('restart_mode', lambda: RESTART_ONREBOOT)
            defaultInfo('cpu_weight',   lambda: 1.0)
            defaultInfo('bootloader',   lambda: None)
            defaultInfo('backend',      lambda: [])
            defaultInfo('device',       lambda: [])

            #        vm.target = info['mem_kb'] * 1024

            # !!! Consistency checks have the possibility of going wrong if
            # xen updates us with a setting which should stay consistent with
            # another.  We should be storing only one value instead.

            # Validate the given backend names.
            for s in self.info['backend']:
                if s not in backendFlags:
                    raise VmError('Invalid backend type: %s' % s)

            for (n, c) in self.info['device']:
                if not n or not c or n not in controllerClasses:
                    raise VmError('invalid device (%s, %s)' %
                                  (str(n), str(c)))

            if self.info['restart_mode'] not in restart_modes:
                raise VmError('invalid restart mode: ' +
                              str(self.info['restart_mode']))

            if self.info['memory'] <= 0:
                # !!! memory / mem_kb consistency check
                raise VmError('Invalid memory size: %d', self.info['memory'])

            if 'cpumap' not in self.info:
                if [self.info['vcpus'] == 1]:
                    self.info['cpumap'] = [1];
                else:
                    raise VmError('Cannot create CPU map')

        except KeyError, exn:
            raise VmError('Unspecified domain detail: %s' % str(exn))


    def readVm(self, *args):
        return xstransact.Read(self.path, *args)

    def writeVm(self, *args):
        return xstransact.Write(self.path, *args)

    def removeVm(self, *args):
        return xstransact.Remove(self.path, *args)

    def gatherVm(self, *args):
        return xstransact.Gather(self.path, *args)

    def storeVm(self, *args):
        return xstransact.Store(self.path, *args)

    def readDom(self, *args):
        return xstransact.Read(self.path, *args)

    def writeDom(self, *args):
        return xstransact.Write(self.path, *args)

    def removeDom(self, *args):
        return xstransact.Remove(self.path, *args)

    def gatherDom(self, *args):
        return xstransact.Gather(self.path, *args)

    def storeDom(self, *args):
        return xstransact.Store(self.path, *args)


    def exportToDB(self, save=False):
        to_store = {
            'id':               str(self.domid),
            'uuid':             self.uuid,
            'config':           sxp.to_string(self.sxpr()),

            'start_time':       str(self.start_time),
            'state':            self.state,
            'restart_time':     str(self.restart_time),
            'restart_count':    str(self.restart_count),
            'device_model_pid': str(self.device_model_pid)
            }

        for (k, v) in self.info.items():
            to_store[k] = str(v)

        log.debug("Storing %s" % str(to_store))

        self.writeVm(to_store)


    def setDomid(self, domid):
        """Set the domain id.

        @param dom: domain id
        """
        self.domid = domid
        self.storeDom("domid", self.domid)

    def getDomain(self):
        return self.domid

    def setName(self, name):
        self.info['name'] = name
        self.storeVm("name", name)

    def getName(self):
        return self.info['name']

    def getPath(self):
        return self.path

    def getUuid(self):
        return self.uuid

    def getVCpuCount(self):
        return self.info['vcpus']

    def getSsidref(self):
        return self.info['ssidref']

    def getMemoryTarget(self):
        """Get this domain's target memory size, in MiB."""
        return self.info['memory']

    def setStoreRef(self, ref):
        self.store_mfn = ref
        self.storeDom("store/ring-ref", ref)


    def getBackendFlags(self):
        return reduce(lambda x, y: x | backendFlags[y],
                      self.info['backend'], 0)


    def closeStoreChannel(self):
        """Close the store channel, if any.  Nothrow guarantee."""
        
        try:
            if self.store_channel:
                try:
                    self.store_channel.close()
                    self.removeDom("store/port")
                finally:
                    self.store_channel = None
        except Exception, exn:
            log.exception(exn)


    def setConsoleRef(self, ref):
        self.console_mfn = ref
        self.storeDom("console/ring-ref", ref)

    def setMemoryTarget(self, target):
        self.storeDom("memory/target", target)


    def update(self, info = None):
        """Update with info from xc.domain_getinfo().
        """

        if not info:
            info = dom_get(self.domid)
            if not info:
                return
            
        self.info.update(info)
        self.validateInfo()


    def state_set(self, state):
        self.state_updated.acquire()
        if self.state != state:
            self.state = state
            self.state_updated.notifyAll()
        self.state_updated.release()
        self.exportToDB()

    def state_wait(self, state):
        self.state_updated.acquire()
        while self.state != state:
            self.state_updated.wait()
        self.state_updated.release()

    def __str__(self):
        s = "<domain"
        s += " id=" + str(self.domid)
        s += " name=" + self.info['name']
        s += " memory=" + str(self.info['memory'])
        s += " ssidref=" + str(self.info['ssidref'])
        s += ">"
        return s

    __repr__ = __str__


    def getDeviceController(self, name):
        if name not in controllerClasses:
            raise XendError("unknown device type: " + str(name))

        return controllerClasses[name](self)


    def createDevice(self, deviceClass, devconfig):
        return self.getDeviceController(deviceClass).createDevice(devconfig)


    def configureDevice(self, deviceClass, devid, devconfig):
        return self.getDeviceController(deviceClass).configureDevice(
            devid, devconfig)


    def destroyDevice(self, deviceClass, devid):
        return self.getDeviceController(deviceClass).destroyDevice(devid)


    def sxpr(self):
        sxpr = ['domain',
                ['domid', self.domid],
                ['name', self.info['name']],
                ['memory', self.info['memory']],
                ['ssidref', self.info['ssidref']]]
#        ,                ['target', self.target] ]
        if self.uuid:
            sxpr.append(['uuid', self.uuid])
        if self.info:
            sxpr.append(['maxmem', self.info['maxmem']])

            def stateChar(name):
                if name in self.info:
                    if self.info[name]:
                        return name[0]
                    else:
                        return '-'
                else:
                    return '?'

            state = reduce(
                lambda x, y: x + y,
                map(stateChar,
                    ['running', 'blocked', 'paused', 'shutdown', 'crashed']))

            sxpr.append(['state', state])
            if 'shutdown' in self.info and self.info['shutdown']:
                reason = shutdown_reason(self.info['shutdown_reason'])
                sxpr.append(['shutdown_reason', reason])
            if 'cpu_time' in self.info:
                sxpr.append(['cpu_time', self.info['cpu_time']/1e9])    
            sxpr.append(['vcpus', self.info['vcpus']])
            sxpr.append(['cpumap', self.info['cpumap']])
            if 'vcpu_to_cpu' in self.info:
                sxpr.append(['cpu', self.info['vcpu_to_cpu'][0]])
                # build a string, using '|' to separate items, show only up
                # to number of vcpus in domain, and trim the trailing '|'
                sxpr.append(['vcpu_to_cpu', ''.join(map(lambda x: str(x)+'|',
                            self.info['vcpu_to_cpu'][0:self.info['vcpus']]))[:-1]])
            
        if self.start_time:
            up_time =  time.time() - self.start_time  
            sxpr.append(['up_time', str(up_time) ])
            sxpr.append(['start_time', str(self.start_time) ])

        if self.store_channel:
            sxpr.append(self.store_channel.sxpr())
        if self.store_mfn:
            sxpr.append(['store_mfn', self.store_mfn])
        if self.console_channel:
            sxpr.append(['console_channel', self.console_channel.sxpr()])
        if self.console_mfn:
            sxpr.append(['console_mfn', self.console_mfn])
# already in (devices)
#        console = self.getConsole()
#        if console:
#            sxpr.append(console.sxpr())

        if self.restart_count:
            sxpr.append(['restart_count', self.restart_count])
        if self.restart_state:
            sxpr.append(['restart_state', self.restart_state])
        if self.restart_time:
            sxpr.append(['restart_time', str(self.restart_time)])
#        if self.config:
#            sxpr.append(['config', self.config])
        return sxpr

    def check_name(self, name):
        """Check if a vm name is valid. Valid names contain alphabetic characters,
        digits, or characters in '_-.:/+'.
        The same name cannot be used for more than one vm at the same time.

        @param name: name
        @raise: VMerror if invalid
        """
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
        if not self.domid or (dominfo.domid != self.domid):
            raise VmError('vm name clash: ' + name)
        
    def construct(self):
        """Construct the vm instance from its configuration.

        @param config: configuration
        @raise: VmError on error
        """
        # todo - add support for scheduling params?
        try:
            # Initial domain create.
            self.check_name(self.info['name'])
            self.setName(self.info['name'])

            if 'image' not in self.info:
                raise VmError('Missing image in configuration')

            self.image = ImageHandler.create(self, self.info['image'])

            self.setMemoryTarget(self.info['memory'] * (1 << 20))

            log.error('%s %s %s %s %s',
                      str(self.domid),
                      str(self.info['memory']),
                      str(self.info['ssidref']),
                      str(self.info['cpu']),
                      str(self.info['cpu_weight']))

            self.setDomid(self.image.initDomain(self.domid,
                                                self.info['memory'],
                                                self.info['ssidref'],
                                                self.info['cpu'],
                                                self.info['cpu_weight'],
                                                self.info['bootloader']))
            
            if self.start_time is None:
                self.start_time = time.time()
                self.storeVm(("start-time", self.start_time))

            log.debug('init_domain> Created domain=%d name=%s memory=%d',
                      self.domid, self.info['name'], self.info['memory'])

            self.register_domain()

            # Create domain devices.
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

    def configure_vcpus(self, vcpus):
        d = {}
        for v in range(0, vcpus):
            d["cpu/%d/availability" % v] = "online"
        self.writeVm(d)

    def construct_image(self):
        """Construct the boot image for the domain.
        """
        self.create_channel()
        self.image.createImage()
        self.exportToDB()
        if self.store_channel and self.store_mfn >= 0:
            IntroduceDomain(self.domid, self.store_mfn,
                            self.store_channel.port1, self.path)
        # get the configured value of vcpus and update store
        self.configure_vcpus(self.info['vcpus'])


    def delete(self):
        """Delete the vm's db.
        """
        try:
            xstransact.Remove(self.path, 'id')
        except Exception, ex:
            log.warning("error in domain db delete: %s", ex)


    def destroy_domain(self):
        """Destroy the vm's domain.
        The domain will not finally go away unless all vm
        devices have been released.
        """
        if self.domid is None:
            return
        try:
            xc.domain_destroy(dom=self.domid)
        except Exception, err:
            log.exception("Domain destroy failed: %s", self.info['name'])

    def cleanup(self):
        """Cleanup vm resources: release devices.
        """
        self.state = STATE_VM_TERMINATED
        self.release_devices()
        self.closeStoreChannel()
        if self.console_channel:
            # notify processes using this console?
            try:
                self.console_channel.close()
                self.console_channel = None
            except:
                pass
        if self.image:
            try:
                self.image.destroy()
                self.image = None
            except:
                pass

    def destroy(self):
        """Cleanup vm and destroy domain.
        """

        log.debug("XendDomainInfo.destroy")

        self.destroy_domain()
        self.cleanup()
        self.exportToDB()
        return 0

    def is_terminated(self):
        """Check if a domain has been terminated.
        """
        return self.state == STATE_VM_TERMINATED

    def release_devices(self):
        """Release all vm devices.
        """

        t = xstransact("%s/device" % self.path)

        for n in controllerClasses.keys():
            for d in t.list(n):
                try:
                    t.remove(d)
                except ex:
                    # Log and swallow any exceptions in removal -- there's
                    # nothing more we can do.
                    log.exception(
                        "Device release failed: %s; %s; %s; %s" %
                        (self.info['name'], n, d, str(ex)))
        t.commit()


    def show(self):
        """Print virtual machine info.
        """
        print "[VM dom=%d name=%s memory=%d ssidref=%d" % (self.domid, self.info['name'], self.info['memory'], self.info['ssidref'])
        print "image:"
        sxp.show(self.image)
        print "]"

    def eventChannel(self, path=None):
        """Create an event channel to the domain.
        
        @param path under which port is stored in db
        """
        port = 0
        if path:
            try:
                port = int(self.readDom(path))
            except:
                # if anything goes wrong, assume the port was not yet set
                pass
        ret = EventChannel.interdomain(0, self.domid, port1=port, port2=0)
        self.storeDom(path, ret.port1)
        return ret
        
    def create_channel(self):
        """Create the channels to the domain.
        """
        self.store_channel = self.eventChannel("store/port")
        self.console_channel = self.eventChannel("console/port")

    def create_configured_devices(self):
        for (n, c) in self.info['device']:
            self.createDevice(n, c)


    def create_devices(self):
        """Create the devices for a vm.

        @raise: VmError for invalid devices
        """
        if not self.rebooting():
            self.create_configured_devices()
        self.image.createDeviceModel()

    def device_create(self, dev_config):
        """Create a new device.

        @param dev_config: device configuration
        """
        dev_type = sxp.name(dev_config)
        devid = self.createDevice(dev_type, dev_config)
#        self.config.append(['device', dev.getConfig()])
        return self.getDeviceController(dev_type).sxpr(devid)


    def device_configure(self, dev_config, devid):
        """Configure an existing device.
        @param dev_config: device configuration
        @param devid:      device id
        """
        deviceClass = sxp.name(dev_config)
        self.configureDevice(deviceClass, devid, dev_config)


    def restart_needed(self, reason):
        """Determine if the vm needs to be restarted when shutdown
        for the given reason.

        @param reason: shutdown reason
        @return True if needs restart, False otherwise
        """
        if self.info['restart_mode'] == RESTART_NEVER:
            return False
        if self.info['restart_mode'] == RESTART_ALWAYS:
            return True
        if self.info['restart_mode'] == RESTART_ONREBOOT:
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
                msg = 'VM %s restarting too fast' % self.info['name']
                log.error(msg)
                raise VmError(msg)
        self.restart_time = tnow
        self.restart_count += 1

    def restart(self):
        """Restart the domain after it has exited.
        Reuses the domain id

        """
        try:
            self.clear_shutdown()
            self.state = STATE_VM_OK
            self.shutdown_pending = None
            self.restart_check()
            self.exportToDB()
            self.restart_state = STATE_RESTART_BOOTING
            self.configure_bootloader()
            self.construct()
            self.exportToDB()
        finally:
            self.restart_state = None

    def configure_bootloader(self):
        if not self.info['bootloader']:
            return
        # if we're restarting with a bootloader, we need to run it
        # FIXME: this assumes the disk is the first device and
        # that we're booting from the first disk
        blcfg = None
        # FIXME: this assumes that we want to use the first disk
        dev = sxp.child_value(self.config, "device")
        if dev:
            disk = sxp.child_value(dev, "uname")
            fn = blkdev_uname_to_file(disk)
            blcfg = bootloader(self.info['bootloader'], fn, 1, self.info['vcpus'])
        if blcfg is None:
            msg = "Had a bootloader specified, but can't find disk"
            log.error(msg)
            raise VmError(msg)
        self.config = sxp.merge(['vm', ['image', blcfg]], self.config)


    def configure(self):
        """Configure a vm.

        """
        self.configure_maxmem()
        self.create_devices()
        self.create_blkif()

    def create_blkif(self):
        """Create the block device interface (blkif) for the vm.
        The vm needs a blkif even if it doesn't have any disks
        at creation time, for example when it uses NFS root.

        """
        return


    def configure_maxmem(self):
        xc.domain_setmaxmem(self.domid,
                            maxmem_kb = self.info['maxmem'] * 1024)


    def vcpu_hotplug(self, vcpu, state):
        """Disable or enable VCPU in domain.
        """
        if vcpu > self.info['vcpus']:
            log.error("Invalid VCPU %d" % vcpu)
            return
        if int(state) == 0:
            availability = "offline"
        else:
            availability = "online"
        self.storeVm("cpu/%d/availability" % vcpu, availability)

    def shutdown(self, reason):
        if not reason in shutdown_reasons.values():
            raise XendError('invalid reason:' + reason)
        self.storeVm("control/shutdown", reason)
        if not reason in ['suspend']:
            self.shutdown_pending = {'start':time.time(), 'reason':reason}

    def clear_shutdown(self):
        self.removeVm("control/shutdown")

    def send_sysrq(self, key=0):
        self.storeVm("control/sysrq", '%c' % key)

    def shutdown_time_left(self, timeout):
        if not self.shutdown_pending:
            return 0
        return timeout - (time.time() - self.shutdown_pending['start'])

    def dom0_init_store(self):
        if not self.store_channel:
            self.store_channel = self.eventChannel("store/port")
            if not self.store_channel:
                return
        ref = xc.init_store(self.store_channel.port2)
        if ref and ref >= 0:
            self.setStoreRef(ref)
            try:
                IntroduceDomain(self.domid, ref, self.store_channel.port1,
                                self.path)
            except RuntimeError, ex:
                if ex.args[0] == errno.EISCONN:
                    pass
                else:
                    raise
            # get run-time value of vcpus and update store
            self.configure_vcpus(dom_get(self.domid)['vcpus'])

    def dom0_enforce_vcpus(self):
        dom = 0
        # get max number of vcpus to use for dom0 from config
        from xen.xend import XendRoot
        xroot = XendRoot.instance()
        target = int(xroot.get_dom0_vcpus())
        log.debug("number of vcpus to use is %d" % (target))
   
        # target = 0 means use all processors
        if target > 0:
            # count the number of online vcpus (cpu values in v2c map >= 0)
            vcpu_to_cpu = dom_get(dom)['vcpu_to_cpu']
            vcpus_online = len(filter(lambda x: x >= 0, vcpu_to_cpu))
            log.debug("found %d vcpus online" % (vcpus_online))

            # disable any extra vcpus that are online over the requested target
            for vcpu in range(target, vcpus_online):
                log.info("enforcement is disabling DOM%d VCPU%d" % (dom, vcpu))
                self.vcpu_hotplug(vcpu, 0)



#============================================================================
# Register image handlers.

from image import          \
     addImageHandlerClass, \
     ImageHandler,         \
     LinuxImageHandler,    \
     VmxImageHandler

addImageHandlerClass(LinuxImageHandler)
addImageHandlerClass(VmxImageHandler)


#============================================================================
# Register device controllers and their device config types.

"""A map from device-class names to the subclass of DevController that
implements the device control specific to that device-class."""
controllerClasses = {}


"""A map of backend names and the corresponding flag."""
backendFlags = {}


def addControllerClass(device_class, backend_name, backend_flag, cls):
    """Register a subclass of DevController to handle the named device-class.

    @param backend_flag One of the SIF_XYZ_BE_DOMAIN constants, or None if
    no flag is to be set.
    """
    cls.deviceClass = device_class
    backendFlags[backend_name] = backend_flag
    controllerClasses[device_class] = cls


from xen.xend.server import blkif, netif, tpmif, pciif, usbif
addControllerClass('vbd',  'blkif', SIF_BLK_BE_DOMAIN, blkif.BlkifController)
addControllerClass('vif',  'netif', SIF_NET_BE_DOMAIN, netif.NetifController)
addControllerClass('vtpm', 'tpmif', SIF_TPM_BE_DOMAIN, tpmif.TPMifController)
addControllerClass('pci',  'pciif', None,              pciif.PciController)
addControllerClass('usb',  'usbif', None,              usbif.UsbifController)
