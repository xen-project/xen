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
# Copyright (C) 2005, 2006 XenSource Ltd
#============================================================================

"""Representation of a single domain.
Includes support for domain construction, using
open-ended configurations.

Author: Mike Wray <mike.wray@hp.com>

"""

import logging
import time
import threading
import re
import copy
import os
from types import StringTypes

import xen.lowlevel.xc
from xen.util import asserts
from xen.util.blkif import blkdev_uname_to_file
from xen.util import security

from xen.xend import balloon, sxp, uuid, image, arch, osdep
from xen.xend import XendOptions, XendNode, XendConfig

from xen.xend.XendConfig import scrub_password
from xen.xend.XendBootloader import bootloader, bootloader_tidy
from xen.xend.XendError import XendError, VmError
from xen.xend.XendDevices import XendDevices
from xen.xend.XendTask import XendTask
from xen.xend.xenstore.xstransact import xstransact, complete
from xen.xend.xenstore.xsutil import GetDomainPath, IntroduceDomain, ResumeDomain
from xen.xend.xenstore.xswatch import xswatch
from xen.xend.XendConstants import *
from xen.xend.XendAPIConstants import *

MIGRATE_TIMEOUT = 30.0
BOOTLOADER_LOOPBACK_DEVICE = '/dev/xvdp'

xc = xen.lowlevel.xc.xc()
xoptions = XendOptions.instance()

log = logging.getLogger("xend.XendDomainInfo")
#log.setLevel(logging.TRACE)


def create(config):
    """Creates and start a VM using the supplied configuration. 

    @param config: A configuration object involving lists of tuples.
    @type  config: list of lists, eg ['vm', ['image', 'xen.gz']]

    @rtype:  XendDomainInfo
    @return: An up and running XendDomainInfo instance
    @raise VmError: Invalid configuration or failure to start.
    """

    log.debug("XendDomainInfo.create(%s)", scrub_password(config))
    vm = XendDomainInfo(XendConfig.XendConfig(sxp_obj = config))
    try:
        vm.start()
    except:
        log.exception('Domain construction failed')
        vm.destroy()
        raise

    return vm

def create_from_dict(config_dict):
    """Creates and start a VM using the supplied configuration. 

    @param config_dict: An configuration dictionary.

    @rtype:  XendDomainInfo
    @return: An up and running XendDomainInfo instance
    @raise VmError: Invalid configuration or failure to start.
    """

    log.debug("XendDomainInfo.create_from_dict(%s)",
              scrub_password(config_dict))
    vm = XendDomainInfo(XendConfig.XendConfig(xapi = config_dict))
    try:
        vm.start()
    except:
        log.exception('Domain construction failed')
        vm.destroy()
        raise
    return vm

def recreate(info, priv):
    """Create the VM object for an existing domain.  The domain must not
    be dying, as the paths in the store should already have been removed,
    and asking us to recreate them causes problems.

    @param xeninfo: Parsed configuration
    @type  xeninfo: Dictionary
    @param priv: Is a privileged domain (Dom 0)
    @type  priv: bool

    @rtype:  XendDomainInfo
    @return: A up and running XendDomainInfo instance
    @raise VmError: Invalid configuration.
    @raise XendError: Errors with configuration.
    """

    log.debug("XendDomainInfo.recreate(%s)", scrub_password(info))

    assert not info['dying']

    xeninfo = XendConfig.XendConfig(dominfo = info)
    domid = xeninfo['domid']
    uuid1 = uuid.fromString(xeninfo['uuid'])
    needs_reinitialising = False
    
    dompath = GetDomainPath(domid)
    if not dompath:
        raise XendError('No domain path in store for existing '
                        'domain %d' % domid)

    log.info("Recreating domain %d, UUID %s. at %s" %
             (domid, xeninfo['uuid'], dompath))

    # need to verify the path and uuid if not Domain-0
    # if the required uuid and vm aren't set, then that means
    # we need to recreate the dom with our own values
    #
    # NOTE: this is probably not desirable, really we should just
    #       abort or ignore, but there may be cases where xenstore's
    #       entry disappears (eg. xenstore-rm /)
    #
    try:
        vmpath = xstransact.Read(dompath, "vm")
        if not vmpath:
            log.warn('/local/domain/%d/vm is missing. recreate is '
                     'confused, trying our best to recover' % domid)
            needs_reinitialising = True
            raise XendError('reinit')
        
        uuid2_str = xstransact.Read(vmpath, "uuid")
        if not uuid2_str:
            log.warn('%s/uuid/ is missing. recreate is confused, '
                     'trying our best to recover' % vmpath)
            needs_reinitialising = True
            raise XendError('reinit')
        
        uuid2 = uuid.fromString(uuid2_str)
        if uuid1 != uuid2:
            log.warn('UUID in /vm does not match the UUID in /dom/%d.'
                     'Trying out best to recover' % domid)
            needs_reinitialising = True
    except XendError:
        pass # our best shot at 'goto' in python :)

    vm = XendDomainInfo(xeninfo, domid, dompath, augment = True, priv = priv)
    
    if needs_reinitialising:
        vm._recreateDom()
        vm._removeVm()
        vm._storeVmDetails()
        vm._storeDomDetails()
        
    if vm.info['image']: # Only dom0 should be without an image entry when
                         # recreating, but we cope with missing ones
                         # elsewhere just in case.
        vm.image = image.create(vm,
                                vm.info,
                                vm.info['image'],
                                vm.info['devices'])
        vm.image.recreate()

    vm._registerWatches()
    vm.refreshShutdown(xeninfo)

    # register the domain in the list 
    from xen.xend import XendDomain
    XendDomain.instance().add_domain(vm)

    return vm


def restore(config):
    """Create a domain and a VM object to do a restore.

    @param config: Domain SXP configuration
    @type  config: list of lists. (see C{create})

    @rtype:  XendDomainInfo
    @return: A up and running XendDomainInfo instance
    @raise VmError: Invalid configuration or failure to start.
    @raise XendError: Errors with configuration.
    """

    log.debug("XendDomainInfo.restore(%s)", scrub_password(config))
    vm = XendDomainInfo(XendConfig.XendConfig(sxp_obj = config),
                        resume = True)
    try:
        vm.resume()
        return vm
    except:
        vm.destroy()
        raise

def createDormant(domconfig):
    """Create a dormant/inactive XenDomainInfo without creating VM.
    This is for creating instances of persistent domains that are not
    yet start.

    @param domconfig: Parsed configuration
    @type  domconfig: XendConfig object
    
    @rtype:  XendDomainInfo
    @return: A up and running XendDomainInfo instance
    @raise XendError: Errors with configuration.    
    """
    
    log.debug("XendDomainInfo.createDormant(%s)", scrub_password(domconfig))
    
    # domid does not make sense for non-running domains.
    domconfig.pop('domid', None)
    vm = XendDomainInfo(domconfig)
    return vm    

def domain_by_name(name):
    """Get domain by name

    @params name: Name of the domain
    @type   name: string
    @return: XendDomainInfo or None
    """
    from xen.xend import XendDomain
    return XendDomain.instance().domain_lookup_by_name_nr(name)


def shutdown_reason(code):
    """Get a shutdown reason from a code.

    @param code: shutdown code
    @type  code: int
    @return: shutdown reason
    @rtype:  string
    """
    return DOMAIN_SHUTDOWN_REASONS.get(code, "?")

def dom_get(dom):
    """Get info from xen for an existing domain.

    @param dom: domain id
    @type  dom: int
    @return: info or None
    @rtype: dictionary
    """
    try:
        domlist = xc.domain_getinfo(dom, 1)
        if domlist and dom == domlist[0]['domid']:
            return domlist[0]
    except Exception, err:
        # ignore missing domain
        log.trace("domain_getinfo(%d) failed, ignoring: %s", dom, str(err))
    return None


class XendDomainInfo:
    """An object represents a domain.

    @TODO: try to unify dom and domid, they mean the same thing, but
           xc refers to it as dom, and everywhere else, including
           xenstore it is domid. The best way is to change xc's
           python interface.

    @ivar info: Parsed configuration
    @type info: dictionary
    @ivar domid: Domain ID (if VM has started)
    @type domid: int or None
    @ivar vmpath: XenStore path to this VM.
    @type vmpath: string
    @ivar dompath: XenStore path to this Domain.
    @type dompath: string
    @ivar image:  Reference to the VM Image.
    @type image: xen.xend.image.ImageHandler
    @ivar store_port: event channel to xenstored
    @type store_port: int
    @ivar console_port: event channel to xenconsoled
    @type console_port: int
    @ivar store_mfn: xenstored mfn
    @type store_mfn: int
    @ivar console_mfn: xenconsoled mfn
    @type console_mfn: int
    @ivar notes: OS image notes
    @type notes: dictionary
    @ivar vmWatch: reference to a watch on the xenstored vmpath
    @type vmWatch: xen.xend.xenstore.xswatch
    @ivar shutdownWatch: reference to watch on the xenstored domain shutdown
    @type shutdownWatch: xen.xend.xenstore.xswatch
    @ivar shutdownStartTime: UNIX Time when domain started shutting down.
    @type shutdownStartTime: float or None
    @ivar state: Domain state
    @type state: enum(DOM_STATE_HALTED, DOM_STATE_RUNNING, ...)
    @ivar state_updated: lock for self.state
    @type state_updated: threading.Condition
    @ivar refresh_shutdown_lock: lock for polling shutdown state
    @type refresh_shutdown_lock: threading.Condition
    @ivar _deviceControllers: device controller cache for this domain
    @type _deviceControllers: dict 'string' to DevControllers
    """
    
    def __init__(self, info, domid = None, dompath = None, augment = False,
                 priv = False, resume = False):
        """Constructor for a domain

        @param   info: parsed configuration
        @type    info: dictionary
        @keyword domid: Set initial domain id (if any)
        @type    domid: int
        @keyword dompath: Set initial dompath (if any)
        @type    dompath: string
        @keyword augment: Augment given info with xenstored VM info
        @type    augment: bool
        @keyword priv: Is a privileged domain (Dom 0)
        @type    priv: bool
        @keyword resume: Is this domain being resumed?
        @type    resume: bool
        """

        self.info = info
        if domid == None:
            self.domid =  self.info.get('domid')
        else:
            self.domid = domid
        
        #REMOVE: uuid is now generated in XendConfig
        #if not self._infoIsSet('uuid'):
        #    self.info['uuid'] = uuid.toString(uuid.create())

        self.vmpath  = XS_VMROOT + self.info['uuid']
        self.dompath = dompath

        self.image = None
        self.store_port = None
        self.store_mfn = None
        self.console_port = None
        self.console_mfn = None

        self.vmWatch = None
        self.shutdownWatch = None
        self.shutdownStartTime = None
        self._resume = resume

        self.state = DOM_STATE_HALTED
        self.state_updated = threading.Condition()
        self.refresh_shutdown_lock = threading.Condition()

        self._deviceControllers = {}

        for state in DOM_STATES_OLD:
            self.info[state] = 0

        if augment:
            self._augmentInfo(priv)

        self._checkName(self.info['name_label'])
            

    #
    # Public functions available through XMLRPC
    #


    def start(self, is_managed = False):
        """Attempts to start the VM by do the appropriate
        initialisation if it not started.
        """
        from xen.xend import XendDomain

        if self.state == DOM_STATE_HALTED:
            try:
                XendTask.log_progress(0, 30, self._constructDomain)
                XendTask.log_progress(31, 60, self._initDomain)
                
                XendTask.log_progress(61, 70, self._storeVmDetails)
                XendTask.log_progress(71, 80, self._storeDomDetails)
                XendTask.log_progress(81, 90, self._registerWatches)
                XendTask.log_progress(91, 100, self.refreshShutdown)

                xendomains = XendDomain.instance()
                xennode = XendNode.instance()

                # save running configuration if XendDomains believe domain is
                # persistent
                if is_managed:
                    xendomains.managed_config_save(self)

                if xennode.xenschedinfo() == 'credit':
                    xendomains.domain_sched_credit_set(self.getDomid(),
                                                       self.getWeight(),
                                                       self.getCap())
            except:
                log.exception('VM start failed')
                self.destroy()
                raise
        else:
            raise XendError('VM already running')

    def resume(self):
        """Resumes a domain that has come back from suspension."""
        if self.state in (DOM_STATE_HALTED, DOM_STATE_SUSPENDED):
            try:
                self._constructDomain()
                self._storeVmDetails()
                self._createDevices()
                self._createChannels()
                self._storeDomDetails()
                self._endRestore()
            except:
                log.exception('VM resume failed')
                raise
        else:
            raise XendError('VM already running')

    def shutdown(self, reason):
        """Shutdown a domain by signalling this via xenstored."""
        log.debug('XendDomainInfo.shutdown(%s)', reason)
        if self.state in (DOM_STATE_SHUTDOWN, DOM_STATE_HALTED,):
            raise XendError('Domain cannot be shutdown')

        if self.domid == 0:
            raise XendError('Domain 0 cannot be shutdown')
        
        if reason not in DOMAIN_SHUTDOWN_REASONS.values():
            raise XendError('Invalid reason: %s' % reason)
        self._removeVm('xend/previous_restart_time')
        self.storeDom("control/shutdown", reason)

        ## shutdown hypercall for hvm domain desides xenstore write
        image_cfg = self.info.get('image', {})
        hvm = image_cfg.has_key('hvm')
        if hvm:
            for code in DOMAIN_SHUTDOWN_REASONS.keys():
                if DOMAIN_SHUTDOWN_REASONS[code] == reason:
                    break
            xc.domain_shutdown(self.domid, code)


    def pause(self):
        """Pause domain
        
        @raise XendError: Failed pausing a domain
        """
        try:
            xc.domain_pause(self.domid)
            self._stateSet(DOM_STATE_PAUSED)
        except Exception, ex:
            log.exception(ex)
            raise XendError("Domain unable to be paused: %s" % str(ex))

    def unpause(self):
        """Unpause domain
        
        @raise XendError: Failed unpausing a domain
        """
        try:
            xc.domain_unpause(self.domid)
            self._stateSet(DOM_STATE_RUNNING)
        except Exception, ex:
            log.exception(ex)
            raise XendError("Domain unable to be unpaused: %s" % str(ex))

    def send_sysrq(self, key):
        """ Send a Sysrq equivalent key via xenstored."""
        asserts.isCharConvertible(key)
        self.storeDom("control/sysrq", '%c' % key)

    def device_create(self, dev_config):
        """Create a new device.

        @param dev_config: device configuration
        @type  dev_config: SXP object (parsed config)
        """
        log.debug("XendDomainInfo.device_create: %s" % scrub_password(dev_config))
        dev_type = sxp.name(dev_config)
        dev_uuid = self.info.device_add(dev_type, cfg_sxp = dev_config)
        dev_config_dict = self.info['devices'][dev_uuid][1]
        log.debug("XendDomainInfo.device_create: %s" % scrub_password(dev_config_dict))
        dev_config_dict['devid'] = devid = \
             self._createDevice(dev_type, dev_config_dict)
        self._waitForDevice(dev_type, devid)
        return self.getDeviceController(dev_type).sxpr(devid)

    def device_configure(self, dev_sxp, devid = None):
        """Configure an existing device.
        
        @param dev_config: device configuration
        @type  dev_config: SXP object (parsed config)
        @param devid:      device id
        @type  devid:      int
        @return: Returns True if successfully updated device
        @rtype: boolean
        """

        # convert device sxp to a dict
        dev_class = sxp.name(dev_sxp)
        dev_config = {}
        for opt_val in dev_sxp[1:]:
            try:
                dev_config[opt_val[0]] = opt_val[1]
            except IndexError:
                pass

        # use DevController.reconfigureDevice to change device config
        dev_control = self.getDeviceController(dev_class)
        dev_uuid = dev_control.reconfigureDevice(devid, dev_config)

        # update XendConfig with new device info
        if dev_uuid:
            self.info.device_update(dev_uuid, dev_sxp)
            
        return True

    def waitForDevices(self):
        """Wait for this domain's configured devices to connect.

        @raise VmError: if any device fails to initialise.
        """
        for devclass in XendDevices.valid_devices():
            self.getDeviceController(devclass).waitForDevices()

    def destroyDevice(self, deviceClass, devid, force = False):
        try:
            devid = int(devid)
        except ValueError:
            # devid is not a number, let's search for it in xenstore.
            devicePath = '%s/device/%s' % (self.dompath, deviceClass)
            for entry in xstransact.List(devicePath):
                backend = xstransact.Read('%s/%s' % (devicePath, entry),
                                          "backend")
                devName = xstransact.Read(backend, "dev")
                if devName == devid:
                    # We found the integer matching our devid, use it instead
                    devid = entry
                    break
                
        return self.getDeviceController(deviceClass).destroyDevice(devid, force)

    def getDeviceSxprs(self, deviceClass):
        if self.state == DOM_STATE_RUNNING:
            return self.getDeviceController(deviceClass).sxprs()
        else:
            sxprs = []
            dev_num = 0
            for dev_type, dev_info in self.info.all_devices_sxpr():
                if dev_type == deviceClass:
                    sxprs.append([dev_num, dev_info])
                    dev_num += 1
            return sxprs


    def setMemoryTarget(self, target):
        """Set the memory target of this domain.
        @param target: In MiB.
        """
        log.debug("Setting memory target of domain %s (%d) to %d MiB.",
                  self.info['name_label'], self.domid, target)
        
        if target <= 0:
            raise XendError('Invalid memory size')
        
        self.info['memory_static_min'] = target
        if self.domid >= 0:
            self.storeVm("memory", target)
            self.storeDom("memory/target", target << 10)
        else:
            self.info['memory_dynamic_min'] = target
            xen.xend.XendDomain.instance().managed_config_save(self)

    def setMemoryMaximum(self, limit):
        """Set the maximum memory limit of this domain
        @param limit: In MiB.
        """
        log.debug("Setting memory maximum of domain %s (%d) to %d MiB.",
                  self.info['name_label'], self.domid, limit)

        if limit <= 0:
            raise XendError('Invalid memory size')

        self.info['memory_static_max'] = limit
        if self.domid >= 0:
            maxmem = int(limit) * 1024
            try:
                return xc.domain_setmaxmem(self.domid, maxmem)
            except Exception, ex:
                raise XendError(str(ex))
        else:
            self.info['memory_dynamic_max'] = limit
            xen.xend.XendDomain.instance().managed_config_save(self)


    def getVCPUInfo(self):
        try:
            # We include the domain name and ID, to help xm.
            sxpr = ['domain',
                    ['domid',      self.domid],
                    ['name',       self.info['name_label']],
                    ['vcpu_count', self.info['vcpus_number']]]

            for i in range(0, self.info['vcpus_number']):
                info = xc.vcpu_getinfo(self.domid, i)

                sxpr.append(['vcpu',
                             ['number',   i],
                             ['online',   info['online']],
                             ['blocked',  info['blocked']],
                             ['running',  info['running']],
                             ['cpu_time', info['cpu_time'] / 1e9],
                             ['cpu',      info['cpu']],
                             ['cpumap',   info['cpumap']]])

            return sxpr

        except RuntimeError, exn:
            raise XendError(str(exn))

    #
    # internal functions ... TODO: re-categorised
    # 

    def _augmentInfo(self, priv):
        """Augment self.info, as given to us through L{recreate}, with
        values taken from the store.  This recovers those values known
        to xend but not to the hypervisor.
        """
        augment_entries = XendConfig.LEGACY_XENSTORE_VM_PARAMS[:]
        if priv:
            augment_entries.remove('memory')
            augment_entries.remove('maxmem')
            augment_entries.remove('vcpus')
            augment_entries.remove('vcpu_avail')

        vm_config = self._readVMDetails([(k, XendConfig.LEGACY_CFG_TYPES[k])
                                         for k in augment_entries])
        
        # make returned lists into a dictionary
        vm_config = dict(zip(augment_entries, vm_config))
        
        for arg in augment_entries:
            xapicfg = arg
            val = vm_config[arg]
            if val != None:
                if arg in XendConfig.LEGACY_CFG_TO_XENAPI_CFG:
                    xapiarg = XendConfig.LEGACY_CFG_TO_XENAPI_CFG[arg]
                    self.info[xapiarg] = val
                else:
                    self.info[arg] = val

        # For dom0, we ignore any stored value for the vcpus fields, and
        # read the current value from Xen instead.  This allows boot-time
        # settings to take precedence over any entries in the store.
        if priv:
            xeninfo = dom_get(self.domid)
            self.info['vcpus_number'] = xeninfo['online_vcpus']
            self.info['vcpu_avail'] = (1 << xeninfo['online_vcpus']) - 1

        # read image value
        image_sxp = self._readVm('image')
        if image_sxp:
            self.info.update_with_image_sxp(sxp.from_string(image_sxp))

        # read devices
        devices = []
        for devclass in XendDevices.valid_devices():
            devconfig = self.getDeviceController(devclass).configurations()
            if devconfig:
                devices.extend(devconfig)

        if not self.info['devices'] and devices is not None:
            for device in devices:
                self.info.device_add(device[0], cfg_sxp = device)

        self._update_consoles()

    def _update_consoles(self):
        if self.domid == None or self.domid == 0:
            return

        # Update VT100 port if it exists
        self.console_port = self.readDom('console/port')
        if self.console_port is not None:
            serial_consoles = self.info.console_get_all('vt100')
            if not serial_consoles:
                cfg = self.info.console_add('vt100', self.console_port)
                self._createDevice('console', cfg)
            else:
                console_uuid = serial_consoles[0].get('uuid')
                self.info.console_update(console_uuid, 'location',
                                         self.console_port)
                

        # Update VNC port if it exists and write to xenstore
        vnc_port = self.readDom('console/vnc-port')
        if vnc_port is not None:
            for dev_uuid, (dev_type, dev_info) in self.info['devices'].items():
                if dev_type == 'vfb':
                    old_location = dev_info.get('location')
                    listen_host = dev_info.get('vnclisten', 'localhost')
                    new_location = '%s:%s' % (listen_host, str(vnc_port))
                    if old_location == new_location:
                        break

                    dev_info['location'] = new_location
                    self.info.device_update(dev_uuid, cfg_xenapi = dev_info)
                    vfb_ctrl = self.getDeviceController('vfb')
                    vfb_ctrl.reconfigureDevice(0, dev_info)
                    break
                
    #
    # Function to update xenstore /vm/*
    #

    def _readVm(self, *args):
        return xstransact.Read(self.vmpath, *args)

    def _writeVm(self, *args):
        return xstransact.Write(self.vmpath, *args)

    def _removeVm(self, *args):
        return xstransact.Remove(self.vmpath, *args)

    def _gatherVm(self, *args):
        return xstransact.Gather(self.vmpath, *args)

    def storeVm(self, *args):
        return xstransact.Store(self.vmpath, *args)

    #
    # Function to update xenstore /dom/*
    #

    def readDom(self, *args):
        return xstransact.Read(self.dompath, *args)

    def gatherDom(self, *args):
        return xstransact.Gather(self.dompath, *args)

    def _writeDom(self, *args):
        return xstransact.Write(self.dompath, *args)

    def _removeDom(self, *args):
        return xstransact.Remove(self.dompath, *args)

    def storeDom(self, *args):
        return xstransact.Store(self.dompath, *args)

    def _recreateDom(self):
        complete(self.dompath, lambda t: self._recreateDomFunc(t))

    def _recreateDomFunc(self, t):
        t.remove()
        t.mkdir()
        t.set_permissions({'dom' : self.domid})
        t.write('vm', self.vmpath)

    def _storeDomDetails(self):
        to_store = {
            'domid':              str(self.domid),
            'vm':                 self.vmpath,
            'name':               self.info['name_label'],
            'console/limit':      str(xoptions.get_console_limit() * 1024),
            'memory/target':      str(self.info['memory_static_min'] * 1024),
            }

        def f(n, v):
            if v is not None:
                if type(v) == bool:
                    to_store[n] = v and "1" or "0"
                else:
                    to_store[n] = str(v)

        f('console/port',     self.console_port)
        f('console/ring-ref', self.console_mfn)
        f('store/port',       self.store_port)
        f('store/ring-ref',   self.store_mfn)

        if arch.type == "x86":
            f('control/platform-feature-multiprocessor-suspend', True)

        # elfnotes
        for n, v in self.info.get_notes().iteritems():
            n = n.lower().replace('_', '-')
            if n == 'features':
                for v in v.split('|'):
                    v = v.replace('_', '-')
                    if v.startswith('!'):
                        f('image/%s/%s' % (n, v[1:]), False)
                    else:
                        f('image/%s/%s' % (n, v), True)
            else:
                f('image/%s' % n, v)

        to_store.update(self._vcpuDomDetails())

        log.debug("Storing domain details: %s", scrub_password(to_store))

        self._writeDom(to_store)

    def _vcpuDomDetails(self):
        def availability(n):
            if self.info['vcpu_avail'] & (1 << n):
                return 'online'
            else:
                return 'offline'

        result = {}
        for v in range(0, self.info['vcpus_number']):
            result["cpu/%d/availability" % v] = availability(v)
        return result

    #
    # xenstore watches
    #

    def _registerWatches(self):
        """Register a watch on this VM's entries in the store, and the
        domain's control/shutdown node, so that when they are changed
        externally, we keep up to date.  This should only be called by {@link
        #create}, {@link #recreate}, or {@link #restore}, once the domain's
        details have been written, but before the new instance is returned."""
        self.vmWatch = xswatch(self.vmpath, self._storeChanged)
        self.shutdownWatch = xswatch(self.dompath + '/control/shutdown',
                                     self._handleShutdownWatch)

    def _storeChanged(self, _):
        log.trace("XendDomainInfo.storeChanged");

        changed = False

        # Check whether values in the configuration have
        # changed in Xenstore.
        
        cfg_vm = ['name', 'on_poweroff', 'on_reboot', 'on_crash']
        
        vm_details = self._readVMDetails([(k,XendConfig.LEGACY_CFG_TYPES[k])
                                           for k in cfg_vm])

        # convert two lists into a python dictionary
        vm_details = dict(zip(cfg_vm, vm_details))
        
        for arg, val in vm_details.items():
            if arg in XendConfig.LEGACY_CFG_TO_XENAPI_CFG:
                xapiarg = XendConfig.LEGACY_CFG_TO_XENAPI_CFG[arg]
                if val != None and val != self.info[xapiarg]:
                    self.info[xapiarg] = val
                    changed= True

        # Check whether image definition has been updated
        image_sxp = self._readVm('image')
        if image_sxp and image_sxp != self.info.image_sxpr():
            self.info.update_with_image_sxp(sxp.from_string(image_sxp))
            changed = True

        if changed:
            # Update the domain section of the store, as this contains some
            # parameters derived from the VM configuration.
            self._storeDomDetails()

        return 1

    def _handleShutdownWatch(self, _):
        log.debug('XendDomainInfo.handleShutdownWatch')
        
        reason = self.readDom('control/shutdown')

        if reason and reason != 'suspend':
            sst = self.readDom('xend/shutdown_start_time')
            now = time.time()
            if sst:
                self.shutdownStartTime = float(sst)
                timeout = float(sst) + SHUTDOWN_TIMEOUT - now
            else:
                self.shutdownStartTime = now
                self.storeDom('xend/shutdown_start_time', now)
                timeout = SHUTDOWN_TIMEOUT

            log.trace(
                "Scheduling refreshShutdown on domain %d in %ds.",
                self.domid, timeout)
            threading.Timer(timeout, self.refreshShutdown).start()
            
        return True


    #
    # Public Attributes for the VM
    #


    def getDomid(self):
        return self.domid

    def setName(self, name):
        self._checkName(name)
        self.info['name_label'] = name
        self.storeVm("name", name)

    def getName(self):
        return self.info['name_label']

    def getDomainPath(self):
        return self.dompath

    def getShutdownReason(self):
        return self.readDom('control/shutdown')

    def getStorePort(self):
        """For use only by image.py and XendCheckpoint.py."""
        return self.store_port

    def getConsolePort(self):
        """For use only by image.py and XendCheckpoint.py"""
        return self.console_port

    def getFeatures(self):
        """For use only by image.py."""
        return self.info['features']

    def getVCpuCount(self):
        return self.info['vcpus_number']

    def setVCpuCount(self, vcpus):
        if vcpus <= 0:
            raise XendError('Invalid VCPUs')
        
        self.info['vcpu_avail'] = (1 << vcpus) - 1
        if self.domid >= 0:
            self.storeVm('vcpu_avail', self.info['vcpu_avail'])
            # update dom differently depending on whether we are adjusting
            # vcpu number up or down, otherwise _vcpuDomDetails does not
            # disable the vcpus
            if self.info['vcpus_number'] > vcpus:
                # decreasing
                self._writeDom(self._vcpuDomDetails())
                self.info['vcpus_number'] = vcpus
            else:
                # same or increasing
                self.info['vcpus_number'] = vcpus
                self._writeDom(self._vcpuDomDetails())
        else:
            self.info['vcpus_number'] = vcpus
            xen.xend.XendDomain.instance().managed_config_save(self)
        log.info("Set VCPU count on domain %s to %d", self.info['name_label'],
                 vcpus)

    def getLabel(self):
        return security.get_security_info(self.info, 'label')

    def getMemoryTarget(self):
        """Get this domain's target memory size, in KB."""
        return self.info['memory_static_min'] * 1024

    def getMemoryMaximum(self):
        """Get this domain's maximum memory size, in KB."""
        return self.info['memory_static_max'] * 1024

    def getResume(self):
        return str(self._resume)

    def getCap(self):
        return self.info.get('cpu_cap', 0)

    def getWeight(self):
        return self.info.get('cpu_weight', 256)

    def setResume(self, state):
        self._resume = state

    def getRestartCount(self):
        return self._readVm('xend/restart_count')

    def refreshShutdown(self, xeninfo = None):
        """ Checks the domain for whether a shutdown is required.

        Called from XendDomainInfo and also image.py for HVM images.
        """
        
        # If set at the end of this method, a restart is required, with the
        # given reason.  This restart has to be done out of the scope of
        # refresh_shutdown_lock.
        restart_reason = None

        self.refresh_shutdown_lock.acquire()
        try:
            if xeninfo is None:
                xeninfo = dom_get(self.domid)
                if xeninfo is None:
                    # The domain no longer exists.  This will occur if we have
                    # scheduled a timer to check for shutdown timeouts and the
                    # shutdown succeeded.  It will also occur if someone
                    # destroys a domain beneath us.  We clean up the domain,
                    # just in case, but we can't clean up the VM, because that
                    # VM may have migrated to a different domain on this
                    # machine.
                    self.cleanupDomain()
                    self._stateSet(DOM_STATE_HALTED)
                    return

            if xeninfo['dying']:
                # Dying means that a domain has been destroyed, but has not
                # yet been cleaned up by Xen.  This state could persist
                # indefinitely if, for example, another domain has some of its
                # pages mapped.  We might like to diagnose this problem in the
                # future, but for now all we do is make sure that it's not us
                # holding the pages, by calling cleanupDomain.  We can't
                # clean up the VM, as above.
                self.cleanupDomain()
                self._stateSet(DOM_STATE_SHUTDOWN)
                return

            elif xeninfo['crashed']:
                if self.readDom('xend/shutdown_completed'):
                    # We've seen this shutdown already, but we are preserving
                    # the domain for debugging.  Leave it alone.
                    return

                log.warn('Domain has crashed: name=%s id=%d.',
                         self.info['name_label'], self.domid)
                self._writeVm(LAST_SHUTDOWN_REASON, 'crash')

                if xoptions.get_enable_dump():
                    try:
                        self.dumpCore()
                    except XendError:
                        # This error has been logged -- there's nothing more
                        # we can do in this context.
                        pass

                restart_reason = 'crash'
                self._stateSet(DOM_STATE_HALTED)

            elif xeninfo['shutdown']:
                self._stateSet(DOM_STATE_SHUTDOWN)
                if self.readDom('xend/shutdown_completed'):
                    # We've seen this shutdown already, but we are preserving
                    # the domain for debugging.  Leave it alone.
                    return

                else:
                    reason = shutdown_reason(xeninfo['shutdown_reason'])

                    log.info('Domain has shutdown: name=%s id=%d reason=%s.',
                             self.info['name_label'], self.domid, reason)
                    self._writeVm(LAST_SHUTDOWN_REASON, reason)

                    self._clearRestart()

                    if reason == 'suspend':
                        self._stateSet(DOM_STATE_SUSPENDED)
                        # Don't destroy the domain.  XendCheckpoint will do
                        # this once it has finished.  However, stop watching
                        # the VM path now, otherwise we will end up with one
                        # watch for the old domain, and one for the new.
                        self._unwatchVm()
                    elif reason in ('poweroff', 'reboot'):
                        restart_reason = reason
                    else:
                        self.destroy()

            elif self.dompath is None:
                # We have yet to manage to call introduceDomain on this
                # domain.  This can happen if a restore is in progress, or has
                # failed.  Ignore this domain.
                pass
            else:
                # Domain is alive.  If we are shutting it down, then check
                # the timeout on that, and destroy it if necessary.
                if xeninfo['paused']:
                    self._stateSet(DOM_STATE_PAUSED)
                else:
                    self._stateSet(DOM_STATE_RUNNING)
                    
                if self.shutdownStartTime:
                    timeout = (SHUTDOWN_TIMEOUT - time.time() +
                               self.shutdownStartTime)
                    if timeout < 0:
                        log.info(
                            "Domain shutdown timeout expired: name=%s id=%s",
                            self.info['name_label'], self.domid)
                        self.destroy()
        finally:
            self.refresh_shutdown_lock.release()

        if restart_reason:
            threading.Thread(target = self._maybeRestart,
                             args = (restart_reason,)).start()


    #
    # Restart functions - handling whether we come back up on shutdown.
    #

    def _clearRestart(self):
        self._removeDom("xend/shutdown_start_time")


    def _maybeRestart(self, reason):
        # Dispatch to the correct method based upon the configured on_{reason}
        # behaviour.
        actions =  {"destroy"        : self.destroy,
                    "restart"        : self._restart,
                    "preserve"       : self._preserve,
                    "rename-restart" : self._renameRestart}

        action_conf = {
            'poweroff': 'actions_after_shutdown',
            'reboot': 'actions_after_reboot',
            'crash': 'actions_after_crash',
        }

        action_target = self.info.get(action_conf.get(reason))
        func = actions.get(action_target, None)
        if func and callable(func):
            func()
        else:
            self.destroy() # default to destroy

    def _renameRestart(self):
        self._restart(True)

    def _restart(self, rename = False):
        """Restart the domain after it has exited.

        @param rename True if the old domain is to be renamed and preserved,
        False if it is to be destroyed.
        """
        from xen.xend import XendDomain
        
        if self._readVm(RESTART_IN_PROGRESS):
            log.error('Xend failed during restart of domain %s.  '
                      'Refusing to restart to avoid loops.',
                      str(self.domid))
            self.destroy()
            return

        old_domid = self.domid
        self._writeVm(RESTART_IN_PROGRESS, 'True')

        now = time.time()
        rst = self._readVm('xend/previous_restart_time')
        if rst:
            rst = float(rst)
            timeout = now - rst
            if timeout < MINIMUM_RESTART_TIME:
                log.error(
                    'VM %s restarting too fast (%f seconds since the last '
                    'restart).  Refusing to restart to avoid loops.',
                    self.info['name_label'], timeout)
                self.destroy()
                return

        self._writeVm('xend/previous_restart_time', str(now))

        try:
            if rename:
                self._preserveForRestart()
            else:
                self._unwatchVm()
                self.destroyDomain()

            # new_dom's VM will be the same as this domain's VM, except where
            # the rename flag has instructed us to call preserveForRestart.
            # In that case, it is important that we remove the
            # RESTART_IN_PROGRESS node from the new domain, not the old one,
            # once the new one is available.

            new_dom = None
            try:
                new_dom = XendDomain.instance().domain_create_from_dict(
                    self.info)
                new_dom.unpause()
                rst_cnt = self._readVm('xend/restart_count')
                rst_cnt = int(rst_cnt) + 1
                self._writeVm('xend/restart_count', str(rst_cnt))
                new_dom._removeVm(RESTART_IN_PROGRESS)
            except:
                if new_dom:
                    new_dom._removeVm(RESTART_IN_PROGRESS)
                    new_dom.destroy()
                else:
                    self._removeVm(RESTART_IN_PROGRESS)
                raise
        except:
            log.exception('Failed to restart domain %s.', str(old_domid))

    def _preserveForRestart(self):
        """Preserve a domain that has been shut down, by giving it a new UUID,
        cloning the VM details, and giving it a new name.  This allows us to
        keep this domain for debugging, but restart a new one in its place
        preserving the restart semantics (name and UUID preserved).
        """
        
        new_uuid = uuid.createString()
        new_name = 'Domain-%s' % new_uuid
        log.info("Renaming dead domain %s (%d, %s) to %s (%s).",
                 self.info['name_label'], self.domid, self.info['uuid'],
                 new_name, new_uuid)
        self._unwatchVm()
        self._releaseDevices()
        self.info['name_label'] = new_name
        self.info['uuid'] = new_uuid
        self.vmpath = XS_VMROOT + new_uuid
        self._storeVmDetails()
        self._preserve()


    def _preserve(self):
        log.info("Preserving dead domain %s (%d).", self.info['name_label'],
                 self.domid)
        self._unwatchVm()
        self.storeDom('xend/shutdown_completed', 'True')
        self._stateSet(DOM_STATE_HALTED)

    #
    # Debugging ..
    #

    def dumpCore(self, corefile = None):
        """Create a core dump for this domain.

        @raise: XendError if core dumping failed.
        """
        
        try:
            if not corefile:
                this_time = time.strftime("%Y-%m%d-%H%M.%S", time.localtime())
                corefile = "/var/xen/dump/%s-%s.%s.core" % (this_time,
                                  self.info['name_label'], self.domid)
                
            if os.path.isdir(corefile):
                raise XendError("Cannot dump core in a directory: %s" %
                                corefile)
            
            xc.domain_dumpcore(self.domid, corefile)
        except RuntimeError, ex:
            corefile_incomp = corefile+'-incomplete'
            os.rename(corefile, corefile_incomp)
            log.exception("XendDomainInfo.dumpCore failed: id = %s name = %s",
                          self.domid, self.info['name_label'])
            raise XendError("Failed to dump core: %s" %  str(ex))

    #
    # Device creation/deletion functions
    #

    def _createDevice(self, deviceClass, devConfig):
        return self.getDeviceController(deviceClass).createDevice(devConfig)

    def _waitForDevice(self, deviceClass, devid):
        return self.getDeviceController(deviceClass).waitForDevice(devid)

    def _waitForDeviceUUID(self, dev_uuid):
        deviceClass, config = self.info['devices'].get(dev_uuid)
        self._waitForDevice(deviceClass, config['devid'])

    def _reconfigureDevice(self, deviceClass, devid, devconfig):
        return self.getDeviceController(deviceClass).reconfigureDevice(
            devid, devconfig)

    def _createDevices(self):
        """Create the devices for a vm.

        @raise: VmError for invalid devices
        """
        ordered_refs = self.info.ordered_device_refs()
        for dev_uuid in ordered_refs:
            devclass, config = self.info['devices'][dev_uuid]
            if devclass in XendDevices.valid_devices():
                log.info("createDevice: %s : %s" % (devclass, scrub_password(config)))
                dev_uuid = config.get('uuid')
                devid = self._createDevice(devclass, config)
                
                # store devid in XendConfig for caching reasons
                if dev_uuid in self.info['devices']:
                    self.info['devices'][dev_uuid][1]['devid'] = devid

        if self.image:
            self.image.createDeviceModel()

    def _releaseDevices(self, suspend = False):
        """Release all domain's devices.  Nothrow guarantee."""
        if suspend and self.image:
            self.image.destroy(suspend)
            return

        while True:
            t = xstransact("%s/device" % self.dompath)
            for devclass in XendDevices.valid_devices():
                for dev in t.list(devclass):
                    try:
                        t.remove(dev)
                    except:
                        # Log and swallow any exceptions in removal --
                        # there's nothing more we can do.
                        log.exception(
                           "Device release failed: %s; %s; %s",
                           self.info['name_label'], devclass, dev)
            if t.commit():
                break

    def getDeviceController(self, name):
        """Get the device controller for this domain, and if it
        doesn't exist, create it.

        @param name: device class name
        @type name: string
        @rtype: subclass of DevController
        """
        if name not in self._deviceControllers:
            devController = XendDevices.make_controller(name, self)
            if not devController:
                raise XendError("Unknown device type: %s" % name)
            self._deviceControllers[name] = devController
    
        return self._deviceControllers[name]

    #
    # Migration functions (public)
    # 

    def testMigrateDevices(self, network, dst):
        """ Notify all device about intention of migration
        @raise: XendError for a device that cannot be migrated
        """
        for (n, c) in self.info.all_devices_sxpr():
            rc = self.migrateDevice(n, c, network, dst, DEV_MIGRATE_TEST)
            if rc != 0:
                raise XendError("Device of type '%s' refuses migration." % n)

    def migrateDevices(self, network, dst, step, domName=''):
        """Notify the devices about migration
        """
        ctr = 0
        try:
            for (dev_type, dev_conf) in self.info.all_devices_sxpr():
                self.migrateDevice(dev_type, dev_conf, network, dst,
                                   step, domName)
                ctr = ctr + 1
        except:
            for dev_type, dev_conf in self.info.all_devices_sxpr():
                if ctr == 0:
                    step = step - 1
                ctr = ctr - 1
                self._recoverMigrateDevice(dev_type, dev_conf, network,
                                           dst, step, domName)
            raise

    def migrateDevice(self, deviceClass, deviceConfig, network, dst,
                      step, domName=''):
        return self.getDeviceController(deviceClass).migrate(deviceConfig,
                                        network, dst, step, domName)

    def _recoverMigrateDevice(self, deviceClass, deviceConfig, network,
                             dst, step, domName=''):
        return self.getDeviceController(deviceClass).recover_migrate(
                     deviceConfig, network, dst, step, domName)


    ## private:

    def _constructDomain(self):
        """Construct the domain.

        @raise: VmError on error
        """

        log.debug('XendDomainInfo.constructDomain')

        self.shutdownStartTime = None

        image_cfg = self.info.get('image', {})
        hvm = image_cfg.has_key('hvm')

        if hvm:
            info = xc.xeninfo()
            if 'hvm' not in info['xen_caps']:
                raise VmError("HVM guest support is unavailable: is VT/AMD-V "
                              "supported by your CPU and enabled in your "
                              "BIOS?")

        self.domid = xc.domain_create(
            domid = 0,
            ssidref = security.get_security_info(self.info, 'ssidref'),
            handle = uuid.fromString(self.info['uuid']),
            hvm = int(hvm))

        if self.domid < 0:
            raise VmError('Creating domain failed: name=%s' %
                          self.info['name_label'])

        self.dompath = GetDomainPath(self.domid)

        self._recreateDom()

        # Set maximum number of vcpus in domain
        xc.domain_max_vcpus(self.domid, int(self.info['vcpus_number']))

        # register the domain in the list 
        from xen.xend import XendDomain
        XendDomain.instance().add_domain(self)

    def _introduceDomain(self):
        assert self.domid is not None
        assert self.store_mfn is not None
        assert self.store_port is not None

        try:
            IntroduceDomain(self.domid, self.store_mfn, self.store_port)
        except RuntimeError, exn:
            raise XendError(str(exn))


    def _initDomain(self):
        log.debug('XendDomainInfo.initDomain: %s %s',
                  self.domid,
                  self.info['cpu_weight'])

        self._configureBootloader()

        if not self._infoIsSet('image'):
            raise VmError('Missing image in configuration')

        try:
            self.image = image.create(self,
                                      self.info,
                                      self.info['image'],
                                      self.info['devices'])

            localtime = self.info.get('platform_localtime', False)
            if localtime:
                xc.domain_set_time_offset(self.domid)

            xc.domain_setcpuweight(self.domid, self.info['cpu_weight'])

            # repin domain vcpus if a restricted cpus list is provided
            # this is done prior to memory allocation to aide in memory
            # distribution for NUMA systems.
            if self.info['cpus'] is not None and len(self.info['cpus']) > 0:
                for v in range(0, self.info['vcpus_number']):
                    xc.vcpu_setaffinity(self.domid, v, self.info['cpus'])

            # Use architecture- and image-specific calculations to determine
            # the various headrooms necessary, given the raw configured
            # values. maxmem, memory, and shadow are all in KiB.
            memory = self.image.getRequiredAvailableMemory(
                self.info['memory_static_min'] * 1024)
            maxmem = self.image.getRequiredAvailableMemory(
                self.info['memory_static_max'] * 1024)
            shadow = self.image.getRequiredShadowMemory(
                self.info['shadow_memory'] * 1024,
                self.info['memory_static_max'] * 1024)

            log.debug("_initDomain:shadow_memory=0x%x, memory_static_max=0x%x, memory_static_min=0x%x.", self.info['shadow_memory'], self.info['memory_static_max'], self.info['memory_static_min'],)
            # Round shadow up to a multiple of a MiB, as shadow_mem_control
            # takes MiB and we must not round down and end up under-providing.
            shadow = ((shadow + 1023) / 1024) * 1024

            # set memory limit
            xc.domain_setmaxmem(self.domid, maxmem)

            # Make sure there's enough RAM available for the domain
            balloon.free(memory + shadow)

            # Set up the shadow memory
            shadow_cur = xc.shadow_mem_control(self.domid, shadow / 1024)
            self.info['shadow_memory'] = shadow_cur

            self._createChannels()

            channel_details = self.image.createImage()

            self.store_mfn = channel_details['store_mfn']
            if 'console_mfn' in channel_details:
                self.console_mfn = channel_details['console_mfn']
            if 'notes' in channel_details:
                self.info.set_notes(channel_details['notes'])

            self._introduceDomain()

            self._createDevices()

            self.image.cleanupBootloading()

            self.info['start_time'] = time.time()

            self._stateSet(DOM_STATE_RUNNING)
        except (RuntimeError, VmError), exn:
            log.exception("XendDomainInfo.initDomain: exception occurred")
            self.image.cleanupBootloading()
            raise VmError(str(exn))


    def cleanupDomain(self):
        """Cleanup domain resources; release devices.  Idempotent.  Nothrow
        guarantee."""

        self.refresh_shutdown_lock.acquire()
        try:
            self.unwatchShutdown()
            self._releaseDevices()
            bootloader_tidy(self)

            if self.image:
                try:
                    self.image.destroy()
                except:
                    log.exception(
                        "XendDomainInfo.cleanup: image.destroy() failed.")
                self.image = None

            try:
                self._removeDom()
            except:
                log.exception("Removing domain path failed.")

            self._stateSet(DOM_STATE_HALTED)
        finally:
            self.refresh_shutdown_lock.release()


    def unwatchShutdown(self):
        """Remove the watch on the domain's control/shutdown node, if any.
        Idempotent.  Nothrow guarantee.  Expects to be protected by the
        refresh_shutdown_lock."""

        try:
            try:
                if self.shutdownWatch:
                    self.shutdownWatch.unwatch()
            finally:
                self.shutdownWatch = None
        except:
            log.exception("Unwatching control/shutdown failed.")

    def waitForShutdown(self):
        self.state_updated.acquire()
        try:
            while self.state in (DOM_STATE_RUNNING,DOM_STATE_PAUSED):
                self.state_updated.wait()
        finally:
            self.state_updated.release()


    #
    # TODO: recategorise - called from XendCheckpoint
    # 

    def completeRestore(self, store_mfn, console_mfn):

        log.debug("XendDomainInfo.completeRestore")

        self.store_mfn = store_mfn
        self.console_mfn = console_mfn

        self._introduceDomain()
        image_cfg = self.info.get('image', {})
        hvm = image_cfg.has_key('hvm')
        if hvm:
            self.image = image.create(self,
                    self.info,
                    self.info['image'],
                    self.info['devices'])
            if self.image:
                self.image.createDeviceModel(True)
                self.image.register_shutdown_watch()
        self._storeDomDetails()
        self._registerWatches()
        self.refreshShutdown()

        log.debug("XendDomainInfo.completeRestore done")


    def _endRestore(self):
        self.setResume(False)

    #
    # VM Destroy
    # 

    def _prepare_phantom_paths(self):
        # get associated devices to destroy
        # build list of phantom devices to be removed after normal devices
        plist = []
        if self.domid is not None:
            from xen.xend.xenstore.xstransact import xstransact
            t = xstransact("%s/device/vbd" % GetDomainPath(self.domid))
            for dev in t.list():
                backend_phantom_vbd = xstransact.Read("%s/device/vbd/%s/phantom_vbd" \
                                      % (self.dompath, dev))
                if backend_phantom_vbd is not None:
                    frontend_phantom_vbd =  xstransact.Read("%s/frontend" \
                                      % backend_phantom_vbd)
                    plist.append(backend_phantom_vbd)
                    plist.append(frontend_phantom_vbd)
        return plist

    def _cleanup_phantom_devs(self, plist):
        # remove phantom devices
        if not plist == []:
            time.sleep(2)
        for paths in plist:
            if paths.find('backend') != -1:
                from xen.xend.server import DevController
                # Modify online status /before/ updating state (latter is watched by
                # drivers, so this ordering avoids a race).
                xstransact.Write(paths, 'online', "0")
                xstransact.Write(paths, 'state', str(DevController.xenbusState['Closing']))
            # force
            xstransact.Remove(paths)

    def destroy(self):
        """Cleanup VM and destroy domain.  Nothrow guarantee."""

        log.debug("XendDomainInfo.destroy: domid=%s", str(self.domid))

        paths = self._prepare_phantom_paths()

        self._cleanupVm()
        if self.dompath is not None:
            self.destroyDomain()

        self._cleanup_phantom_devs(paths)

    def destroyDomain(self):
        log.debug("XendDomainInfo.destroyDomain(%s)", str(self.domid))

        paths = self._prepare_phantom_paths()

        try:
            if self.domid is not None:
                xc.domain_destroy(self.domid)
                self.domid = None
                for state in DOM_STATES_OLD:
                    self.info[state] = 0
        except:
            log.exception("XendDomainInfo.destroy: xc.domain_destroy failed.")

        from xen.xend import XendDomain
        XendDomain.instance().remove_domain(self)

        self.cleanupDomain()
        self._cleanup_phantom_devs(paths)

    def resumeDomain(self):
        log.debug("XendDomainInfo.resumeDomain(%s)", str(self.domid))

        if self.domid is None:
            return
        try:
            # could also fetch a parsed note from xenstore
            fast = self.info.get_notes().get('SUSPEND_CANCEL') and 1 or 0
            if not fast:
                self._releaseDevices()
                self.testDeviceComplete()
                self.testvifsComplete()
                log.debug("XendDomainInfo.resumeDomain: devices released")

                self._resetChannels()

                self._removeDom('control/shutdown')
                self._removeDom('device-misc/vif/nextDeviceID')

                self._createChannels()
                self._introduceDomain()
                self._storeDomDetails()

                self._createDevices()
                log.debug("XendDomainInfo.resumeDomain: devices created")

            xc.domain_resume(self.domid, fast)
            ResumeDomain(self.domid)
        except:
            log.exception("XendDomainInfo.resume: xc.domain_resume failed on domain %s." % (str(self.domid)))

    #
    # Channels for xenstore and console
    # 

    def _createChannels(self):
        """Create the channels to the domain.
        """
        self.store_port = self._createChannel()
        self.console_port = self._createChannel()


    def _createChannel(self):
        """Create an event channel to the domain.
        """
        try:
            if self.domid != None:
                return xc.evtchn_alloc_unbound(domid = self.domid,
                                               remote_dom = 0)
        except:
            log.exception("Exception in alloc_unbound(%s)", str(self.domid))
            raise

    def _resetChannels(self):
        """Reset all event channels in the domain.
        """
        try:
            if self.domid != None:
                return xc.evtchn_reset(dom = self.domid)
        except:
            log.exception("Exception in evtcnh_reset(%s)", str(self.domid))
            raise


    #
    # Bootloader configuration
    #

    def _configureBootloader(self):
        """Run the bootloader if we're configured to do so."""

        blexec          = self.info['PV_bootloader']
        bootloader_args = self.info['PV_bootloader_args']
        kernel          = self.info['PV_kernel']
        ramdisk         = self.info['PV_ramdisk']
        args            = self.info['PV_args']
        boot            = self.info['HVM_boot_policy']

        if boot:
            # HVM booting.
            self.info['image']['type'] = 'hvm'
            if not 'devices' in self.info['image']:
                self.info['image']['devices'] = {}
            self.info['image']['devices']['boot'] = \
                self.info['HVM_boot_params'].get('order', 'dc')
        elif not blexec and kernel:
            # Boot from dom0.  Nothing left to do -- the kernel and ramdisk
            # will be picked up by image.py.
            pass
        else:
            # Boot using bootloader
            if not blexec or blexec == 'pygrub':
                blexec = osdep.pygrub_path

            blcfg = None
            disks = [x for x in self.info['vbd_refs']
                     if self.info['devices'][x][1]['bootable']]

            if not disks:
                msg = "Had a bootloader specified, but no disks are bootable"
                log.error(msg)
                raise VmError(msg)

            devinfo = self.info['devices'][disks[0]]
            devtype = devinfo[0]
            disk = devinfo[1]['uname']

            fn = blkdev_uname_to_file(disk)
            mounted = devtype == 'tap' and not os.stat(fn).st_rdev
            if mounted:
                # This is a file, not a device.  pygrub can cope with a
                # file if it's raw, but if it's QCOW or other such formats
                # used through blktap, then we need to mount it first.

                log.info("Mounting %s on %s." %
                         (fn, BOOTLOADER_LOOPBACK_DEVICE))

                vbd = {
                    'mode': 'RO',
                    'device': BOOTLOADER_LOOPBACK_DEVICE,
                    }

                from xen.xend import XendDomain
                dom0 = XendDomain.instance().privilegedDomain()
                dom0._waitForDeviceUUID(dom0.create_vbd(vbd, fn))
                fn = BOOTLOADER_LOOPBACK_DEVICE

            try:
                blcfg = bootloader(blexec, fn, self, False,
                                   bootloader_args, kernel, ramdisk, args)
            finally:
                if mounted:
                    log.info("Unmounting %s from %s." %
                             (fn, BOOTLOADER_LOOPBACK_DEVICE))

                    dom0.destroyDevice('tap', '/dev/xvdp')

            if blcfg is None:
                msg = "Had a bootloader specified, but can't find disk"
                log.error(msg)
                raise VmError(msg)
        
            self.info.update_with_image_sxp(blcfg, True)


    # 
    # VM Functions
    #

    def _readVMDetails(self, params):
        """Read the specified parameters from the store.
        """
        try:
            return self._gatherVm(*params)
        except ValueError:
            # One of the int/float entries in params has a corresponding store
            # entry that is invalid.  We recover, because older versions of
            # Xend may have put the entry there (memory/target, for example),
            # but this is in general a bad situation to have reached.
            log.exception(
                "Store corrupted at %s!  Domain %d's configuration may be "
                "affected.", self.vmpath, self.domid)
            return []

    def _cleanupVm(self):
        """Cleanup VM resources.  Idempotent.  Nothrow guarantee."""

        self._unwatchVm()

        try:
            self._removeVm()
        except:
            log.exception("Removing VM path failed.")


    def checkLiveMigrateMemory(self):
        """ Make sure there's enough memory to migrate this domain """
        overhead_kb = 0
        if arch.type == "x86":
            # 1MB per vcpu plus 4Kib/Mib of RAM.  This is higher than 
            # the minimum that Xen would allocate if no value were given.
            overhead_kb = self.info['vcpus_number'] * 1024 + \
                          self.info['memory_static_max'] * 4
            overhead_kb = ((overhead_kb + 1023) / 1024) * 1024
            # The domain might already have some shadow memory
            overhead_kb -= xc.shadow_mem_control(self.domid) * 1024
        if overhead_kb > 0:
            balloon.free(overhead_kb)

    def _unwatchVm(self):
        """Remove the watch on the VM path, if any.  Idempotent.  Nothrow
        guarantee."""
        try:
            try:
                if self.vmWatch:
                    self.vmWatch.unwatch()
            finally:
                self.vmWatch = None
        except:
            log.exception("Unwatching VM path failed.")

    def testDeviceComplete(self):
        """ For Block IO migration safety we must ensure that
        the device has shutdown correctly, i.e. all blocks are
        flushed to disk
        """
        start = time.time()
        while True:
            test = 0
            diff = time.time() - start
            for i in self.getDeviceController('vbd').deviceIDs():
                test = 1
                log.info("Dev %s still active, looping...", i)
                time.sleep(0.1)
                
            if test == 0:
                break
            if diff >= MIGRATE_TIMEOUT:
                log.info("Dev still active but hit max loop timeout")
                break

    def testvifsComplete(self):
        """ In case vifs are released and then created for the same
        domain, we need to wait the device shut down.
        """
        start = time.time()
        while True:
            test = 0
            diff = time.time() - start
            for i in self.getDeviceController('vif').deviceIDs():
                test = 1
                log.info("Dev %s still active, looping...", i)
                time.sleep(0.1)
                
            if test == 0:
                break
            if diff >= MIGRATE_TIMEOUT:
                log.info("Dev still active but hit max loop timeout")
                break

    def _storeVmDetails(self):
        to_store = {}

        for key in XendConfig.LEGACY_XENSTORE_VM_PARAMS:
            info_key = XendConfig.LEGACY_CFG_TO_XENAPI_CFG.get(key, key)
            if self._infoIsSet(info_key):
                to_store[key] = str(self.info[info_key])

        if self.info.get('image'):
            image_sxpr = self.info.image_sxpr()
            if image_sxpr:
                to_store['image'] = sxp.to_string(image_sxpr)

        if self._infoIsSet('security'):
            secinfo = self.info['security']
            to_store['security'] = sxp.to_string(secinfo)
            for idx in range(0, len(secinfo)):
                if secinfo[idx][0] == 'access_control':
                    to_store['security/access_control'] = sxp.to_string(
                        [secinfo[idx][1], secinfo[idx][2]])
                    for aidx in range(1, len(secinfo[idx])):
                        if secinfo[idx][aidx][0] == 'label':
                            to_store['security/access_control/label'] = \
                                secinfo[idx][aidx][1]
                        if secinfo[idx][aidx][0] == 'policy':
                            to_store['security/access_control/policy'] = \
                                secinfo[idx][aidx][1]
                if secinfo[idx][0] == 'ssidref':
                    to_store['security/ssidref'] = str(secinfo[idx][1])


        if not self._readVm('xend/restart_count'):
            to_store['xend/restart_count'] = str(0)

        log.debug("Storing VM details: %s", scrub_password(to_store))

        self._writeVm(to_store)
        self._setVmPermissions()


    def _setVmPermissions(self):
        """Allow the guest domain to read its UUID.  We don't allow it to
        access any other entry, for security."""
        xstransact.SetPermissions('%s/uuid' % self.vmpath,
                                  { 'dom' : self.domid,
                                    'read' : True,
                                    'write' : False })

    #
    # Utility functions
    #

    def _stateSet(self, state):
        self.state_updated.acquire()
        try:
            if self.state != state:
                self.state = state
                self.state_updated.notifyAll()
        finally:
            self.state_updated.release()

    def _infoIsSet(self, name):
        return name in self.info and self.info[name] is not None

    def _checkName(self, name):
        """Check if a vm name is valid. Valid names contain alphabetic
        characters, digits, or characters in '_-.:/+'.
        The same name cannot be used for more than one vm at the same time.

        @param name: name
        @raise: VmError if invalid
        """
        from xen.xend import XendDomain
        
        if name is None or name == '':
            raise VmError('Missing VM Name')

        if not re.search(r'^[A-Za-z0-9_\-\.\:\/\+]+$', name):
            raise VmError('Invalid VM Name')

        dom =  XendDomain.instance().domain_lookup_nr(name)
        if dom and dom.info['uuid'] != self.info['uuid']:
            raise VmError("VM name '%s' already exists%s" %
                          (name,
                           dom.domid is not None and
                           (" as domain %s" % str(dom.domid)) or ""))
        

    def update(self, info = None, refresh = True):
        """Update with info from xc.domain_getinfo().
        """
        log.trace("XendDomainInfo.update(%s) on domain %s", info,
                  str(self.domid))
        
        if not info:
            info = dom_get(self.domid)
            if not info:
                return
            
        #manually update ssidref / security fields
        if security.on() and info.has_key('ssidref'):
            if (info['ssidref'] != 0) and self.info.has_key('security'):
                security_field = self.info['security']
                if not security_field:
                    #create new security element
                    self.info.update({'security':
                                      [['ssidref', str(info['ssidref'])]]})
                    
        #ssidref field not used any longer
        if 'ssidref' in info:
            info.pop('ssidref')

        # make sure state is reset for info
        # TODO: we should eventually get rid of old_dom_states

        self.info.update_config(info)
        self._update_consoles()
        
        if refresh:
            self.refreshShutdown(info)

        log.trace("XendDomainInfo.update done on domain %s: %s",
                  str(self.domid), self.info)

    def sxpr(self, ignore_store = False, legacy_only = True):
        result = self.info.to_sxp(domain = self,
                                  ignore_devices = ignore_store,
                                  legacy_only = legacy_only)

        #if not ignore_store and self.dompath:
        #    vnc_port = self.readDom('console/vnc-port')
        #    if vnc_port is not None:
        #        result.append(['device',
        #                       ['console', ['vnc-port', str(vnc_port)]]])

        return result

    # Xen API
    # ----------------------------------------------------------------

    def get_uuid(self):
        dom_uuid = self.info.get('uuid')
        if not dom_uuid: # if it doesn't exist, make one up
            dom_uuid = uuid.createString()
            self.info['uuid'] = dom_uuid
        return dom_uuid
    
    def get_memory_static_max(self):
        return self.info.get('memory_static_max', 0)
    def get_memory_static_min(self):
        return self.info.get('memory_static_min', 0)
    def get_memory_dynamic_max(self):
        return self.info.get('memory_dynamic_max', 0)
    def get_memory_dynamic_min(self):
        return self.info.get('memory_dynamic_min', 0)

    def get_vcpus_policy(self):
        sched_id = xc.sched_id_get()
        if sched_id == xen.lowlevel.xc.XEN_SCHEDULER_SEDF:
            return 'sedf'
        elif sched_id == xen.lowlevel.xc.XEN_SCHEDULER_CREDIT:
            return 'credit'
        else:
            return 'unknown'
    def get_vcpus_params(self):
        if self.getDomid() is None:
            return self.info['vcpus_params']

        retval = xc.sched_credit_domain_get(self.getDomid())
        return retval
    def get_power_state(self):
        return XEN_API_VM_POWER_STATE[self.state]
    def get_platform_std_vga(self):
        return self.info.get('platform_std_vga', False)    
    def get_platform_serial(self):
        return self.info.get('platform_serial', '')
    def get_platform_localtime(self):
        return self.info.get('platform_localtime', False)
    def get_platform_clock_offset(self):
        return self.info.get('platform_clock_offset', False)
    def get_platform_enable_audio(self):
        return self.info.get('platform_enable_audio', False)
    def get_platform_keymap(self):
        return self.info.get('platform_keymap', '')
    def get_pci_bus(self):
        return self.info.get('pci_bus', '')
    def get_tools_version(self):
        return self.info.get('tools_version', {})
    
    def get_on_shutdown(self):
        after_shutdown = self.info.get('actions_after_shutdown')
        if not after_shutdown or after_shutdown not in XEN_API_ON_NORMAL_EXIT:
            return XEN_API_ON_NORMAL_EXIT[-1]
        return after_shutdown

    def get_on_reboot(self):
        after_reboot = self.info.get('actions_after_reboot')
        if not after_reboot or after_reboot not in XEN_API_ON_NORMAL_EXIT:
            return XEN_API_ON_NORMAL_EXIT[-1]
        return after_reboot

    def get_on_suspend(self):
        # TODO: not supported        
        after_suspend = self.info.get('actions_after_suspend') 
        if not after_suspend or after_suspend not in XEN_API_ON_NORMAL_EXIT:
            return XEN_API_ON_NORMAL_EXIT[-1]
        return after_suspend        

    def get_on_crash(self):
        after_crash = self.info.get('actions_after_crash')
        if not after_crash or after_crash not in XEN_API_ON_CRASH_BEHAVIOUR:
            return XEN_API_ON_CRASH_BEHAVIOUR[0]
        return after_crash

    def get_dev_config_by_uuid(self, dev_class, dev_uuid):
        """ Get's a device configuration either from XendConfig or
        from the DevController.

        @param dev_class: device class, either, 'vbd' or 'vif'
        @param dev_uuid: device UUID

        @rtype: dictionary
        """
        dev_type, dev_config = self.info['devices'].get(dev_uuid, (None, None))

        # shortcut if the domain isn't started because
        # the devcontrollers will have no better information
        # than XendConfig.
        if self.state in (XEN_API_VM_POWER_STATE_HALTED,):
            if dev_config:
                return copy.deepcopy(dev_config)
            return None

        # instead of using dev_class, we use the dev_type
        # that is from XendConfig.
        controller = self.getDeviceController(dev_type)
        if not controller:
            return None
            
        all_configs = controller.getAllDeviceConfigurations()
        if not all_configs:
            return None

        updated_dev_config = copy.deepcopy(dev_config)
        for _devid, _devcfg in all_configs.items():
            if _devcfg.get('uuid') == dev_uuid:
                updated_dev_config.update(_devcfg)
                updated_dev_config['id'] = _devid
                return updated_dev_config

        return updated_dev_config
                    
    def get_dev_xenapi_config(self, dev_class, dev_uuid):
        config = self.get_dev_config_by_uuid(dev_class, dev_uuid)
        if not config:
            return {}
        
        config['VM'] = self.get_uuid()
        
        if dev_class == 'vif':
            if not config.has_key('name'):
                config['name'] = config.get('vifname', '')
            if not config.has_key('MAC'):
                config['MAC'] = config.get('mac', '')
            if not config.has_key('type'):
                config['type'] = 'paravirtualised'
            if not config.has_key('device'):
                devid = config.get('id')
                if devid != None:
                    config['device'] = 'eth%d' % devid
                else:
                    config['device'] = ''

            if not config.has_key('network'):
                try:
                    config['network'] = \
                        XendNode.instance().bridge_to_network(
                        config.get('bridge')).uuid
                except Exception:
                    log.exception('bridge_to_network')
                    # Ignore this for now -- it may happen if the device
                    # has been specified using the legacy methods, but at
                    # some point we're going to have to figure out how to
                    # handle that properly.

            config['MTU'] = 1500 # TODO
            
            if self.state not in (XEN_API_VM_POWER_STATE_HALTED,):
                xennode = XendNode.instance()
                rx_bps, tx_bps = xennode.get_vif_util(self.domid, devid)
                config['io_read_kbs'] = rx_bps/1024
                config['io_write_kbs'] = tx_bps/1024
            else:
                config['io_read_kbs'] = 0.0
                config['io_write_kbs'] = 0.0                

        if dev_class == 'vbd':

            if self.state not in (XEN_API_VM_POWER_STATE_HALTED,):
                controller = self.getDeviceController(dev_class)
                devid, _1, _2 = controller.getDeviceDetails(config)
                xennode = XendNode.instance()
                rd_blkps, wr_blkps = xennode.get_vbd_util(self.domid, devid)
                config['io_read_kbs'] = rd_blkps
                config['io_write_kbs'] = wr_blkps
            else:
                config['io_read_kbs'] = 0.0
                config['io_write_kbs'] = 0.0                
            
            config['VDI'] = config.get('VDI', '')
            config['device'] = config.get('dev', '')
            if ':' in config['device']:
                vbd_name, vbd_type = config['device'].split(':', 1)
                config['device'] = vbd_name
                if vbd_type == 'cdrom':
                    config['type'] = XEN_API_VBD_TYPE[0]
                else:
                    config['type'] = XEN_API_VBD_TYPE[1]

            config['driver'] = 'paravirtualised' # TODO
            config['image'] = config.get('uname', '')

            if config.get('mode', 'r') == 'r':
                config['mode'] = 'RO'
            else:
                config['mode'] = 'RW'

        if dev_class == 'vtpm':
            if not config.has_key('type'):
                config['type'] = 'paravirtualised' # TODO
            if not config.has_key('backend'):
                config['backend'] = "00000000-0000-0000-0000-000000000000"

        return config

    def get_dev_property(self, dev_class, dev_uuid, field):
        config = self.get_dev_xenapi_config(dev_class, dev_uuid)
        try:
            return config[field]
        except KeyError:
            raise XendError('Invalid property for device: %s' % field)

    def set_dev_property(self, dev_class, dev_uuid, field, value):
        self.info['devices'][dev_uuid][1][field] = value

    def get_vcpus_util(self):
        vcpu_util = {}
        xennode = XendNode.instance()
        if 'vcpus_number' in self.info and self.domid != None:
            for i in range(0, self.info['vcpus_number']):
                util = xennode.get_vcpu_util(self.domid, i)
                vcpu_util[str(i)] = util
                
        return vcpu_util

    def get_consoles(self):
        return self.info.get('console_refs', [])

    def get_vifs(self):
        return self.info.get('vif_refs', [])

    def get_vbds(self):
        return self.info.get('vbd_refs', [])

    def get_vtpms(self):
        return self.info.get('vtpm_refs', [])

    def create_vbd(self, xenapi_vbd, vdi_image_path):
        """Create a VBD using a VDI from XendStorageRepository.

        @param xenapi_vbd: vbd struct from the Xen API
        @param vdi_image_path: VDI UUID
        @rtype: string
        @return: uuid of the device
        """
        xenapi_vbd['image'] = vdi_image_path
        log.debug('create_vbd: %s' % xenapi_vbd)
        dev_uuid = ''
        if vdi_image_path.startswith('tap'):
            dev_uuid = self.info.device_add('tap', cfg_xenapi = xenapi_vbd)
        else:
            dev_uuid = self.info.device_add('vbd', cfg_xenapi = xenapi_vbd)
            
        if not dev_uuid:
            raise XendError('Failed to create device')

        if self.state == XEN_API_VM_POWER_STATE_RUNNING:
            _, config = self.info['devices'][dev_uuid]
            dev_control = None
            
            if vdi_image_path.startswith('tap'):
                dev_control =  self.getDeviceController('tap')
            else:
                dev_control = self.getDeviceController('vbd')
                
            config['devid'] = dev_control.createDevice(config)

        return dev_uuid

    def create_phantom_vbd_with_vdi(self, xenapi_vbd, vdi_image_path):
        """Create a VBD using a VDI from XendStorageRepository.

        @param xenapi_vbd: vbd struct from the Xen API
        @param vdi_image_path: VDI UUID
        @rtype: string
        @return: uuid of the device
        """
        xenapi_vbd['image'] = vdi_image_path
        dev_uuid = self.info.phantom_device_add('tap', cfg_xenapi = xenapi_vbd)
        if not dev_uuid:
            raise XendError('Failed to create device')

        if self.state == XEN_API_VM_POWER_STATE_RUNNING:
            _, config = self.info['devices'][dev_uuid]
            config['devid'] = self.getDeviceController('tap').createDevice(config)

        return config['devid']

    def create_vif(self, xenapi_vif):
        """Create VIF device from the passed struct in Xen API format.

        @param xenapi_vif: Xen API VIF Struct.
        @rtype: string
        @return: UUID
        """
        dev_uuid = self.info.device_add('vif', cfg_xenapi = xenapi_vif)
        if not dev_uuid:
            raise XendError('Failed to create device')
        
        if self.state == XEN_API_VM_POWER_STATE_RUNNING:
            _, config = self.info['devices'][dev_uuid]
            config['devid'] = self.getDeviceController('vif').createDevice(config)

        return dev_uuid

    def create_vtpm(self, xenapi_vtpm):
        """Create a VTPM device from the passed struct in Xen API format.

        @return: uuid of the device
        @rtype: string
        """

        if self.state not in (DOM_STATE_HALTED,):
            raise VmError("Can only add vTPM to a halted domain.")
        if self.get_vtpms() != []:
            raise VmError('Domain already has a vTPM.')
        dev_uuid = self.info.device_add('vtpm', cfg_xenapi = xenapi_vtpm)
        if not dev_uuid:
            raise XendError('Failed to create device')

        return dev_uuid

    def create_console(self, xenapi_console):
        """ Create a console device from a Xen API struct.

        @return: uuid of device
        @rtype: string
        """
        if self.state not in (DOM_STATE_HALTED,):
            raise VmError("Can only add console to a halted domain.")

        dev_uuid = self.info.device_add('console', cfg_xenapi = xenapi_console)
        if not dev_uuid:
            raise XendError('Failed to create device')

        return dev_uuid

    def destroy_device_by_uuid(self, dev_type, dev_uuid):
        if dev_uuid not in self.info['devices']:
            raise XendError('Device does not exist')

        try:
            if self.state == XEN_API_VM_POWER_STATE_RUNNING:
                _, config = self.info['devices'][dev_uuid]
                devid = config.get('devid')
                if devid != None:
                    self.getDeviceController(dev_type).destroyDevice(devid, force = False)
                else:
                    raise XendError('Unable to get devid for device: %s:%s' %
                                    (dev_type, dev_uuid))
        finally:
            del self.info['devices'][dev_uuid]
            self.info['%s_refs' % dev_type].remove(dev_uuid)

    def destroy_vbd(self, dev_uuid):
        self.destroy_device_by_uuid('vbd', dev_uuid)

    def destroy_vif(self, dev_uuid):
        self.destroy_device_by_uuid('vif', dev_uuid)

    def destroy_vtpm(self, dev_uuid):
        self.destroy_device_by_uuid('vtpm', dev_uuid)
            
    def has_device(self, dev_class, dev_uuid):
        return (dev_uuid in self.info['%s_refs' % dev_class.lower()])

    def __str__(self):
        return '<domain id=%s name=%s memory=%s state=%s>' % \
               (str(self.domid), self.info['name_label'],
                str(self.info['memory_static_min']), DOM_STATES[self.state])

    __repr__ = __str__

