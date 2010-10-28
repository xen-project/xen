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
# Copyright (C) 2005-2007 XenSource Ltd
#============================================================================

"""Representation of a single domain.
Includes support for domain construction, using
open-ended configurations.

Author: Mike Wray <mike.wray@hp.com>

"""

import logging
import time
import threading
import thread
import re
import copy
import os
import stat
import shutil
import traceback
from types import StringTypes

import xen.lowlevel.xc
from xen.util import asserts, auxbin, mkdir
from xen.util.blkif import blkdev_uname_to_file, blkdev_uname_to_taptype
import xen.util.xsm.xsm as security
from xen.util import xsconstants
from xen.util import mkdir
from xen.util.pci import serialise_pci_opts, pci_opts_list_to_sxp, \
                         append_default_pci_opts, \
                         pci_dict_to_bdf_str, pci_dict_to_xc_str, \
                         pci_convert_sxp_to_dict, pci_convert_dict_to_sxp, \
                         pci_dict_cmp, PCI_DEVFN, PCI_SLOT, PCI_FUNC, parse_hex

from xen.xend import balloon, sxp, uuid, image, arch
from xen.xend import XendOptions, XendNode, XendConfig

from xen.xend.XendConfig import scrub_password
from xen.xend.XendBootloader import bootloader, bootloader_tidy
from xen.xend.XendError import XendError, VmError
from xen.xend.XendDevices import XendDevices
from xen.xend.XendTask import XendTask
from xen.xend.xenstore.xstransact import xstransact, complete
from xen.xend.xenstore.xsutil import GetDomainPath, IntroduceDomain, SetTarget, ResumeDomain
from xen.xend.xenstore.xswatch import xswatch
from xen.xend.XendConstants import *
from xen.xend.XendAPIConstants import *
from xen.xend.XendCPUPool import XendCPUPool
from xen.xend.server.DevConstants import xenbusState
from xen.xend.server.BlktapController import TapdiskController

from xen.xend.XendVMMetrics import XendVMMetrics

from xen.xend import XendAPIStore
from xen.xend.XendPPCI import XendPPCI
from xen.xend.XendDPCI import XendDPCI
from xen.xend.XendPSCSI import XendPSCSI
from xen.xend.XendDSCSI import XendDSCSI, XendDSCSI_HBA

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
    from xen.xend import XendDomain
    domconfig = XendConfig.XendConfig(sxp_obj = config)
    othervm = XendDomain.instance().domain_lookup_nr(domconfig["name_label"])
    if othervm is None or othervm.domid is None:
        othervm = XendDomain.instance().domain_lookup_nr(domconfig["uuid"])
    if othervm is not None and othervm.domid is not None:
        raise VmError("Domain '%s' already exists with ID '%d'" % (domconfig["name_label"], othervm.domid))
    log.debug("XendDomainInfo.create(%s)", scrub_password(config))
    vm = XendDomainInfo(domconfig)
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
    xeninfo['is_control_domain'] = priv
    xeninfo['is_a_template'] = False
    xeninfo['auto_power_on'] = False
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
            if not priv:
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

    vm = XendDomainInfo(xeninfo, domid, dompath, augment = True, priv = priv,
                        vmpath = vmpath)
    
    if needs_reinitialising:
        vm._recreateDom()
        vm._removeVm()
        vm._storeVmDetails()
        vm._storeDomDetails()
        
    vm.image = image.create(vm, vm.info)
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

from xen.xend.server.pciif import parse_pci_name, PciDevice,\
    get_assigned_pci_devices, get_all_assigned_pci_devices


def do_FLR(domid, is_hvm):
    dev_str_list = get_assigned_pci_devices(domid)

    for dev_str in dev_str_list:
        try:
            dev = PciDevice(parse_pci_name(dev_str))
        except Exception, e:
            raise VmError("pci: failed to locate device and "+
                    "parse it's resources - "+str(e))
        dev.do_FLR(is_hvm, xoptions.get_pci_dev_assign_strict_check())

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
    @ivar paused_by_admin: Is this Domain paused by command or API 
    @type paused_by_admin: bool 
    @ivar guest_bitsize: the bitsize of guest 
    @type guest_bitsize: int or None
    @ivar alloc_mem: the memory domain allocated when booting 
    @type alloc_mem: int or None 
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
    @ivar restart_in_progress: Is a domain restart thread running?
    @type restart_in_progress: bool
#    @ivar state: Domain state
#    @type state: enum(DOM_STATE_HALTED, DOM_STATE_RUNNING, ...)
    @ivar state_updated: lock for self.state
    @type state_updated: threading.Condition
    @ivar refresh_shutdown_lock: lock for polling shutdown state
    @type refresh_shutdown_lock: threading.Condition
    @ivar _deviceControllers: device controller cache for this domain
    @type _deviceControllers: dict 'string' to DevControllers
    """
    
    def __init__(self, info, domid = None, dompath = None, augment = False,
                 priv = False, resume = False, vmpath = None):
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
        self.guest_bitsize = None
        self.alloc_mem = None
        self.paused_by_admin = False

        maxmem = self.info.get('memory_static_max', 0)
        memory = self.info.get('memory_dynamic_max', 0)

        if self.info.is_hvm() and maxmem > memory:
            self.pod_enabled = True
        else:
            self.pod_enabled = False
        
        #REMOVE: uuid is now generated in XendConfig
        #if not self._infoIsSet('uuid'):
        #    self.info['uuid'] = uuid.toString(uuid.create())

        # Find a unique /vm/<uuid>/<integer> path if not specified.
        # This avoids conflict between pre-/post-migrate domains when doing
        # localhost relocation.
        self.vmpath = vmpath
        i = 0
        while self.vmpath == None:
            self.vmpath = XS_VMROOT + self.info['uuid']
            if i != 0:
                self.vmpath = self.vmpath + '-' + str(i)
            try:
                if self._readVm("uuid"):
                    self.vmpath = None
                    i = i + 1
            except:
                pass

        self.dompath = dompath

        self.image = None
        self.store_port = None
        self.store_mfn = None
        self.console_port = None
        self.console_mfn = None

        self.native_protocol = None

        self.vmWatch = None
        self.shutdownWatch = None
        self.shutdownStartTime = None
        self._resume = resume
        self.restart_in_progress = False

        self.state_updated = threading.Condition()
        self.refresh_shutdown_lock = threading.Condition()
        self._stateSet(DOM_STATE_HALTED)

        self._deviceControllers = {}

        for state in DOM_STATES_OLD:
            self.info[state] = 0

        if augment:
            self._augmentInfo(priv)

        self._checkName(self.info['name_label'])

        self.metrics = XendVMMetrics(uuid.createString(), self)
            

    #
    # Public functions available through XMLRPC
    #


    def start(self, is_managed = False):
        """Attempts to start the VM by do the appropriate
        initialisation if it not started.
        """
        from xen.xend import XendDomain

        if self._stateGet() in (XEN_API_VM_POWER_STATE_HALTED, XEN_API_VM_POWER_STATE_SUSPENDED, XEN_API_VM_POWER_STATE_CRASHED):
            try:
                XendTask.log_progress(0, 30, self._constructDomain)
                XendTask.log_progress(31, 60, self._initDomain)
                
                XendTask.log_progress(61, 70, self._storeVmDetails)
                XendTask.log_progress(71, 80, self._storeDomDetails)
                XendTask.log_progress(81, 90, self._registerWatches)
                XendTask.log_progress(91, 100, self.refreshShutdown)

                xendomains = XendDomain.instance()

                # save running configuration if XendDomains believe domain is
                # persistent
                if is_managed:
                    xendomains.managed_config_save(self)
            except:
                log.exception('VM start failed')
                self.destroy()
                raise
        else:
            raise XendError('VM already running')

    def resume(self):
        """Resumes a domain that has come back from suspension."""
        state = self._stateGet()
        if state in (DOM_STATE_SUSPENDED, DOM_STATE_HALTED):
            try:
                self._constructDomain()

                try:
                    self._setCPUAffinity()
                except:
                    # usually a CPU we want to set affinity to does not exist
                    # we just ignore it so that the domain can still be restored
                    log.warn("Cannot restore CPU affinity")

                self._setSchedParams()
                self._storeVmDetails()
                self._createChannels()
                self._createDevices()
                self._storeDomDetails()
                self._endRestore()
            except:
                log.exception('VM resume failed')
                self.destroy()
                raise
        else:
            raise XendError('VM is not suspended; it is %s'
                            % XEN_API_VM_POWER_STATE[state])

    def shutdown(self, reason):
        """Shutdown a domain by signalling this via xenstored."""
        log.debug('XendDomainInfo.shutdown(%s)', reason)
        if self._stateGet() in (DOM_STATE_SHUTDOWN, DOM_STATE_HALTED,):
            raise XendError('Domain cannot be shutdown')

        if self.domid == 0:
            raise XendError('Domain 0 cannot be shutdown')
        
        if reason not in DOMAIN_SHUTDOWN_REASONS.values():
            raise XendError('Invalid reason: %s' % reason)
        self.storeDom("control/shutdown", reason)

        # HVM domain shuts itself down only if it has PV drivers
        if self.info.is_hvm():
            hvm_pvdrv = xc.hvm_get_param(self.domid, HVM_PARAM_CALLBACK_IRQ)
            hvm_s_state = xc.hvm_get_param(self.domid, HVM_PARAM_ACPI_S_STATE)
            if not hvm_pvdrv or hvm_s_state != 0:
                code = REVERSE_DOMAIN_SHUTDOWN_REASONS[reason]
                log.info("HVM save:remote shutdown dom %d!", self.domid)
                xc.domain_shutdown(self.domid, code)

    def pause(self):
        """Pause domain
        
        @raise XendError: Failed pausing a domain
        """
        try:
            if(self.domid):
                # get all blktap2 devices
                dev =  xstransact.List(self.vmpath + '/device/tap2')
                for x in dev:
                    path = self.getDeviceController('tap2').readBackend(x, 'params')
                    if path and path.startswith(TapdiskController.TAP_DEV):
                        TapdiskController.pause(path)
        except Exception, ex:
            log.warn('Could not pause blktap disk.');

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
            if(self.domid):
                dev =  xstransact.List(self.vmpath + '/device/tap2')
                for x in dev:
                    path = self.getDeviceController('tap2').readBackend(x, 'params')
                    if path and path.startswith(TapdiskController.TAP_DEV):
                        TapdiskController.unpause(path)

        except Exception, ex:
            log.warn('Could not unpause blktap disk: %s' % str(ex));

        try:
            xc.domain_unpause(self.domid)
            self._stateSet(DOM_STATE_RUNNING)
        except Exception, ex:
            log.exception(ex)
            raise XendError("Domain unable to be unpaused: %s" % str(ex))

    def send_sysrq(self, key):
        """ Send a Sysrq equivalent key via xenstored."""
        if self._stateGet() not in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
            raise XendError("Domain '%s' is not started" % self.info['name_label'])

        asserts.isCharConvertible(key)
        self.storeDom("control/sysrq", '%c' % key)

    def pci_device_configure_boot(self):

        if not self.info.is_hvm():
            return

        devid = '0'
        first = True
        dev_info = self._getDeviceInfo_pci(devid)
        if dev_info is None:
            return

        # get the virtual slot info from xenstore
        dev_uuid = sxp.child_value(dev_info, 'uuid')
        pci_conf = self.info['devices'][dev_uuid][1]
        pci_devs = pci_conf['devs']

        # Keep a set of keys that are done rather than
        # just itterating through set(map(..., pci_devs))
        # to preserve any order information present.
        done = set()
        for key in map(lambda x: x['key'], pci_devs):
            if key in done:
                continue
            done |= set([key])
            dev = filter(lambda x: x['key'] == key, pci_devs)

            head_dev = dev.pop()
            dev_sxp = pci_convert_dict_to_sxp(head_dev, 'Initialising',
                                              'Booting')
            self.pci_device_configure(dev_sxp, first_dev = first)
            first = False

            # That is all for single-function virtual devices
            if len(dev) == 0:
                continue

            if int(head_dev['vdevfn'], 16) & AUTO_PHP_SLOT:
                new_dev_info = self._getDeviceInfo_pci(devid)
                if new_dev_info is None:
                    continue
                new_dev_uuid = sxp.child_value(new_dev_info, 'uuid')
                new_pci_conf = self.info['devices'][new_dev_uuid][1]
                new_pci_devs = new_pci_conf['devs']

                new_head_dev = filter(lambda x: pci_dict_cmp(x, head_dev),
                                      new_pci_devs)[0]

                if int(new_head_dev['vdevfn'], 16) & AUTO_PHP_SLOT:
                    continue

                vdevfn = PCI_SLOT(int(new_head_dev['vdevfn'], 16))
                new_dev = []
                for i in dev:
                    i['vdevfn'] = '0x%02x' % \
                                 PCI_DEVFN(vdevfn,
                                           PCI_FUNC(int(i['vdevfn'], 16)))
                    new_dev.append(i)

                dev = new_dev

            for i in dev:
                dev_sxp = pci_convert_dict_to_sxp(i, 'Initialising', 'Booting')
                self.pci_device_configure(dev_sxp)

    def hvm_pci_device_create(self, dev_config):
        log.debug("XendDomainInfo.hvm_pci_device_create: %s"
                  % scrub_password(dev_config))

        if not self.info.is_hvm():
            raise VmError("hvm_pci_device_create called on non-HVM guest")

        #all the PCI devs share one conf node
        devid = '0'

        new_dev = dev_config['devs'][0]
        dev_info = self._getDeviceInfo_pci(devid)#from self.info['devices']

        #check conflict before trigger hotplug event
        if dev_info is not None:
            dev_uuid = sxp.child_value(dev_info, 'uuid')
            pci_conf = self.info['devices'][dev_uuid][1]
            pci_devs = pci_conf['devs']
            for x in pci_devs:
                if (int(x['vdevfn'], 16) == int(new_dev['vdevfn'], 16) and
                    not int(x['vdevfn'], 16) & AUTO_PHP_SLOT):
                    raise VmError("vdevfn %s already have a device." %
                                  (new_dev['vdevfn']))

                if (pci_dict_cmp(x, new_dev)):
                    raise VmError("device is already inserted")

        # Test whether the devices can be assigned.
        self.pci_dev_check_attachability_and_do_FLR(new_dev)

        return self.hvm_pci_device_insert_dev(new_dev)

    def iommu_check_pod_mode(self):
        """ Disallow PCI device assignment if pod is enabled. """
        if self.pod_enabled:
            raise VmError("failed to assign device since pod is enabled")

    def pci_dev_check_assignability_and_do_FLR(self, config):
        """ In the case of static device assignment(i.e., the 'pci' string in
        guest config file), we check if the device(s) specified in the 'pci'
        can be  assigned to guest or not; if yes, we do_FLR the device(s).
        """

        self.iommu_check_pod_mode()
        pci_dev_ctrl = self.getDeviceController('pci')
        return pci_dev_ctrl.dev_check_assignability_and_do_FLR(config)

    def pci_dev_check_attachability_and_do_FLR(self, new_dev):
        """ In the case of dynamic device assignment(i.e., xm pci-attach), we
        check if the device can be attached to guest or not; if yes, we do_FLR
        the device.
        """

        self.iommu_check_pod_mode()

        # Test whether the devices can be assigned

        pci_name = pci_dict_to_bdf_str(new_dev)
        _all_assigned_pci_devices =  get_all_assigned_pci_devices(self.domid)
        if pci_name in _all_assigned_pci_devices:
            raise VmError("failed to assign device %s that has"
                          " already been assigned to other domain." % pci_name)

        # Test whether the device is owned by pciback or pci-stub.
        try:
            pci_device = PciDevice(new_dev)
        except Exception, e:
            raise VmError("pci: failed to locate device and "+
                    "parse its resources - "+str(e))
        if pci_device.driver!='pciback' and pci_device.driver!='pci-stub':
            raise VmError(("pci: PCI Backend and pci-stub don't own device %s")\
                            %pci_device.name)

        strict_check = xoptions.get_pci_dev_assign_strict_check()
        # Check non-page-aligned MMIO BAR.
        if pci_device.has_non_page_aligned_bar and strict_check:
            raise VmError("pci: %s: non-page-aligned MMIO BAR found." % \
                pci_device.name)

        # PV guest has less checkings.
        if not self.info.is_hvm():
            # try to do FLR for PV guest
            pci_device.do_FLR(self.info.is_hvm(), strict_check)
            return

        if not strict_check:
            return

        # Check if there is intermediate PCIe switch bewteen the device and
        # Root Complex.
        if pci_device.is_behind_switch_lacking_acs():
            err_msg = 'pci: to avoid potential security issue, %s is not'+\
                    ' allowed to be assigned to guest since it is behind'+\
                    ' PCIe switch that does not support or enable ACS.'
            raise VmError(err_msg % pci_device.name)

        # Check the co-assignment.
        # To pci-attach a device D to domN, we should ensure each of D's
        # co-assignment devices hasn't been assigned, or has been assigned to
        # domN.
        coassignment_list = pci_device.find_coassigned_devices()
        pci_device.devs_check_driver(coassignment_list)
        assigned_pci_device_str_list = self._get_assigned_pci_devices()
        for pci_str in coassignment_list:
            if not (pci_str in _all_assigned_pci_devices):
                continue
            if not pci_str in assigned_pci_device_str_list:
                raise VmError(("pci: failed to pci-attach %s to domain %s" + \
                    " because one of its co-assignment device %s has been" + \
                    " assigned to other domain." \
                    )% (pci_device.name, self.info['name_label'], pci_str))

        # try to do FLR for HVM guest
        pci_device.do_FLR(self.info.is_hvm(), strict_check)

    def hvm_pci_device_insert(self, dev_config):
        log.debug("XendDomainInfo.hvm_pci_device_insert: %s"
                  % scrub_password(dev_config))

        if not self.info.is_hvm():
            raise VmError("hvm_pci_device_create called on non-HVM guest")

        new_dev = dev_config['devs'][0]

        return self.hvm_pci_device_insert_dev(new_dev)

    def hvm_pci_device_insert_dev(self, new_dev):
        log.debug("XendDomainInfo.hvm_pci_device_insert_dev: %s"
                  % scrub_password(new_dev))

        if self.domid is not None:
            opts = ''
            optslist = []
            pci_defopts = []
            if 'pci_msitranslate' in self.info['platform']:
                pci_defopts.append(['msitranslate',
                        str(self.info['platform']['pci_msitranslate'])])
            if 'pci_power_mgmt' in self.info['platform']:
                pci_defopts.append(['power_mgmt',
                        str(self.info['platform']['pci_power_mgmt'])])
            if new_dev.has_key('opts'):
                optslist += new_dev['opts']

            if optslist or pci_defopts:
                opts = ',' + serialise_pci_opts(
                       append_default_pci_opts(optslist, pci_defopts))

            bdf_str = "%s@%02x%s" % (pci_dict_to_bdf_str(new_dev),
                                     int(new_dev['vdevfn'], 16), opts)
            log.debug("XendDomainInfo.hvm_pci_device_insert_dev: %s" % bdf_str)
            bdf = xc.assign_device(self.domid, pci_dict_to_xc_str(new_dev))
            if bdf > 0:
                raise VmError("Failed to assign device to IOMMU (%s)" % bdf_str)
            log.debug("pci: assign device %s" % bdf_str)
            self.image.signalDeviceModel('pci-ins', 'pci-inserted', bdf_str)

            vdevfn = xstransact.Read("/local/domain/0/device-model/%i/parameter"
                                    % self.getDomid())
            try:
                vdevfn_int = int(vdevfn, 16)
            except ValueError:
                raise VmError(("Cannot pass-through PCI function '%s'. " +
                               "Device model reported an error: %s") %
                              (bdf_str, vdevfn))
        else:
            vdevfn = new_dev['vdevfn']

        return vdevfn


    def device_create(self, dev_config):
        """Create a new device.

        @param dev_config: device configuration
        @type  dev_config: SXP object (parsed config)
        """
        log.debug("XendDomainInfo.device_create: %s" % scrub_password(dev_config))
        dev_type = sxp.name(dev_config)

        if dev_type == 'vif':
            for x in dev_config:
                if x != 'vif' and x[0] == 'mac':
                    if not re.match('^([0-9a-f]{2}:){5}[0-9a-f]{2}$', x[1], re.I):
                        log.error("Virtual network interface creation error - invalid MAC Address entered: %s", x[1])
                        raise VmError("Cannot create a new virtual network interface - MAC address is not valid!");

        dev_uuid = self.info.device_add(dev_type, cfg_sxp = dev_config)
        dev_config_dict = self.info['devices'][dev_uuid][1]
        log.debug("XendDomainInfo.device_create: %s" % scrub_password(dev_config_dict))

        if self.domid is not None:
            try:
                dev_config_dict['devid'] = devid = \
                    self._createDevice(dev_type, dev_config_dict)
                if dev_type == 'tap2':
                    # createDevice may create a blktap1 device if blktap2 is not
                    # installed or if the blktap driver is not supported in
                    # blktap1
                    dev_type = self.getBlockDeviceClass(devid)
                self._waitForDevice(dev_type, devid)
            except VmError, ex:
                del self.info['devices'][dev_uuid]
                if dev_type == 'pci':
                    for dev in dev_config_dict['devs']:
                        XendAPIStore.deregister(dev['uuid'], 'DPCI')
                elif dev_type == 'vscsi':
                    for dev in dev_config_dict['devs']:
                        XendAPIStore.deregister(dev['uuid'], 'DSCSI')
                elif dev_type == 'tap' or dev_type == 'tap2':
                    self.info['vbd_refs'].remove(dev_uuid)
                else:
                    self.info['%s_refs' % dev_type].remove(dev_uuid)
                raise ex
        else:
            devid = None

        xen.xend.XendDomain.instance().managed_config_save(self)
        return self.getDeviceController(dev_type).sxpr(devid)


    def pci_device_configure(self, dev_sxp, devid = 0, first_dev = False):
        """Configure an existing pci device.
        
        @param dev_sxp: device configuration
        @type  dev_sxp: SXP object (parsed config)
        @param devid:      device id
        @type  devid:      int
        @return: Returns True if successfully updated device
        @rtype: boolean
        """
        log.debug("XendDomainInfo.pci_device_configure: %s"
                  % scrub_password(dev_sxp))

        dev_class = sxp.name(dev_sxp)

        if dev_class != 'pci':
            return False

        pci_state = sxp.child_value(dev_sxp, 'state')
        pci_sub_state = sxp.child_value(dev_sxp, 'sub_state')
        existing_dev_info = self._getDeviceInfo_pci(devid)

        if existing_dev_info is None and pci_state != 'Initialising':
            raise XendError("Cannot detach when pci platform does not exist")

        pci_dev = sxp.children(dev_sxp, 'dev')[0]
        dev_config = pci_convert_sxp_to_dict(dev_sxp)
        dev = dev_config['devs'][0]

        stubdomid = self.getStubdomDomid()
        # Do HVM specific processing
        if self.info.is_hvm():
            from xen.xend import XendDomain
            if pci_state == 'Initialising':
                if stubdomid is not None :
                    XendDomain.instance().domain_lookup(stubdomid).pci_device_configure(dev_sxp[:])

                # HVM PCI device attachment
                if pci_sub_state == 'Booting':
                    vdevfn = self.hvm_pci_device_insert(dev_config)
                else:
                    vdevfn = self.hvm_pci_device_create(dev_config)
                # Update vdevfn
                dev['vdevfn'] = vdevfn
                for n in sxp.children(pci_dev):
                    if(n[0] == 'vdevfn'):
                        n[1] = vdevfn
            else:
                # HVM PCI device detachment
                existing_dev_uuid = sxp.child_value(existing_dev_info, 'uuid')
                existing_pci_conf = self.info['devices'][existing_dev_uuid][1]
                existing_pci_devs = existing_pci_conf['devs']
                new_devs = filter(lambda x: pci_dict_cmp(x, dev),
                                  existing_pci_devs)
                if len(new_devs) < 0:
                    raise VmError("Device %s is not connected" %
                                  pci_dict_to_bdf_str(dev))
                new_dev = new_devs[0]
                # Only tell qemu-dm to unplug function 0.
                # When unplugging a function, all functions in the
                # same vslot must be unplugged, and function 0 must
                # be one of the functions present when a vslot is
                # hot-plugged. Telling qemu-dm to unplug function 0
                # also tells it to unplug all other functions in the
                # same vslot.
                if (PCI_FUNC(int(new_dev['vdevfn'], 16)) == 0):
                    self.hvm_destroyPCIDevice(new_dev)
                if stubdomid is not None :
                    XendDomain.instance().domain_lookup(stubdomid).pci_device_configure(dev_sxp[:])
                # Update vdevfn
                dev['vdevfn'] = new_dev['vdevfn']
                for n in sxp.children(pci_dev):
                    if(n[0] == 'vdevfn'):
                        n[1] = new_dev['vdevfn']
        else:
        # Do PV specific checking
            if pci_state == 'Initialising':
                # PV PCI device attachment
                self.pci_dev_check_attachability_and_do_FLR(dev)

        # If pci platform does not exist, create and exit.
        if existing_dev_info is None :
            self.device_create(dev_sxp)
            return True

        if first_dev is True :
            existing_dev_uuid = sxp.child_value(existing_dev_info, 'uuid')
            existing_pci_conf = self.info['devices'][existing_dev_uuid][1]
            devid = self._createDevice('pci', existing_pci_conf)
            self.info['devices'][existing_dev_uuid][1]['devid'] = devid

        if self.domid is not None:
            # use DevController.reconfigureDevice to change device config
            dev_control = self.getDeviceController(dev_class)
            dev_uuid = dev_control.reconfigureDevice(devid, dev_config)
            if not self.info.is_hvm() and not self.info.is_stubdom():
                # in PV case, wait until backend state becomes connected.
                dev_control.waitForDevice_reconfigure(devid)
            num_devs = dev_control.cleanupDevice(devid)

            # update XendConfig with new device info
            if dev_uuid:
                new_dev_sxp = dev_control.configuration(devid)
                self.info.device_update(dev_uuid, new_dev_sxp)

            # If there is no device left, destroy pci and remove config.
            if num_devs == 0:
                if self.info.is_hvm():
                    self.destroyDevice('pci', devid, True)
                else:
                    self.destroyDevice('pci', devid)
                del self.info['devices'][dev_uuid]
        else:
            new_dev_sxp = ['pci']
            for cur_dev in sxp.children(existing_dev_info, 'dev'):
                if pci_state == 'Closing':
                    if int(dev['domain'], 16) == int(sxp.child_value(cur_dev, 'domain'), 16) and \
                       int(dev['bus'], 16) == int(sxp.child_value(cur_dev, 'bus'), 16) and \
                       int(dev['slot'], 16) == int(sxp.child_value(cur_dev, 'slot'), 16) and \
                       int(dev['func'], 16) == int(sxp.child_value(cur_dev, 'func'), 16):
                        continue
                new_dev_sxp.append(cur_dev)

            if pci_state == 'Initialising' and pci_sub_state != 'Booting':
                for new_dev in sxp.children(dev_sxp, 'dev'):
                    new_dev_sxp.append(new_dev)

            dev_uuid = sxp.child_value(existing_dev_info, 'uuid')
            self.info.device_update(dev_uuid, new_dev_sxp)

            # If there is no device left, remove config.
            if len(sxp.children(new_dev_sxp, 'dev')) == 0:
                del self.info['devices'][dev_uuid]

        xen.xend.XendDomain.instance().managed_config_save(self)

        return True

    def vscsi_device_configure(self, dev_sxp):
        """Configure an existing vscsi device.
            quoted pci funciton
        """
        def _is_vscsi_defined(dev_info, p_devs = None, v_devs = None):
            if not dev_info:
                return False
            for dev in sxp.children(dev_info, 'dev'):
                if p_devs is not None:
                    if sxp.child_value(dev, 'p-dev') in p_devs:
                        return True
                if v_devs is not None:
                    if sxp.child_value(dev, 'v-dev') in v_devs:
                        return True
            return False

        def _vscsi_be(be):
            be_xdi = xen.xend.XendDomain.instance().domain_lookup_nr(be)
            if be_xdi is not None:
                be_domid = be_xdi.getDomid()
                if be_domid is not None:
                    return str(be_domid)
            return str(be)

        dev_class = sxp.name(dev_sxp)
        if dev_class != 'vscsi':
            return False

        dev_config = self.info.vscsi_convert_sxp_to_dict(dev_sxp)
        devs = dev_config['devs']
        v_devs = [d['v-dev'] for d in devs]
        state = devs[0]['state']
        req_devid = int(devs[0]['devid'])
        cur_dev_sxp = self._getDeviceInfo_vscsi(req_devid)

        if state == xenbusState['Initialising']:
            # new create
            # If request devid does not exist, create and exit.
            p_devs = [d['p-dev'] for d in devs]
            for dev_type, dev_info in self.info.all_devices_sxpr():
                if dev_type != 'vscsi':
                    continue
                if _is_vscsi_defined(dev_info, p_devs = p_devs):
                    raise XendError('The physical device "%s" is already defined' % \
                                    p_devs[0])
            if cur_dev_sxp is None:
                self.device_create(dev_sxp)
                return True

            if _is_vscsi_defined(cur_dev_sxp, v_devs = v_devs):
                raise XendError('The virtual device "%s" is already defined' % \
                                v_devs[0])

            if int(dev_config['feature-host']) != \
               int(sxp.child_value(cur_dev_sxp, 'feature-host')):
                raise XendError('The physical device "%s" cannot define '
                                'because mode is different' % devs[0]['p-dev'])

            new_be = dev_config.get('backend', None)
            if new_be is not None:
                cur_be = sxp.child_value(cur_dev_sxp, 'backend', None)
                if cur_be is None:
                    cur_be = xen.xend.XendDomain.DOM0_ID
                new_be_dom = _vscsi_be(new_be)
                cur_be_dom = _vscsi_be(cur_be)
                if new_be_dom != cur_be_dom:
                    raise XendError('The physical device "%s" cannot define '
                                    'because backend is different' % devs[0]['p-dev'])

        elif state == xenbusState['Closing']:
            if not _is_vscsi_defined(cur_dev_sxp, v_devs = v_devs):
                raise XendError("Cannot detach vscsi device does not exist")

        if self.domid is not None:
            # use DevController.reconfigureDevice to change device config
            dev_control = self.getDeviceController(dev_class)
            dev_uuid = dev_control.reconfigureDevice(req_devid, dev_config)
            dev_control.waitForDevice_reconfigure(req_devid)
            num_devs = dev_control.cleanupDevice(req_devid)

            # update XendConfig with new device info
            if dev_uuid:
                new_dev_sxp = dev_control.configuration(req_devid)
                self.info.device_update(dev_uuid, new_dev_sxp)

            # If there is no device left, destroy vscsi and remove config.
            if num_devs == 0:
                self.destroyDevice('vscsi', req_devid)
                del self.info['devices'][dev_uuid]

        else:
            new_dev_sxp = ['vscsi']
            cur_mode = sxp.children(cur_dev_sxp, 'feature-host')[0]
            new_dev_sxp.append(cur_mode)
            try:
                cur_be = sxp.children(cur_dev_sxp, 'backend')[0]
                new_dev_sxp.append(cur_be)
            except IndexError:
                pass

            for cur_dev in sxp.children(cur_dev_sxp, 'dev'):
                if state == xenbusState['Closing']:
                    if int(cur_mode[1]) == 1:
                        continue
                    if sxp.child_value(cur_dev, 'v-dev') in v_devs:
                        continue
                new_dev_sxp.append(cur_dev)

            if state == xenbusState['Initialising']:
                for new_dev in sxp.children(dev_sxp, 'dev'):
                    new_dev_sxp.append(new_dev)

            dev_uuid = sxp.child_value(cur_dev_sxp, 'uuid')
            self.info.device_update(dev_uuid, new_dev_sxp)

            # If there is only 'vscsi' in new_dev_sxp, remove the config.
            if len(sxp.children(new_dev_sxp, 'dev')) == 0:
                del self.info['devices'][dev_uuid]

        xen.xend.XendDomain.instance().managed_config_save(self)

        return True

    def vusb_device_configure(self, dev_sxp, devid):
        """Configure a virtual root port.
        """
        dev_class = sxp.name(dev_sxp)
        if dev_class != 'vusb':
            return False

        dev_config = {}
        ports = sxp.child(dev_sxp, 'port')
        for port in ports[1:]:
            try:
                num, bus = port
                dev_config['port-%i' % int(num)] = str(bus)
            except TypeError:
                pass

        dev_control = self.getDeviceController(dev_class)
        dev_control.reconfigureDevice(devid, dev_config)

        return True

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

        if dev_class == 'pci':
            return self.pci_device_configure(dev_sxp)

        if dev_class == 'vscsi':
            return self.vscsi_device_configure(dev_sxp)

        if dev_class == 'vusb':
            return self.vusb_device_configure(dev_sxp, devid)

        for opt_val in dev_sxp[1:]:
            try:
                dev_config[opt_val[0]] = opt_val[1]
            except IndexError:
                pass

        dev_control = self.getDeviceController(dev_class)
        if devid is None:
            dev = dev_config.get('dev', '')
            if not dev:
                raise VmError('Block device must have virtual details specified')
            if 'ioemu:' in dev:
                (_, dev) = dev.split(':', 1)
            try:
                (dev, _) = dev.split(':', 1)  # Remove ":disk" or ":cdrom"
            except ValueError:
                pass
            devid = dev_control.convertToDeviceNumber(dev)
        dev_info = self._getDeviceInfo_vbd(devid)
        if dev_info is None:
            raise VmError("Device %s not connected" % devid)
        dev_uuid = sxp.child_value(dev_info, 'uuid')

        if self.domid is not None:
            # use DevController.reconfigureDevice to change device config
            dev_control.reconfigureDevice(devid, dev_config)
        else:
            (_, new_b, new_f) = dev_control.getDeviceDetails(dev_config)
            if (new_f['device-type'] == 'cdrom' and
                sxp.child_value(dev_info, 'dev').endswith(':cdrom') and
                new_b['mode'] == 'r' and
                sxp.child_value(dev_info, 'mode') == 'r'):
                pass
            else:
                raise VmError('Refusing to reconfigure device %s:%d to %s' %
                              (dev_class, devid, dev_config))

        # update XendConfig with new device info
        self.info.device_update(dev_uuid, dev_sxp)
        xen.xend.XendDomain.instance().managed_config_save(self)

        return True

    def waitForDevices(self):
        """Wait for this domain's configured devices to connect.

        @raise VmError: if any device fails to initialise.
        """
        for devclass in XendDevices.valid_devices():
            self.getDeviceController(devclass).waitForDevices()

    def hvm_destroyPCIDevice(self, pci_dev):
        log.debug("hvm_destroyPCIDevice: %s", pci_dev)

        if not self.info.is_hvm():
            raise VmError("hvm_destroyPCIDevice called on non-HVM guest")

        # Check the co-assignment.
        # To pci-detach a device D from domN, we should ensure: for each DD in the
        # list of D's co-assignment devices, DD is not assigned (to domN).
        # 
        from xen.xend.server.pciif import PciDevice
        try:
            pci_device = PciDevice(pci_dev)
        except Exception, e:
            raise VmError("pci: failed to locate device and "+
                    "parse its resources - "+str(e))
        coassignment_list = pci_device.find_coassigned_devices()
        coassignment_list.remove(pci_device.name)
        assigned_pci_device_str_list = self._get_assigned_pci_devices()
        for pci_str in coassignment_list:
            if xoptions.get_pci_dev_assign_strict_check() and \
                pci_str in assigned_pci_device_str_list:
                raise VmError(("pci: failed to pci-detach %s from domain %s" + \
                    " because one of its co-assignment device %s is still " + \
                    " assigned to the domain." \
                    )% (pci_device.name, self.info['name_label'], pci_str))


        bdf_str = pci_dict_to_bdf_str(pci_dev)
        log.info("hvm_destroyPCIDevice:%s:%s!", pci_dev, bdf_str)
        if self.domid is not None:
            self.image.signalDeviceModel('pci-rem', 'pci-removed', bdf_str)

        return 0

    def destroyDevice(self, deviceClass, devid, force = False, rm_cfg = False):
        log.debug("XendDomainInfo.destroyDevice: deviceClass = %s, device = %s",
                  deviceClass, devid)

        if rm_cfg:
            # Convert devid to device number.  A device number is
            # needed to remove its configuration.
            dev = self.getDeviceController(deviceClass).convertToDeviceNumber(devid)
            
            # Save current sxprs.  A device number and a backend
            # path are needed to remove its configuration but sxprs
            # do not have those after calling destroyDevice.
            sxprs = self.getDeviceSxprs(deviceClass)

        rc = None
        if self.domid is not None:
            
            #new blktap implementation may need a sysfs write after everything is torn down.
            if deviceClass == 'tap2':
                dev = self.getDeviceController(deviceClass).convertToDeviceNumber(devid)
                path = self.getDeviceController(deviceClass).readBackend(dev, 'params')
                frontpath = self.getDeviceController(deviceClass).frontendPath(dev)
                backpath = xstransact.Read(frontpath, "backend")
                thread.start_new_thread(self.getDeviceController(deviceClass).finishDeviceCleanup, (backpath, path))

            rc = self.getDeviceController(deviceClass).destroyDevice(devid, force)
            if not force and rm_cfg:
                # The backend path, other than the device itself,
                # has to be passed because its accompanied frontend
                # path may be void until its removal is actually
                # issued.  It is probable because destroyDevice is
                # issued first.
                for dev_num, dev_info in sxprs:
                    dev_num = int(dev_num)
                    if dev_num == dev:
                        for x in dev_info:
                            if x[0] == 'backend':
                                backend = x[1]
                                break
                        break
                self._waitForDevice_destroy(deviceClass, devid, backend)

        if rm_cfg and deviceClass != "vif2":
            if deviceClass == 'vif':
                if self.domid is not None:
                    mac = ''
                    for dev_num, dev_info in sxprs:
                        dev_num = int(dev_num)
                        if dev_num == dev:
                            for x in dev_info:
                                if x[0] == 'mac':
                                    mac = x[1]
                                    break
                            break
                    dev_info = self._getDeviceInfo_vif(mac)
                else:
                    _, dev_info = sxprs[dev]
            else:  # 'vbd' or 'tap' or 'tap2'
                dev_info = self._getDeviceInfo_vbd(dev)
                # To remove the UUID of the device from refs,
                # deviceClass must be always 'vbd'.
                deviceClass = 'vbd'
            if dev_info is None:
                raise XendError("Device %s is not defined" % devid)

            dev_uuid = sxp.child_value(dev_info, 'uuid')
            del self.info['devices'][dev_uuid]
            self.info['%s_refs' % deviceClass].remove(dev_uuid)
            xen.xend.XendDomain.instance().managed_config_save(self)

        return rc

    def getDeviceSxprs(self, deviceClass):
        if deviceClass == 'pci':
            dev_info = self._getDeviceInfo_pci('0')#from self.info['devices']
            if dev_info is None:
                return []
            dev_uuid = sxp.child_value(dev_info, 'uuid')
            pci_devs = self.info['devices'][dev_uuid][1]['devs']
            return pci_devs
        if self._stateGet() in (DOM_STATE_RUNNING, DOM_STATE_PAUSED, DOM_STATE_CRASHED):
            return self.getDeviceController(deviceClass).sxprs()
        else:
            sxprs = []
            dev_num = 0
            for dev_type, dev_info in self.info.all_devices_sxpr():
                if (deviceClass == 'vbd' and dev_type not in ['vbd', 'tap', 'tap2']) or \
                   (deviceClass != 'vbd' and dev_type != deviceClass):
                    continue

                if deviceClass == 'vscsi':
                    vscsi_devs = ['devs', []]
                    for vscsi_dev in sxp.children(dev_info, 'dev'):
                        vscsi_dev.append(['frontstate', None])
                        vscsi_devs[1].append(vscsi_dev)
                        dev_num = int(sxp.child_value(vscsi_dev, 'devid'))
                    vscsi_mode = sxp.children(dev_info, 'feature-host')[0]
                    sxprs.append([dev_num, [vscsi_devs, vscsi_mode]])
                elif deviceClass == 'vbd':
                    dev = sxp.child_value(dev_info, 'dev')
                    if 'ioemu:' in dev:
                        (_, dev) = dev.split(':', 1)
                    try:
                        (dev_name, _) = dev.split(':', 1)  # Remove ":disk" or ":cdrom"
                    except ValueError:
                        dev_name = dev
                    dev_num = self.getDeviceController('vbd').convertToDeviceNumber(dev_name)
                    sxprs.append([dev_num, dev_info])
                else:
                    sxprs.append([dev_num, dev_info])
                    dev_num += 1
            return sxprs

    def getBlockDeviceClass(self, devid):
        # if the domain is running we can get the device class from xenstore.
        # This is more accurate, as blktap1 devices show up as blktap2 devices
        # in the config.
        if self._stateGet() in (DOM_STATE_RUNNING, DOM_STATE_PAUSED, DOM_STATE_CRASHED):
            # All block devices have a vbd frontend, so we know the frontend path
            dev = self.getDeviceController('vbd').convertToDeviceNumber(devid)
            frontendPath = "%s/device/vbd/%s" % (self.dompath, dev)
            for devclass in XendDevices.valid_devices():
                for dev in xstransact.List("%s/device/%s" % (self.vmpath, devclass)):
                    devFrontendPath = xstransact.Read("%s/device/%s/%s/frontend" % (self.vmpath, devclass, dev))
                    if frontendPath == devFrontendPath:
                        return devclass

        else: # the domain is not active so we must get the device class
              # from the config
            # To get a device number from the devid,
            # we temporarily use the device controller of VBD.
            dev = self.getDeviceController('vbd').convertToDeviceNumber(devid)
            dev_info = self._getDeviceInfo_vbd(dev)
            if dev_info:
                return dev_info[0]

    def _getDeviceInfo_vif(self, mac):
        for dev_type, dev_info in self.info.all_devices_sxpr():
            if dev_type != 'vif':
                continue
            if mac == sxp.child_value(dev_info, 'mac'):
                return dev_info

    def _getDeviceInfo_vbd(self, devid):
        for dev_type, dev_info in self.info.all_devices_sxpr():
            if dev_type != 'vbd' and dev_type != 'tap' and dev_type != 'tap2':
                continue
            dev = sxp.child_value(dev_info, 'dev')
            dev = dev.split(':')[0]
            dev = self.getDeviceController(dev_type).convertToDeviceNumber(dev)
            if devid == dev:
                return dev_info

    def _getDeviceInfo_pci(self, devid):
        for dev_type, dev_info in self.info.all_devices_sxpr():
            if dev_type != 'pci':
                continue
            return dev_info
        return None

    def _getDeviceInfo_vscsi(self, devid):
        devid = int(devid)
        for dev_type, dev_info in self.info.all_devices_sxpr():
            if dev_type != 'vscsi':
                continue
            devs = sxp.children(dev_info, 'dev')
            if devid == int(sxp.child_value(devs[0], 'devid')):
                return dev_info
        return None

    def _getDeviceInfo_vusb(self, devid):
        for dev_type, dev_info in self.info.all_devices_sxpr():
            if dev_type != 'vusb':
                continue
            return dev_info
        return None

    def _get_assigned_pci_devices(self, devid = 0):
        if self.domid is not None:
            return get_assigned_pci_devices(self.domid)

        dev_info = self._getDeviceInfo_pci(devid)
        if dev_info is None:
            return []
        dev_uuid = sxp.child_value(dev_info, 'uuid')
        pci_conf = self.info['devices'][dev_uuid][1]
        return map(pci_dict_to_bdf_str, pci_conf['devs'])

    def setMemoryTarget(self, target):
        """Set the memory target of this domain.
        @param target: In MiB.
        """
        log.debug("Setting memory target of domain %s (%s) to %d MiB.",
                  self.info['name_label'], str(self.domid), target)
        
        MiB = 1024 * 1024
        memory_cur = self.get_memory_dynamic_max() / MiB

        if self.domid == 0:
            dom0_min_mem = xoptions.get_dom0_min_mem()
            if target < memory_cur and dom0_min_mem > target:
                raise XendError("memory_dynamic_max too small")

        self._safe_set_memory('memory_dynamic_min', target * MiB)
        self._safe_set_memory('memory_dynamic_max', target * MiB)

        if self.domid >= 0:
            if target > memory_cur:
                balloon.free((target - memory_cur) * 1024, self)
            self.storeVm("memory", target)
            self.storeDom("memory/target", target << 10)
            xc.domain_set_target_mem(self.domid,
                                     (target * 1024))
        xen.xend.XendDomain.instance().managed_config_save(self)

    def setMemoryMaximum(self, limit):
        """Set the maximum memory limit of this domain
        @param limit: In MiB.
        """
        log.debug("Setting memory maximum of domain %s (%s) to %d MiB.",
                  self.info['name_label'], str(self.domid), limit)

        maxmem_cur = self.get_memory_static_max()
        MiB = 1024 * 1024
        self._safe_set_memory('memory_static_max', limit * MiB)

        if self.domid >= 0:
            maxmem = int(limit) * 1024
            try:
                return xc.domain_setmaxmem(self.domid, maxmem)
            except Exception, ex:
                self._safe_set_memory('memory_static_max', maxmem_cur)
                raise XendError(str(ex))
        xen.xend.XendDomain.instance().managed_config_save(self)


    def getVCPUInfo(self):
        try:
            # We include the domain name and ID, to help xm.
            sxpr = ['domain',
                    ['domid',      self.domid],
                    ['name',       self.info['name_label']],
                    ['vcpu_count', self.info['VCPUs_max']]]

            for i in range(0, self.info['VCPUs_max']):
                if self.domid is not None:
                    info = xc.vcpu_getinfo(self.domid, i)

                    sxpr.append(['vcpu',
                                 ['number',   i],
                                 ['online',   info['online']],
                                 ['blocked',  info['blocked']],
                                 ['running',  info['running']],
                                 ['cpu_time', info['cpu_time'] / 1e9],
                                 ['cpu',      info['cpu']],
                                 ['cpumap',   info['cpumap']]])
                else:
                    sxpr.append(['vcpu',
                                 ['number',   i],
                                 ['online',   0],
                                 ['blocked',  0],
                                 ['running',  0],
                                 ['cpu_time', 0.0],
                                 ['cpu',      -1],
                                 ['cpumap',   self.info['cpus'][i] and \
                                              self.info['cpus'][i] or range(64)]])

            return sxpr

        except RuntimeError, exn:
            raise XendError(str(exn))


    def getDomInfo(self):
        return dom_get(self.domid)

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
            val = vm_config[arg]
            if val != None:
                if arg in XendConfig.LEGACY_CFG_TO_XENAPI_CFG:
                    xapiarg = XendConfig.LEGACY_CFG_TO_XENAPI_CFG[arg]
                    self.info[xapiarg] = val
                elif arg == "memory":
                    self.info["static_memory_min"] = val
                elif arg == "maxmem":
                    self.info["static_memory_max"] = val
                else:
                    self.info[arg] = val

        # read CPU Affinity
        self.info['cpus'] = []
        vcpus_info = self.getVCPUInfo()
        for vcpu_info in sxp.children(vcpus_info, 'vcpu'):
            self.info['cpus'].append(sxp.child_value(vcpu_info, 'cpumap'))

        # For dom0, we ignore any stored value for the vcpus fields, and
        # read the current value from Xen instead.  This allows boot-time
        # settings to take precedence over any entries in the store.
        if priv:
            xeninfo = dom_get(self.domid)
            self.info['VCPUs_max'] = xeninfo['online_vcpus']
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

    def _update_consoles(self, transaction = None):
        if self.domid == None or self.domid == 0:
            return

        # Update VT100 port if it exists
        if transaction is None:
            self.console_port = self.readDom('console/port')
        else:
            self.console_port = self.readDomTxn(transaction, 'console/port')
        if self.console_port is not None:
            serial_consoles = self.info.console_get_all('vt100')
            if not serial_consoles:
                cfg = self.info.console_add('vt100', self.console_port)
                self._createDevice('console', cfg)
            else:
                console_uuid = serial_consoles[0].get('uuid')
                self.info.console_update(console_uuid, 'location',
                                         self.console_port)
                # Notify xenpv device model that console info is ready
                if not self.info.is_hvm() and self.info.has_rfb():
                    console_ctrl = self.getDeviceController('console')
                    # The value is unchanged. Just for xenstore watcher
                    console_ctrl.writeBackend(0, 'uuid', console_uuid)
                

        # Update VNC port if it exists and write to xenstore
        if transaction is None:
            vnc_port = self.readDom('console/vnc-port')
        else:
            vnc_port = self.readDomTxn(transaction, 'console/vnc-port')
        if vnc_port is not None:
            for dev_uuid, (dev_type, dev_info) in self.info['devices'].items():
                if dev_type == 'vfb':
                    old_location = dev_info.get('location')
                    listen_host = dev_info.get('vnclisten', \
                                XendOptions.instance().get_vnclisten_address())
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

    def _listRecursiveVm(self, *args):
        return xstransact.ListRecursive(self.vmpath, *args)

    def storeVm(self, *args):
        return xstransact.Store(self.vmpath, *args)

    def permissionsVm(self, *args):
        return xstransact.SetPermissions(self.vmpath, *args)

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


    def readDomTxn(self, transaction, *args):
        paths = map(lambda x: self.dompath + "/" + x, args)
        return transaction.read(*paths)

    def gatherDomTxn(self, transaction, *args):
        paths = map(lambda x: self.dompath + "/" + x, args)
        return transaction.gather(*paths)

    def _writeDomTxn(self, transaction, *args):
        paths = map(lambda x: self.dompath + "/" + x, args)
        return transaction.write(*paths)

    def _removeDomTxn(self, transaction, *args):
        paths = map(lambda x: self.dompath + "/" + x, args)
        return transaction.remove(*paths)

    def storeDomTxn(self, transaction, *args):
        paths = map(lambda x: self.dompath + "/" + x, args)
        return transaction.store(*paths)


    def _recreateDom(self):
        complete(self.dompath, lambda t: self._recreateDomFunc(t))

    def _recreateDomFunc(self, t):
        t.remove()
        t.mkdir()
        t.set_permissions({'dom' : self.domid, 'read' : True})
        t.write('vm', self.vmpath)
        # NB. Solaris guests use guest/ and hvmpv/ xenstore directories
        #     XCP Windows paravirtualized guests use data/
        for i in [ 'device', 'control', 'error', 'memory', 'guest', \
                   'hvmpv', 'data' ]:
            t.mkdir(i)
            t.set_permissions(i, {'dom' : self.domid})

    def _storeDomDetails(self):
        to_store = {
            'domid':              str(self.domid),
            'vm':                 self.vmpath,
            'name':               self.info['name_label'],
            'console/limit':      str(xoptions.get_console_limit() * 1024),
            'memory/target':      str(self.info['memory_dynamic_max'] / 1024),
            'description':        str(self.info['description']),
            }

        def f(n, v):
            if v is not None:
                if type(v) == bool:
                    to_store[n] = v and "1" or "0"
                else:
                    to_store[n] = str(v)

        # Figure out if we need to tell xenconsoled to ignore this guest's
        # console - device model will handle console if it is running
        constype = "ioemu"
        if 'device_model' not in self.info['platform']:
            constype = "xenconsoled"

        f('console/port',     self.console_port)
        f('console/ring-ref', self.console_mfn)
        f('console/type',     constype)
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

        if self.info.has_key('security_label'):
            f('security_label', self.info['security_label'])

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
        for v in range(0, self.info['VCPUs_max']):
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
        
        cfg_vm = ['name', 'on_poweroff', 'on_reboot', 'on_crash',
                  'rtc/timeoffset']
        
        vm_details = self._readVMDetails([(k,XendConfig.LEGACY_CFG_TYPES[k])
                                           for k in cfg_vm])

        # convert two lists into a python dictionary
        vm_details = dict(zip(cfg_vm, vm_details))

        for arg, val in vm_details.items():
            if arg in XendConfig.LEGACY_CFG_TO_XENAPI_CFG:
                xapiarg = XendConfig.LEGACY_CFG_TO_XENAPI_CFG[arg]
                if val != None and val != self.info[xapiarg]:
                    self.info[xapiarg] = val
                    changed = True
            elif arg == "memory":
                if val != None and val != self.info["static_memory_min"]:
                    self.info["static_memory_min"] = val
                    changed = True
            elif arg == "maxmem":
                if val != None and val != self.info["static_memory_max"]:
                    self.info["static_memory_max"] = val
                    changed = True

        # Check whether image definition has been updated
        image_sxp = self._readVm('image')
        if image_sxp and image_sxp != sxp.to_string(self.info.image_sxpr()):
            self.info.update_with_image_sxp(sxp.from_string(image_sxp))
            changed = True

        # Update the rtc_timeoffset to be preserved across reboot.
        # NB. No need to update xenstore domain section.
        val = int(vm_details.get("rtc/timeoffset", 0))
        self.info["platform"]["rtc_timeoffset"] = val
 
        if changed:
            # Update the domain section of the store, as this contains some
            # parameters derived from the VM configuration.
            self.refresh_shutdown_lock.acquire()
            try:
                state = self._stateGet()
                if state not in (DOM_STATE_SHUTDOWN, DOM_STATE_HALTED,):
                    self._storeDomDetails()
            finally:
                self.refresh_shutdown_lock.release()

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

    def getStubdomDomid(self):
        dom_list = xstransact.List('/local/domain')
        for d in dom_list:
            target = xstransact.Read('/local/domain/' + d + '/target')
            if target is not None and int(target) == self.domid:
                return int(d)
        return None

    def setName(self, name, to_store = True):
        self._checkName(name)
        self.info['name_label'] = name
        if to_store:
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
        return self.info['VCPUs_max']

    def getVCpuAvail(self):
        return self.info['vcpu_avail']

    def setVCpuCount(self, vcpus):
        def vcpus_valid(n):
            if vcpus <= 0:
                raise XendError('Zero or less VCPUs is invalid')
            if self.domid >= 0 and vcpus > self.info['VCPUs_max']:
                raise XendError('Cannot set vcpus greater than max vcpus on running domain')
        vcpus_valid(vcpus)
        
        self.info['vcpu_avail'] = (1 << vcpus) - 1
        if self.domid >= 0:
            self.storeVm('vcpu_avail', self.info['vcpu_avail'])
            self._writeDom(self._vcpuDomDetails())
            self.info['VCPUs_live'] = vcpus
        else:
            if self.info['VCPUs_max'] > vcpus:
                # decreasing
                del self.info['cpus'][vcpus:]
            elif self.info['VCPUs_max'] < vcpus:
                # increasing
                for c in range(self.info['VCPUs_max'], vcpus):
                    self.info['cpus'].append(list())
            self.info['VCPUs_max'] = vcpus
        xen.xend.XendDomain.instance().managed_config_save(self)
        log.info("Set VCPU count on domain %s to %d", self.info['name_label'],
                 vcpus)

    def getMemoryTarget(self):
        """Get this domain's target memory size, in KB."""
        return self.info['memory_dynamic_max'] / 1024

    def getMemoryMaximum(self):
        """Get this domain's maximum memory size, in KB."""
        # remember, info now stores memory in bytes
        return self.info['memory_static_max'] / 1024

    def getResume(self):
        return str(self._resume)

    def setResume(self, isresume):
        self._resume = isresume

    def getCpus(self):
        return self.info['cpus']

    def setCpus(self, cpumap):
        self.info['cpus'] = cpumap

    def getCap(self):
        return self.info['vcpus_params']['cap']

    def setCap(self, cpu_cap):
        self.info['vcpus_params']['cap'] = cpu_cap

    def getWeight(self):
        return self.info['vcpus_params']['weight']

    def setWeight(self, cpu_weight):
        self.info['vcpus_params']['weight'] = cpu_weight

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
                # Domain is alive.  If we are shutting it down, log a message
                # if it seems unresponsive.
                if xeninfo['paused']:
                    self._stateSet(DOM_STATE_PAUSED)
                else:
                    self._stateSet(DOM_STATE_RUNNING)
                    
                if self.shutdownStartTime:
                    timeout = (SHUTDOWN_TIMEOUT - time.time() +
                               self.shutdownStartTime)
                    if (timeout < 0 and not self.readDom('xend/unresponsive')):
                        log.info(
                            "Domain shutdown timeout expired: name=%s id=%s",
                            self.info['name_label'], self.domid)
                        self.storeDom('xend/unresponsive', 'True')
        finally:
            self.refresh_shutdown_lock.release()

        if restart_reason and not self.restart_in_progress:
            self.restart_in_progress = True
            threading.Thread(target = self._maybeRestart,
                             args = (restart_reason,)).start()


    #
    # Restart functions - handling whether we come back up on shutdown.
    #

    def _clearRestart(self):
        self._removeDom("xend/shutdown_start_time")

    def _maybeDumpCore(self, reason):
        if reason == 'crash':
            if xoptions.get_enable_dump() or self.get_on_crash() \
                   in ['coredump_and_destroy', 'coredump_and_restart']:
                try:
                    self.dumpCore()
                except XendError:
                    # This error has been logged -- there's nothing more
                    # we can do in this context.
                    pass

    def _maybeRestart(self, reason):
        # Before taking configured action, dump core if configured to do so.
        #
        self._maybeDumpCore(reason)

        # Dispatch to the correct method based upon the configured on_{reason}
        # behaviour.
        actions =  {"destroy"        : self.destroy,
                    "restart"        : self._restart,
                    "preserve"       : self._preserve,
                    "rename-restart" : self._renameRestart,
                    "coredump-destroy" : self.destroy,
                    "coredump-restart" : self._restart}

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

        elapse = time.time() - self.info['start_time']
        if elapse < MINIMUM_RESTART_TIME:
            log.error('VM %s restarting too fast (Elapsed time: %f seconds). '
                      'Refusing to restart to avoid loops.',
                      self.info['name_label'], elapse)
            self.destroy()
            return

        prev_vm_xend = self._listRecursiveVm('xend')
        new_dom_info = self.info
        try:
            if rename:
                new_dom_info = self._preserveForRestart()
            else:
                self._unwatchVm()
                self.destroy()

            # new_dom's VM will be the same as this domain's VM, except where
            # the rename flag has instructed us to call preserveForRestart.
            # In that case, it is important that we remove the
            # RESTART_IN_PROGRESS node from the new domain, not the old one,
            # once the new one is available.

            new_dom = None
            try:
                new_dom = XendDomain.instance().domain_create_from_dict(
                    new_dom_info)
                for x in prev_vm_xend[0][1]:
                    new_dom._writeVm('xend/%s' % x[0], x[1])
                new_dom.waitForDevices()
                new_dom.unpause()
                rst_cnt = new_dom._readVm('xend/restart_count')
                rst_cnt = int(rst_cnt) + 1
                new_dom._writeVm('xend/restart_count', str(rst_cnt))
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
        # Remove existing vm node in xenstore
        self._removeVm()
        new_dom_info = self.info.copy()
        new_dom_info['name_label'] = self.info['name_label']
        new_dom_info['uuid'] = self.info['uuid']
        self.info['name_label'] = new_name
        self.info['uuid'] = new_uuid
        self.vmpath = XS_VMROOT + new_uuid
        # Write out new vm node to xenstore
        self._storeVmDetails()
        self._preserve()
        return new_dom_info


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
        
        if not corefile:
            # To prohibit directory traversal
            based_name = os.path.basename(self.info['name_label'])
            
            coredir = "/var/xen/dump/%s" % (based_name)
            if not os.path.exists(coredir):
                try:
                    mkdir.parents(coredir, stat.S_IRWXU)
                except Exception, ex:
                    log.error("Cannot create directory: %s" % str(ex))

            if not os.path.isdir(coredir):
                # Use former directory to dump core
                coredir = '/var/xen/dump'

            this_time = time.strftime("%Y-%m%d-%H%M.%S", time.localtime())
            corefile = "%s/%s-%s.%s.core" % (coredir, this_time,
                                             self.info['name_label'], self.domid)
                
        if os.path.isdir(corefile):
            raise XendError("Cannot dump core in a directory: %s" %
                            corefile)

        try:
            try:
                self._writeVm(DUMPCORE_IN_PROGRESS, 'True')
                xc.domain_dumpcore(self.domid, corefile)
            except RuntimeError, ex:
                corefile_incomp = corefile+'-incomplete'
                try:
                    os.rename(corefile, corefile_incomp)
                except:
                    pass

                log.error("core dump failed: id = %s name = %s: %s",
                          self.domid, self.info['name_label'], str(ex))
                raise XendError("Failed to dump core: %s" %  str(ex))
        finally:
            self._removeVm(DUMPCORE_IN_PROGRESS)

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

    def _waitForDevice_destroy(self, deviceClass, devid, backpath):
        return self.getDeviceController(deviceClass).waitForDevice_destroy(
            devid, backpath)

    def _reconfigureDevice(self, deviceClass, devid, devconfig):
        return self.getDeviceController(deviceClass).reconfigureDevice(
            devid, devconfig)

    def _createDevices(self):
        """Create the devices for a vm.

        @raise: VmError for invalid devices
        """
        if self.image:
            self.image.prepareEnvironment()

        vscsi_uuidlist = {}
        vscsi_devidlist = []
        ordered_refs = self.info.ordered_device_refs()
        for dev_uuid in ordered_refs:
            devclass, config = self.info['devices'][dev_uuid]
            if devclass in XendDevices.valid_devices() and devclass != 'vscsi':
                log.info("createDevice: %s : %s" % (devclass, scrub_password(config)))
                dev_uuid = config.get('uuid')

                if devclass == 'pci':
                    self.pci_dev_check_assignability_and_do_FLR(config)

                if devclass != 'pci' or not self.info.is_hvm() :
                    devid = self._createDevice(devclass, config)
                
                    # store devid in XendConfig for caching reasons
                    if dev_uuid in self.info['devices']:
                        self.info['devices'][dev_uuid][1]['devid'] = devid

            elif devclass == 'vscsi':
                vscsi_config = config.get('devs', [])[0]
                devid = vscsi_config.get('devid', '')
                dev_uuid = config.get('uuid')
                vscsi_uuidlist[devid] = dev_uuid
                vscsi_devidlist.append(devid)

        #It is necessary to sorted it for /dev/sdxx in guest. 
        if len(vscsi_uuidlist) > 0:
            vscsi_devidlist.sort()
            for vscsiid in vscsi_devidlist:
                dev_uuid = vscsi_uuidlist[vscsiid]
                devclass, config = self.info['devices'][dev_uuid]
                log.info("createDevice: %s : %s" % (devclass, scrub_password(config)))
                dev_uuid = config.get('uuid')
                devid = self._createDevice(devclass, config)
                # store devid in XendConfig for caching reasons
                if dev_uuid in self.info['devices']:
                    self.info['devices'][dev_uuid][1]['devid'] = devid


        if self.image:
            self.image.createDeviceModel()

        #if have pass-through devs, need the virtual pci slots info from qemu
        self.pci_device_configure_boot()

    def _releaseDevices(self, suspend = False):
        """Release all domain's devices.  Nothrow guarantee."""
        if self.image:
            try:
                log.debug("Destroying device model")
                self.image.destroyDeviceModel()
            except Exception, e:
                log.exception("Device model destroy failed %s" % str(e))
        else:
            log.debug("No device model")

        log.debug("Releasing devices")
        t = xstransact("%s/device" % self.vmpath)
        try:
            for devclass in XendDevices.valid_devices():
                for dev in t.list(devclass):
                    try:
                        log.debug("Removing %s", dev);
                        self.destroyDevice(devclass, dev, False);
                    except:
                        # Log and swallow any exceptions in removal --
                        # there's nothing more we can do.
                        log.exception("Device release failed: %s; %s; %s",
                                      self.info['name_label'],
                                      devclass, dev)
        finally:
            t.abort()

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
            rc = self.migrateDevice(n, c, network, dst, DEV_MIGRATE_TEST, self.getName())
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

    def setChangeHomeServer(self, chs):
        if chs is not None:
            self.info['change_home_server'] = bool(chs)
        else:
            if self.info.has_key('change_home_server'):
                del self.info['change_home_server']


    ## private:

    def _constructDomain(self):
        """Construct the domain.

        @raise: VmError on error
        """

        log.debug('XendDomainInfo.constructDomain')

        self.shutdownStartTime = None
        self.restart_in_progress = False

        hap = 0
        hvm = self.info.is_hvm()
        if hvm:
            hap = self.info.is_hap()
            info = xc.xeninfo()
            if 'hvm' not in info['xen_caps']:
                raise VmError("HVM guest support is unavailable: is VT/AMD-V "
                              "supported by your CPU and enabled in your "
                              "BIOS?")

        # Hack to pre-reserve some memory for initial domain creation.
        # There is an implicit memory overhead for any domain creation. This
        # overhead is greater for some types of domain than others. For
        # example, an x86 HVM domain will have a default shadow-pagetable
        # allocation of 4MB. We free up 16MB here to be on the safe side.
        balloon.free(16*1024, self) # 16MB should be plenty

        ssidref = 0
        if security.on() == xsconstants.XS_POLICY_USE:
            ssidref = security.calc_dom_ssidref_from_info(self.info)
            if security.has_authorization(ssidref) == False:
                raise VmError("VM is not authorized to run.")

        s3_integrity = 0
        if self.info.has_key('s3_integrity'):
            s3_integrity = self.info['s3_integrity']

        oos = self.info['platform'].get('oos', 1)
        oos_off = 1 - int(oos)

        # look-up pool id to use
        pool_name = self.info['pool_name']
        if len(pool_name) == 0:
            pool_name = "Pool-0"

        pool = XendCPUPool.lookup_pool(pool_name)

        if pool is None:
            raise VmError("unknown pool %s" % pool_name)
        pool_id = pool.query_pool_id()
        if pool_id is None:
            raise VmError("pool %s not activated" % pool_name)

        flags = (int(hvm) << 0) | (int(hap) << 1) | (int(s3_integrity) << 2) | (int(oos_off) << 3)

        try:
            self.domid = xc.domain_create(
                domid = 0,
                ssidref = ssidref,
                handle = uuid.fromString(self.info['uuid']),
                flags = flags,
                #cpupool = pool_id,
                target = self.info.target())
        except Exception, e:
            # may get here if due to ACM the operation is not permitted
            if security.on() == xsconstants.XS_POLICY_ACM:
                raise VmError('Domain in conflict set with running domain?')
            log.exception(e)

        if not self.domid or self.domid < 0:
            failmsg = 'Creating domain failed: name=%s' % self.info['name_label']
            if self.domid:
                failmsg += ', error=%i' % int(self.domid)
            raise VmError(failmsg)

        try:
            xc.cpupool_movedomain(pool_id, self.domid)
        except Exception, e:
            raise VmError('Moving domain to target pool failed')

        self.dompath = GetDomainPath(self.domid)

        self._recreateDom()

        # Set TSC mode of domain
        tsc_mode = self.info["platform"].get("tsc_mode")
        if arch.type == "x86" and tsc_mode is not None:
            xc.domain_set_tsc_info(self.domid, int(tsc_mode))

        # Set timer configuration of domain
        timer_mode = self.info["platform"].get("timer_mode")
        if hvm and timer_mode is not None:
            xc.hvm_set_param(self.domid, HVM_PARAM_TIMER_MODE,
                             long(timer_mode))

        # Set Viridian interface configuration of domain
        viridian = self.info["platform"].get("viridian")
        if arch.type == "x86" and hvm and viridian is not None:
            xc.hvm_set_param(self.domid, HVM_PARAM_VIRIDIAN, long(viridian))

        # If nomigrate is set, disable migration
        nomigrate = self.info["platform"].get("nomigrate")
        if nomigrate is not None and long(nomigrate) != 0:
            xc.domain_disable_migrate(self.domid)

        # Optionally enable virtual HPET
        hpet = self.info["platform"].get("hpet")
        if hvm and hpet is not None:
            xc.hvm_set_param(self.domid, HVM_PARAM_HPET_ENABLED,
                             long(hpet))

        # Optionally enable periodic vpt aligning
        vpt_align = self.info["platform"].get("vpt_align")
        if hvm and vpt_align is not None:
            xc.hvm_set_param(self.domid, HVM_PARAM_VPT_ALIGN,
                             long(vpt_align))

        # Set maximum number of vcpus in domain
        xc.domain_max_vcpus(self.domid, int(self.info['VCPUs_max']))

        # Check for cpu_{cap|weight} validity for credit scheduler
        if XendNode.instance().xenschedinfo() == 'credit':
            cap = self.getCap()
            weight = self.getWeight()

            assert type(weight) == int
            assert type(cap) == int

            if weight < 1 or weight > 65535:
                raise VmError("Cpu weight out of range, valid values are within range from 1 to 65535")

            if cap < 0 or cap > self.getVCpuCount() * 100:
                raise VmError("Cpu cap out of range, valid range is from 0 to %s for specified number of vcpus" %
                              (self.getVCpuCount() * 100))

        # Test whether the devices can be assigned with VT-d
        self.info.update_platform_pci()
        pci = self.info["platform"].get("pci")
        pci_str = ''
        if pci and len(pci) > 0:
            pci = map(lambda x: x[0:4], pci)  # strip options 
            pci_str = str(pci)

        # This test is done for both pv and hvm guest.
        for p in pci:
            pci_name = '%04x:%02x:%02x.%x' % \
                (parse_hex(p[0]), parse_hex(p[1]), parse_hex(p[2]), parse_hex(p[3]))
            try:
                pci_device = PciDevice(parse_pci_name(pci_name))
            except Exception, e:
                raise VmError("pci: failed to locate device and "+
                    "parse its resources - "+str(e))
            if pci_device.driver!='pciback' and pci_device.driver!='pci-stub':
                raise VmError(("pci: PCI Backend and pci-stub don't own device %s")\
                                %pci_device.name)
            if pci_name in get_all_assigned_pci_devices():
                raise VmError("failed to assign device %s that has"
                              " already been assigned to other domain." % pci_name)

        if hvm and pci_str != '':
            bdf = xc.test_assign_device(0, pci_str)
            if bdf != 0:
                if bdf == -1:
                    raise VmError("failed to assign device: maybe the platform"
                                  " doesn't support VT-d, or VT-d isn't enabled"
                                  " properly?")
                bus = (bdf >> 16) & 0xff
                devfn = (bdf >> 8) & 0xff
                dev = (devfn >> 3) & 0x1f
                func = devfn & 0x7
                raise VmError("failed to assign device %02x:%02x.%x: maybe it has"
                              " already been assigned to other domain, or maybe"
                              " it doesn't exist." % (bus, dev, func))

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

    def _setTarget(self, target):
        assert self.domid is not None

        try:
            SetTarget(self.domid, target)
            self.storeDom('target', target)
        except RuntimeError, exn:
            raise XendError(str(exn))


    def _setCPUAffinity(self):
        """ Repin domain vcpus if a restricted cpus list is provided.
            Returns the choosen node number.
        """

        def has_cpus():
            if self.info['cpus'] is not None:
                for c in self.info['cpus']:
                    if c:
                        return True
            return False

        def has_cpumap():
            if self.info.has_key('vcpus_params'):
                for k, v in self.info['vcpus_params'].items():
                    if k.startswith('cpumap'):
                        return True
            return False

        index = 0
        if has_cpumap():
            for v in range(0, self.info['VCPUs_max']):
                if self.info['vcpus_params'].has_key('cpumap%i' % v):
                    cpumask = map(int, self.info['vcpus_params']['cpumap%i' % v].split(','))
                    xc.vcpu_setaffinity(self.domid, v, cpumask)
        elif has_cpus():
            for v in range(0, self.info['VCPUs_max']):
                if self.info['cpus'][v]:
                    xc.vcpu_setaffinity(self.domid, v, self.info['cpus'][v])
        else:
            def find_relaxed_node(node_list):
                import sys
                nr_nodes = info['max_node_index'] + 1
                if node_list is None:
                    node_list = range(0, nr_nodes)
                nodeload = [0]
                nodeload = nodeload * nr_nodes
                from xen.xend import XendDomain
                doms = XendDomain.instance().list('all')
                for dom in filter (lambda d: d.domid != self.domid, doms):
                    cpuinfo = dom.getVCPUInfo()
                    for vcpu in sxp.children(cpuinfo, 'vcpu'):
                        if sxp.child_value(vcpu, 'online') == 0: continue
                        cpumap = list(sxp.child_value(vcpu,'cpumap'))
                        for i in range(0, nr_nodes):
                            node_cpumask = node_to_cpu[i]
                            for j in node_cpumask:
                                if j in cpumap:
                                    nodeload[i] += 1
                                    break
                for i in range(0, nr_nodes):
                    if len(node_to_cpu[i]) == 0:
                        nodeload[i] += 8
                    else:
                        nodeload[i] = int(nodeload[i] * 16 / len(node_to_cpu[i]))
                        if i not in node_list:
                            nodeload[i] += 8
                return map(lambda x: x[0], sorted(enumerate(nodeload), key=lambda x:x[1]))

            info = xc.numainfo()
            if info['max_node_index'] > 0 and  XendCPUPool.number_of_pools() < 2:
                node_memory_list = info['node_memfree']
                node_to_cpu = []
                for i in range(0, info['max_node_index'] + 1):
                    node_to_cpu.append([])
                for cpu, node in enumerate(xc.topologyinfo()['cpu_to_node']):
                    node_to_cpu[node].append(cpu)
                needmem = self.image.getRequiredAvailableMemory(self.info['memory_dynamic_max']) / 1024
                candidate_node_list = []
                for i in range(0, info['max_node_index'] + 1):
                    if node_memory_list[i] >= needmem and len(node_to_cpu[i]) > 0:
                        candidate_node_list.append(i)
                best_node = find_relaxed_node(candidate_node_list)[0]
                cpumask = node_to_cpu[best_node]
                best_nodes = find_relaxed_node(filter(lambda x: x != best_node, range(0,info['max_node_index']+1)))
                for node_idx in best_nodes:
                    if len(cpumask) >= self.info['VCPUs_max']:
                        break
                    cpumask = cpumask + node_to_cpu[node_idx]
                    log.debug("allocating additional NUMA node %d", node_idx)
                for v in range(0, self.info['VCPUs_max']):
                    xc.vcpu_setaffinity(self.domid, v, cpumask)
        return index

    def _freeDMAmemory(self, node):

        # If we are PV and have PCI devices the guest will
        # turn on a SWIOTLB. The SWIOTLB _MUST_ be located in the DMA32
        # zone (under 4GB). To do so, we need to balloon down Dom0 to where
        # there is enough (64MB) memory under the 4GB mark. This balloon-ing
        # might take more memory out than just 64MB thought :-(
        if not self.info.is_pv_and_has_pci():
            return

        retries = 2000
        ask_for_mem = 0
        need_mem = 0
        try:
            while (retries > 0):
                physinfo = xc.physinfo()
                free_mem = physinfo['free_memory']
                max_node_id = physinfo['max_node_id']
                node_to_dma32_mem = physinfo['node_to_dma32_mem']
                if (node > max_node_id):
                    return
                # Extra 2MB above 64GB seems to do the trick.
                need_mem = 64 * 1024 + 2048 - node_to_dma32_mem[node]
                # our starting point. We ask just for the difference to
                # be have an extra 64MB under 4GB.
                ask_for_mem = max(need_mem, ask_for_mem);
                if (need_mem > 0):
                    log.debug('_freeDMAmemory (%d) Need %dKiB DMA memory. '
                              'Asking for %dKiB', retries, need_mem,
                              ask_for_mem)

                    balloon.free(ask_for_mem, self)
                    ask_for_mem = ask_for_mem + 2048
                else:
                    # OK. We got enough DMA memory.
                    break
                retries = retries - 1
        except:
            # This is best-try after all.
            need_mem = max(1, need_mem)
            pass

        if (need_mem > 0):
            log.warn('We tried our best to balloon down DMA memory to '
                     'accomodate your PV guest. We need %dKiB extra memory.',
                     need_mem)

    def _setSchedParams(self):
        if XendNode.instance().xenschedinfo() == 'credit':
            from xen.xend import XendDomain
            XendDomain.instance().domain_sched_credit_set(self.getDomid(),
                                                          self.getWeight(),
                                                          self.getCap())
        elif XendNode.instance().xenschedinfo() == 'credit2':
            from xen.xend import XendDomain
            XendDomain.instance().domain_sched_credit2_set(self.getDomid(),
                                                           self.getWeight())

    def _initDomain(self):
        log.debug('XendDomainInfo.initDomain: %s %s',
                  self.domid,
                  self.info['vcpus_params']['weight'])

        self._configureBootloader()

        try:
            self.image = image.create(self, self.info)

            # repin domain vcpus if a restricted cpus list is provided
            # this is done prior to memory allocation to aide in memory
            # distribution for NUMA systems.
            node = self._setCPUAffinity()

            # Set scheduling parameters.
            self._setSchedParams()

            # Use architecture- and image-specific calculations to determine
            # the various headrooms necessary, given the raw configured
            # values. maxmem, memory, and shadow are all in KiB.
            # but memory_static_max etc are all stored in bytes now.
            memory = self.image.getRequiredAvailableMemory(
                self.info['memory_dynamic_max'] / 1024)
            maxmem = self.image.getRequiredAvailableMemory(
                self.info['memory_static_max'] / 1024)
            shadow = self.image.getRequiredShadowMemory(
                self.info['shadow_memory'] * 1024,
                self.info['memory_static_max'] / 1024)

            log.debug("_initDomain:shadow_memory=0x%x, memory_static_max=0x%x, memory_static_min=0x%x.", self.info['shadow_memory'], self.info['memory_static_max'], self.info['memory_static_min'],)
            # Round shadow up to a multiple of a MiB, as shadow_mem_control
            # takes MiB and we must not round down and end up under-providing.
            shadow = ((shadow + 1023) / 1024) * 1024

            # set memory limit
            xc.domain_setmaxmem(self.domid, maxmem)

            vtd_mem = 0
            info = xc.physinfo()
            if 'hvm_directio' in info['virt_caps']:
                # Reserve 1 page per MiB of RAM for separate VT-d page table.
                vtd_mem = 4 * (self.info['memory_static_max'] / 1024 / 1024)
                # Round vtd_mem up to a multiple of a MiB.
                vtd_mem = ((vtd_mem + 1023) / 1024) * 1024

            self.guest_bitsize = self.image.getBitSize()
            # Make sure there's enough RAM available for the domain
            balloon.free(memory + shadow + vtd_mem, self)

            # Set up the shadow memory
            shadow_cur = xc.shadow_mem_control(self.domid, shadow / 1024)
            self.info['shadow_memory'] = shadow_cur

            # machine address size
            if self.info.has_key('machine_address_size'):
                log.debug("_initDomain: setting maximum machine address size %d" % self.info['machine_address_size'])
                xc.domain_set_machine_address_size(self.domid, self.info['machine_address_size'])

            if self.info.has_key('suppress_spurious_page_faults') and self.info['suppress_spurious_page_faults']:
                log.debug("_initDomain: suppressing spurious page faults")
                xc.domain_suppress_spurious_page_faults(self.domid)
                
            self._createChannels()

            channel_details = self.image.createImage()

            self.store_mfn = channel_details['store_mfn']
            if 'console_mfn' in channel_details:
                self.console_mfn = channel_details['console_mfn']
            if 'notes' in channel_details:
                self.info.set_notes(channel_details['notes'])
            if 'native_protocol' in channel_details:
                self.native_protocol = channel_details['native_protocol'];

            self._introduceDomain()
            if self.info.target():
                self._setTarget(self.info.target())

            self._freeDMAmemory(node)

            self._createDevices()

            self.image.cleanupTmpImages()

            self.info['start_time'] = time.time()

            self._stateSet(DOM_STATE_RUNNING)
        except VmError, exn:
            log.exception("XendDomainInfo.initDomain: exception occurred")
            if self.image:
                self.image.cleanupTmpImages()
            raise exn
        except RuntimeError, exn:
            log.exception("XendDomainInfo.initDomain: exception occurred")
            if self.image:
                self.image.cleanupTmpImages()
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
                self.image = None

            try:
                self._removeDom()
            except:
                log.exception("Removing domain path failed.")

            self._stateSet(DOM_STATE_HALTED)
            self.domid = None  # Do not push into _stateSet()!
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
            while self._stateGet() in (DOM_STATE_RUNNING,DOM_STATE_PAUSED):
                self.state_updated.wait(timeout=1.0)
        finally:
            self.state_updated.release()

    def waitForSuspend(self):
        """Wait for the guest to respond to a suspend request by
        shutting down.  If the guest hasn't re-written control/shutdown
        after a certain amount of time, it's obviously not listening and
        won't suspend, so we give up.  HVM guests with no PV drivers
        should already be shutdown.
        """
        state = "suspend"
        nr_tries = 60

        self.state_updated.acquire()
        try:
            while self._stateGet() in (DOM_STATE_RUNNING,DOM_STATE_PAUSED):
                self.state_updated.wait(1.0)
                if state == "suspend":
                    if nr_tries == 0:
                        msg = ('Timeout waiting for domain %s to suspend'
                            % self.domid)
                        self._writeDom('control/shutdown', '')
                        raise XendError(msg)
                    state = self.readDom('control/shutdown')
                    nr_tries -= 1
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
        self.image = image.create(self, self.info)
        if self.image:
            self.image.createDeviceModel(True)
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
            t = xstransact("%s/device/vbd" % GetDomainPath(self.domid))
            try:
                for dev in t.list():
                    backend_phantom_vbd = xstransact.Read("%s/device/vbd/%s/phantom_vbd" \
                                          % (self.dompath, dev))
                    if backend_phantom_vbd is not None:
                        frontend_phantom_vbd =  xstransact.Read("%s/frontend" \
                                          % backend_phantom_vbd)
                        plist.append(backend_phantom_vbd)
                        plist.append(frontend_phantom_vbd)
            finally:
                t.abort()
        return plist

    def _cleanup_phantom_devs(self, plist):
        # remove phantom devices
        if not plist == []:
            time.sleep(2)
        for paths in plist:
            if paths.find('backend') != -1:
                # Modify online status /before/ updating state (latter is watched by
                # drivers, so this ordering avoids a race).
                xstransact.Write(paths, 'online', "0")
                xstransact.Write(paths, 'state', str(xenbusState['Closing']))
            # force
            xstransact.Remove(paths)

    def destroy(self):
        """Cleanup VM and destroy domain.  Nothrow guarantee."""

        if self.domid is None:
            return
        from xen.xend import XendDomain
        log.debug("XendDomainInfo.destroy: domid=%s", str(self.domid))

        paths = self._prepare_phantom_paths()

        if self.dompath is not None:
            try:
                xc.domain_destroy_hook(self.domid)
                xc.domain_pause(self.domid)
                do_FLR(self.domid, self.info.is_hvm())
                xc.domain_destroy(self.domid)
                for state in DOM_STATES_OLD:
                    self.info[state] = 0
                self._stateSet(DOM_STATE_HALTED)
            except:
                log.exception("XendDomainInfo.destroy: domain destruction failed.")

            XendDomain.instance().remove_domain(self)
            self.cleanupDomain()

        if self.info.is_hvm() or self.guest_bitsize != 32:
            if self.alloc_mem:
                import MemoryPool 
                log.debug("%s KiB need to add to Memory pool" %self.alloc_mem)
                MemoryPool.instance().increase_memory(self.alloc_mem)

        self._cleanup_phantom_devs(paths)
        self._cleanupVm()

        if ("transient" in self.info["other_config"] and \
            bool(self.info["other_config"]["transient"])) or \
           ("change_home_server" in self.info and \
            bool(self.info["change_home_server"])):
            XendDomain.instance().domain_delete_by_dominfo(self)


    def resetDomain(self):
        log.debug("XendDomainInfo.resetDomain(%s)", str(self.domid))

        old_domid = self.domid
        prev_vm_xend = self._listRecursiveVm('xend')
        new_dom_info = self.info
        try:
            self._unwatchVm()
            self.destroy()

            new_dom = None
            try:
                from xen.xend import XendDomain
                new_dom_info['domid'] = None
                new_dom = XendDomain.instance().domain_create_from_dict(
                    new_dom_info)
                for x in prev_vm_xend[0][1]:
                    new_dom._writeVm('xend/%s' % x[0], x[1])
                new_dom.waitForDevices()
                new_dom.unpause()
            except:
                if new_dom:
                    new_dom.destroy()
                raise
        except:
            log.exception('Failed to reset domain %s.', str(old_domid))


    def resumeDomain(self):
        log.debug("XendDomainInfo.resumeDomain(%s)", str(self.domid))

        # resume a suspended domain (e.g. after live checkpoint, or after
        # a later error during save or migate); checks that the domain
        # is currently suspended first so safe to call from anywhere

        xeninfo = dom_get(self.domid)
        if xeninfo is None: 
            return
        if not xeninfo['shutdown']:
            return
        reason = shutdown_reason(xeninfo['shutdown_reason'])
        if reason != 'suspend':
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
        self.image.resumeDeviceModel()
        log.debug("XendDomainInfo.resumeDomain: completed")


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
            pass
        elif not blexec and kernel:
            # Boot from dom0.  Nothing left to do -- the kernel and ramdisk
            # will be picked up by image.py.
            pass
        else:
            # Boot using bootloader
            if not blexec or blexec == 'pygrub':
                blexec = auxbin.pathTo('pygrub')

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

            # If this is a drbd volume, check if we need to activate it
            if disk.find(":") != -1:
                (disktype, diskname) = disk.split(':', 1)
                if disktype == 'drbd':
                    (drbdadmstdin, drbdadmstdout) = os.popen2(["/sbin/drbdadm", "state", diskname])
                    (state, junk) = drbdadmstdout.readline().split('/', 1)
                    if state == 'Secondary':
                        os.system('/sbin/drbdadm primary ' + diskname)

            taptype = blkdev_uname_to_taptype(disk)
            mounted = devtype in ['tap', 'tap2'] and taptype != 'aio' and taptype != 'sync' and not os.stat(fn).st_rdev
            mounted_vbd_uuid = 0
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
                mounted_vbd_uuid = dom0.create_vbd(vbd, disk);
                dom0._waitForDeviceUUID(mounted_vbd_uuid)
                fn = BOOTLOADER_LOOPBACK_DEVICE

            try:
                blcfg = bootloader(blexec, fn, self, False,
                                   bootloader_args, kernel, ramdisk, args)
            finally:
                if mounted:
                    log.info("Unmounting %s from %s." %
                             (fn, BOOTLOADER_LOOPBACK_DEVICE))
                    _, vbd_info = dom0.info['devices'][mounted_vbd_uuid]
                    dom0.destroyDevice(dom0.getBlockDeviceClass(vbd_info['devid']), 
                                       BOOTLOADER_LOOPBACK_DEVICE, force = True)

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
            overhead_kb = self.info['VCPUs_max'] * 1024 + \
                          (self.info['memory_static_max'] / 1024 / 1024) * 4
            overhead_kb = ((overhead_kb + 1023) / 1024) * 1024
            # The domain might already have some shadow memory
            overhead_kb -= xc.shadow_mem_control(self.domid) * 1024
        if overhead_kb > 0:
            balloon.free(overhead_kb, self)

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
            vbds = self.getDeviceController('vbd').deviceIDs()
            taps = self.getDeviceController('tap').deviceIDs()
            tap2s = self.getDeviceController('tap2').deviceIDs()
            for i in vbds + taps + tap2s:
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

        if self._infoIsSet("static_memory_min"):
            to_store["memory"] = str(self.info["static_memory_min"])
        if self._infoIsSet("static_memory_max"):
            to_store["maxmem"] = str(self.info["static_memory_max"])

        image_sxpr = self.info.image_sxpr()
        if image_sxpr:
            to_store['image'] = sxp.to_string(image_sxpr)

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

    def __getattr__(self, name):
         if name == "state":
             log.warn("Somebody tried to read XendDomainInfo.state... should us _stateGet()!!!")
             log.warn("".join(traceback.format_stack()))
             return self._stateGet()
         else:
             raise AttributeError(name)

    def __setattr__(self, name, value):
        if name == "state":
            log.warn("Somebody tried to set XendDomainInfo.state... should us _stateGet()!!!")
            log.warn("".join(traceback.format_stack()))
            self._stateSet(value)
        else:
            self.__dict__[name] = value

    def _stateSet(self, state):
        self.state_updated.acquire()
        try:
            # TODO Not sure this is correct...
            # _stateGet is live now. Why not fire event
            # even when it hasn't changed?
            if self._stateGet() != state:
                self.state_updated.notifyAll()
                import XendAPI
                XendAPI.event_dispatch('mod', 'VM', self.info['uuid'],
                                       'power_state')
        finally:
            self.state_updated.release()

    def _stateGet(self):
        # Lets try and reconsitute the state from xc
        # first lets try and get the domain info
        # from xc - this will tell us if the domain
        # exists
        info = dom_get(self.getDomid())
        if info is None or info['shutdown']:
            # We are either HALTED or SUSPENDED
            # check saved image exists
            from xen.xend import XendDomain
            managed_config_path = \
                XendDomain.instance()._managed_check_point_path( \
                    self.get_uuid())
            if os.path.exists(managed_config_path):
                return XEN_API_VM_POWER_STATE_SUSPENDED
            else:
                return XEN_API_VM_POWER_STATE_HALTED
        elif info['crashed']:
            # Crashed
            return XEN_API_VM_POWER_STATE_CRASHED
        else:
            # We are either RUNNING or PAUSED
            if info['paused']:
                return XEN_API_VM_POWER_STATE_PAUSED
            else:
                return XEN_API_VM_POWER_STATE_RUNNING

    def _infoIsSet(self, name):
        return name in self.info and self.info[name] is not None

    def _checkName(self, name):
        """Check if a vm name is valid. Valid names contain alphabetic
        characters, digits, or characters in '_-.:+'.
        The same name cannot be used for more than one vm at the same time.

        @param name: name
        @raise: VmError if invalid
        """
        from xen.xend import XendDomain
        
        if name is None or name == '':
            raise VmError('Missing VM Name')

        if not re.search(r'^[A-Za-z0-9_\-\.\:\+]+$', name):
            raise VmError('Invalid VM Name')

        dom =  XendDomain.instance().domain_lookup_nr(name)
        if dom and dom.info['uuid'] != self.info['uuid']:
            raise VmError("VM name '%s' already exists%s" %
                          (name,
                           dom.domid is not None and
                           (" as domain %s" % str(dom.domid)) or ""))
        

    def update(self, info = None, refresh = True, transaction = None):
        """Update with info from xc.domain_getinfo().
        """
        log.trace("XendDomainInfo.update(%s) on domain %s", info,
                  str(self.domid))
        
        if not info:
            info = dom_get(self.domid)
            if not info:
                return

        if info["maxmem_kb"] < 0:
            info["maxmem_kb"] = XendNode.instance() \
                                .physinfo_dict()['total_memory'] * 1024

        # make sure state is reset for info
        # TODO: we should eventually get rid of old_dom_states

        self.info.update_config(info)
        self._update_consoles(transaction)
        
        if refresh:
            self.refreshShutdown(info)

        log.trace("XendDomainInfo.update done on domain %s: %s",
                  str(self.domid), self.info)

    def sxpr(self, ignore_store = False, legacy_only = True):
        result = self.info.to_sxp(domain = self,
                                  ignore_devices = ignore_store,
                                  legacy_only = legacy_only)

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

    # only update memory-related config values if they maintain sanity 
    def _safe_set_memory(self, key, newval):
        oldval = self.info.get(key, 0)
        try:
            self.info[key] = newval
            self.info._memory_sanity_check()
        except Exception, ex:
            self.info[key] = oldval
            raise 
    
    def set_memory_static_max(self, val):
        self._safe_set_memory('memory_static_max', val)
    def set_memory_static_min(self, val):
        self._safe_set_memory('memory_static_min', val)
    def set_memory_dynamic_max(self, val):
        self._safe_set_memory('memory_dynamic_max', val)
    def set_memory_dynamic_min(self, val):
        self._safe_set_memory('memory_dynamic_min', val)
    
    def get_vcpus_params(self):
        if self.getDomid() is None:
            return self.info['vcpus_params']

        retval = xc.sched_credit_domain_get(self.getDomid())
        return retval
    def get_cpu_pool(self):
        if self.getDomid() is None:
            return None
        xeninfo = dom_get(self.domid)
        return xeninfo['cpupool']
    def get_power_state(self):
        return XEN_API_VM_POWER_STATE[self._stateGet()]
    def get_platform(self):
        return self.info.get('platform', {})    
    def get_pci_bus(self):
        return self.info.get('pci_bus', '')
    def get_tools_version(self):
        return self.info.get('tools_version', {})
    def get_metrics(self):
        return self.metrics.get_uuid();


    def get_security_label(self, xspol=None):
        import xen.util.xsm.xsm as security
        label = security.get_security_label(self, xspol)
        return label

    def set_security_label(self, seclab, old_seclab, xspol=None,
                           xspol_old=None):
        """
           Set the security label of a domain from its old to
           a new value.
           @param seclab  New security label formatted in the form
                          <policy type>:<policy name>:<vm label>
           @param old_seclab  The current security label that the
                          VM must have.
           @param xspol   An optional policy under which this
                          update should be done. If not given,
                          then the current active policy is used.
           @param xspol_old The old policy; only to be passed during
                           the updating of a policy
           @return Returns return code, a string with errors from
                   the hypervisor's operation, old label of the
                   domain
        """
        rc = 0
        errors = ""
        old_label = ""
        new_ssidref = 0
        domid = self.getDomid()
        res_labels = None
        is_policy_update = (xspol_old != None)

        from xen.xend.XendXSPolicyAdmin import XSPolicyAdminInstance

        state = self._stateGet()
        # Relabel only HALTED or RUNNING or PAUSED domains
        if domid != 0 and \
           state not in \
              [ DOM_STATE_HALTED, DOM_STATE_RUNNING, DOM_STATE_PAUSED, \
                DOM_STATE_SUSPENDED ]:
            log.warn("Relabeling domain not possible in state '%s'" %
                     DOM_STATES[state])
            return (-xsconstants.XSERR_VM_WRONG_STATE, "", "", 0)

        # Remove security label. Works only for halted or suspended domains
        if not seclab or seclab == "":
            if state not in [ DOM_STATE_HALTED, DOM_STATE_SUSPENDED ]:
                return (-xsconstants.XSERR_VM_WRONG_STATE, "", "", 0)

            if self.info.has_key('security_label'):
                old_label = self.info['security_label']
                # Check label against expected one.
                if old_label != old_seclab:
                    return (-xsconstants.XSERR_BAD_LABEL, "", "", 0)
                del self.info['security_label']
                xen.xend.XendDomain.instance().managed_config_save(self)
                return (xsconstants.XSERR_SUCCESS, "", "", 0)

        tmp = seclab.split(":")
        if len(tmp) != 3:
            return (-xsconstants.XSERR_BAD_LABEL_FORMAT, "", "", 0)
        typ, policy, label = tmp

        poladmin = XSPolicyAdminInstance()
        if not xspol:
            xspol = poladmin.get_policy_by_name(policy)

        try:
            xen.xend.XendDomain.instance().policy_lock.acquire_writer()

            if state in [ DOM_STATE_RUNNING, DOM_STATE_PAUSED ]:
                #if domain is running or paused try to relabel in hypervisor
                if not xspol:
                    return (-xsconstants.XSERR_POLICY_NOT_LOADED, "", "", 0)

                if typ != xspol.get_type_name() or \
                   policy != xspol.get_name():
                    return (-xsconstants.XSERR_BAD_LABEL, "", "", 0)

                if typ == xsconstants.ACM_POLICY_ID:
                    new_ssidref = xspol.vmlabel_to_ssidref(label)
                    if new_ssidref == xsconstants.INVALID_SSIDREF:
                        return (-xsconstants.XSERR_BAD_LABEL, "", "", 0)

                    # Check that all used resources are accessible under the
                    # new label
                    if not is_policy_update and \
                       not security.resources_compatible_with_vmlabel(xspol,
                              self, label):
                        return (-xsconstants.XSERR_BAD_LABEL, "", "", 0)

                    #Check label against expected one. Can only do this
                    # if the policy hasn't changed underneath in the meantime
                    if xspol_old == None:
                        old_label = self.get_security_label()
                        if old_label != old_seclab:
                            log.info("old_label != old_seclab: %s != %s" %
                                     (old_label, old_seclab))
                            return (-xsconstants.XSERR_BAD_LABEL, "", "", 0)

                    # relabel domain in the hypervisor
                    rc, errors = security.relabel_domains([[domid, new_ssidref]])
                    log.info("rc from relabeling in HV: %d" % rc)
                else:
                    return (-xsconstants.XSERR_POLICY_TYPE_UNSUPPORTED, "", "", 0)

            if rc == 0:
                # HALTED, RUNNING or PAUSED
                if domid == 0:
                    if xspol:
                        self.info['security_label'] = seclab
                        ssidref = poladmin.set_domain0_bootlabel(xspol, label)
                    else:
                        return (-xsconstants.XSERR_POLICY_NOT_LOADED, "", "", 0)
                else:
                    if self.info.has_key('security_label'):
                        old_label = self.info['security_label']
                        # Check label against expected one, unless wildcard
                        if old_label != old_seclab:
                            return (-xsconstants.XSERR_BAD_LABEL, "", "", 0)

                    self.info['security_label'] = seclab

                    try:
                        xen.xend.XendDomain.instance().managed_config_save(self)
                    except:
                        pass
            return (rc, errors, old_label, new_ssidref)
        finally:
            xen.xend.XendDomain.instance().policy_lock.release()

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
        if not after_crash or after_crash not in \
               XEN_API_ON_CRASH_BEHAVIOUR + restart_modes:
            return XEN_API_ON_CRASH_BEHAVIOUR[0]
        return XEN_API_ON_CRASH_BEHAVIOUR_FILTER[after_crash]

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
        if self._stateGet() in (XEN_API_VM_POWER_STATE_HALTED,
                                XEN_API_VM_POWER_STATE_SUSPENDED):
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
                    config['device'] = 'eth%s' % devid
                else:
                    config['device'] = ''

            if not config.has_key('network'):
                try:
                    bridge = config.get('bridge', None)
                    if bridge is None:
                        from xen.util import Brctl
                        if_to_br = dict([(i,b)
                            for (b,ifs) in Brctl.get_state().items()
                                for i in ifs])
                        vifname = "vif%s.%s" % (self.getDomid(),
                                                config.get('id'))
                        bridge = if_to_br.get(vifname, None)
                    config['network'] = \
                        XendNode.instance().bridge_to_network(
                        config.get('bridge')).get_uuid()
                except Exception:
                    log.exception('bridge_to_network')
                    # Ignore this for now -- it may happen if the device
                    # has been specified using the legacy methods, but at
                    # some point we're going to have to figure out how to
                    # handle that properly.

            config['MTU'] = 1500 # TODO
            
            if self._stateGet() not in (XEN_API_VM_POWER_STATE_HALTED,):
                xennode = XendNode.instance()
                rx_bps, tx_bps = xennode.get_vif_util(self.domid, devid)
                config['io_read_kbs'] = rx_bps/1024
                config['io_write_kbs'] = tx_bps/1024
                rx, tx = xennode.get_vif_stat(self.domid, devid)
                config['io_total_read_kbs'] = rx/1024
                config['io_total_write_kbs'] = tx/1024
            else:
                config['io_read_kbs'] = 0.0
                config['io_write_kbs'] = 0.0          
                config['io_total_read_kbs'] = 0.0
                config['io_total_write_kbs'] = 0.0

            config['security_label'] = config.get('security_label', '')

        if dev_class == 'vbd':

            if self._stateGet() not in (XEN_API_VM_POWER_STATE_HALTED,):
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
            if config['device'].startswith('ioemu:'):
                _, vbd_device = config['device'].split(':', 1)
                config['device'] = vbd_device
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
        if 'VCPUs_max' in self.info and self.domid != None:
            for i in range(0, self.info['VCPUs_max']):
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

    def get_dpcis(self):
        return XendDPCI.get_by_VM(self.info.get('uuid'))

    def get_dscsis(self):
        return XendDSCSI.get_by_VM(self.info.get('uuid'))

    def get_dscsi_HBAs(self):
        return XendDSCSI_HBA.get_by_VM(self.info.get('uuid'))

    def create_vbd(self, xenapi_vbd, vdi_image_path):
        """Create a VBD using a VDI from XendStorageRepository.

        @param xenapi_vbd: vbd struct from the Xen API
        @param vdi_image_path: VDI UUID
        @rtype: string
        @return: uuid of the device
        """
        xenapi_vbd['image'] = vdi_image_path
        if vdi_image_path.startswith('tap'):
            dev_uuid = self.info.device_add('tap2', cfg_xenapi = xenapi_vbd)
        else:
            dev_uuid = self.info.device_add('vbd', cfg_xenapi = xenapi_vbd)
            
        if not dev_uuid:
            raise XendError('Failed to create device')

        if self._stateGet() in (XEN_API_VM_POWER_STATE_RUNNING,
                                XEN_API_VM_POWER_STATE_PAUSED):
            _, config = self.info['devices'][dev_uuid]
            
            if vdi_image_path.startswith('tap'):
                dev_control = self.getDeviceController('tap2')
            else:
                dev_control = self.getDeviceController('vbd')

            try:
                devid = dev_control.createDevice(config)
                dev_type = self.getBlockDeviceClass(devid)
                self._waitForDevice(dev_type, devid)
                self.info.device_update(dev_uuid,
                                        cfg_xenapi = {'devid': devid})
            except Exception, exn:
                log.exception(exn)
                del self.info['devices'][dev_uuid]
                self.info['vbd_refs'].remove(dev_uuid)
                raise
            
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

        if self._stateGet() == XEN_API_VM_POWER_STATE_RUNNING:
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
        
        if self._stateGet() in (XEN_API_VM_POWER_STATE_RUNNING,
                                XEN_API_VM_POWER_STATE_PAUSED):

            _, config = self.info['devices'][dev_uuid]
            dev_control = self.getDeviceController('vif')

            try:
                devid = dev_control.createDevice(config)
                dev_control.waitForDevice(devid)
                self.info.device_update(dev_uuid,
                                        cfg_xenapi = {'devid': devid})
            except Exception, exn:
                log.exception(exn)
                del self.info['devices'][dev_uuid]
                self.info['vif_refs'].remove(dev_uuid)
                raise            
 
        return dev_uuid

    def create_vtpm(self, xenapi_vtpm):
        """Create a VTPM device from the passed struct in Xen API format.

        @return: uuid of the device
        @rtype: string
        """

        if self._stateGet() not in (DOM_STATE_HALTED,):
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
        if self._stateGet() not in (DOM_STATE_HALTED,):
            raise VmError("Can only add console to a halted domain.")

        dev_uuid = self.info.device_add('console', cfg_xenapi = xenapi_console)
        if not dev_uuid:
            raise XendError('Failed to create device')

        return dev_uuid

    def set_console_other_config(self, console_uuid, other_config):
        self.info.console_update(console_uuid, 'other_config', other_config)

    def create_dpci(self, xenapi_pci):
        """Create pci device from the passed struct in Xen API format.

        @param xenapi_pci: DPCI struct from Xen API
        @rtype: bool
        #@rtype: string
        @return: True if successfully created device
        #@return: UUID
        """

        dpci_uuid = uuid.createString()

        dpci_opts = []
        opts_dict = xenapi_pci.get('options')
        for k in opts_dict.keys():
            dpci_opts.append([k, opts_dict[k]])
        opts_sxp = pci_opts_list_to_sxp(dpci_opts)

        # Convert xenapi to sxp
        ppci = XendAPIStore.get(xenapi_pci.get('PPCI'), 'PPCI')

        dev_sxp = ['dev',
                   ['domain', '0x%02x' % ppci.get_domain()],
                   ['bus', '0x%02x' % ppci.get_bus()],
                   ['slot', '0x%02x' % ppci.get_slot()],
                   ['func', '0x%1x' % ppci.get_func()],
                   ['vdevfn', '0x%02x' % xenapi_pci.get('hotplug_slot')],
                   ['key', xenapi_pci['key']],
                   ['uuid', dpci_uuid]]
        dev_sxp = sxp.merge(dev_sxp, opts_sxp)

        target_pci_sxp = ['pci', dev_sxp, ['state', 'Initialising'] ]

        if self._stateGet() != XEN_API_VM_POWER_STATE_RUNNING:

            old_pci_sxp = self._getDeviceInfo_pci(0)

            if old_pci_sxp is None:
                dev_uuid = self.info.device_add('pci', cfg_sxp = target_pci_sxp)
                if not dev_uuid:
                    raise XendError('Failed to create device')

            else:
                new_pci_sxp = ['pci']
                for existing_dev in sxp.children(old_pci_sxp, 'dev'):
                    new_pci_sxp.append(existing_dev)
                new_pci_sxp.append(sxp.child0(target_pci_sxp, 'dev'))

                dev_uuid = sxp.child_value(old_pci_sxp, 'uuid')
                self.info.device_update(dev_uuid, new_pci_sxp)

            xen.xend.XendDomain.instance().managed_config_save(self)

        else:
            try:
                self.device_configure(target_pci_sxp)

            except Exception, exn:
                raise XendError('Failed to create device')

        return dpci_uuid

    def create_dscsi(self, xenapi_dscsi):
        """Create scsi device from the passed struct in Xen API format.

        @param xenapi_dscsi: DSCSI struct from Xen API
        @rtype: string
        @return: UUID
        """

        dscsi_uuid = uuid.createString()

        # Convert xenapi to sxp
        pscsi = XendAPIStore.get(xenapi_dscsi.get('PSCSI'), 'PSCSI')
        devid = int(xenapi_dscsi.get('virtual_HCTL').split(':')[0])
        target_vscsi_sxp = \
            ['vscsi', 
                ['dev',
                    ['devid', devid],
                    ['p-devname', pscsi.get_dev_name()],
                    ['p-dev', pscsi.get_physical_HCTL()],
                    ['v-dev', xenapi_dscsi.get('virtual_HCTL')],
                    ['state', xenbusState['Initialising']],
                    ['uuid', dscsi_uuid]
                ],
                ['feature-host', 0]
            ]

        if self._stateGet() != XEN_API_VM_POWER_STATE_RUNNING:

            cur_vscsi_sxp = self._getDeviceInfo_vscsi(devid)

            if cur_vscsi_sxp is None:
                dev_uuid = self.info.device_add('vscsi', cfg_sxp = target_vscsi_sxp)
                if not dev_uuid:
                    raise XendError('Failed to create device')

            else:
                new_vscsi_sxp = ['vscsi', ['feature-host', 0]]
                for existing_dev in sxp.children(cur_vscsi_sxp, 'dev'):
                    new_vscsi_sxp.append(existing_dev)
                new_vscsi_sxp.append(sxp.child0(target_vscsi_sxp, 'dev'))

                dev_uuid = sxp.child_value(cur_vscsi_sxp, 'uuid')
                self.info.device_update(dev_uuid, new_vscsi_sxp)

            xen.xend.XendDomain.instance().managed_config_save(self)

        else:
            try:
                self.device_configure(target_vscsi_sxp)
            except Exception, exn:
                log.exception('create_dscsi: %s', exn)
                raise XendError('Failed to create device')

        return dscsi_uuid

    def create_dscsi_HBA(self, xenapi_dscsi):
        """Create scsi devices from the passed struct in Xen API format.

        @param xenapi_dscsi: DSCSI_HBA struct from Xen API
        @rtype: string
        @return: UUID
        """

        dscsi_HBA_uuid = uuid.createString()

        # Convert xenapi to sxp
        feature_host = xenapi_dscsi.get('assignment_mode', 'HOST') == 'HOST' and 1 or 0
        target_vscsi_sxp = \
            ['vscsi',
                ['feature-host', feature_host],
                ['uuid', dscsi_HBA_uuid],
            ]
        pscsi_HBA = XendAPIStore.get(xenapi_dscsi.get('PSCSI_HBA'), 'PSCSI_HBA')
        devid = pscsi_HBA.get_physical_host()
        for pscsi_uuid in pscsi_HBA.get_PSCSIs():
            pscsi = XendAPIStore.get(pscsi_uuid, 'PSCSI')
            pscsi_HCTL = pscsi.get_physical_HCTL()
            dscsi_uuid = uuid.createString()
            dev = \
                ['dev',
                    ['devid', devid],
                    ['p-devname', pscsi.get_dev_name()],
                    ['p-dev', pscsi_HCTL],
                    ['v-dev', pscsi_HCTL],
                    ['state', xenbusState['Initialising']],
                    ['uuid', dscsi_uuid]
                ]
            target_vscsi_sxp.append(dev)

        if self._stateGet() != XEN_API_VM_POWER_STATE_RUNNING:
            if not self.info.device_add('vscsi', cfg_sxp = target_vscsi_sxp):
                raise XendError('Failed to create device')
            xen.xend.XendDomain.instance().managed_config_save(self)
        else:
            try:
                self.device_configure(target_vscsi_sxp)
            except Exception, exn:
                log.exception('create_dscsi_HBA: %s', exn)
                raise XendError('Failed to create device')

        return dscsi_HBA_uuid


    def change_vdi_of_vbd(self, xenapi_vbd, vdi_image_path):
        """Change current VDI with the new VDI.

        @param xenapi_vbd: vbd struct from the Xen API
        @param vdi_image_path: path of VDI
        """
        dev_uuid = xenapi_vbd['uuid']
        if dev_uuid not in self.info['devices']:
            raise XendError('Device does not exist')

        # Convert xenapi to sxp
        if vdi_image_path.startswith('tap'):
            dev_class = 'tap'
        else:
            dev_class = 'vbd'
        dev_sxp = [
            dev_class,
            ['uuid',  dev_uuid],
            ['uname', vdi_image_path],
            ['dev',   '%s:cdrom' % xenapi_vbd['device']],
            ['mode',  'r'],
            ['VDI',   xenapi_vbd['VDI']]
        ]

        if self._stateGet() in (XEN_API_VM_POWER_STATE_RUNNING,
                                XEN_API_VM_POWER_STATE_PAUSED):
            self.device_configure(dev_sxp)
        else:
            self.info.device_update(dev_uuid, dev_sxp)


    def destroy_device_by_uuid(self, dev_type, dev_uuid):
        if dev_uuid not in self.info['devices']:
            raise XendError('Device does not exist')

        try:
            if self._stateGet() in (XEN_API_VM_POWER_STATE_RUNNING,
                                    XEN_API_VM_POWER_STATE_PAUSED):
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

    def destroy_dpci(self, dev_uuid):

        dpci = XendAPIStore.get(dev_uuid, 'DPCI')
        ppci = XendAPIStore.get(dpci.get_PPCI(), 'PPCI')

        old_pci_sxp = self._getDeviceInfo_pci(0)
        dev_uuid = sxp.child_value(old_pci_sxp, 'uuid')
        target_dev = None
        new_pci_sxp = ['pci']
        for dev in sxp.children(old_pci_sxp, 'dev'):
            pci_dev = {}
            pci_dev['domain'] = sxp.child_value(dev, 'domain')
            pci_dev['bus'] = sxp.child_value(dev, 'bus')
            pci_dev['slot'] = sxp.child_value(dev, 'slot')
            pci_dev['func'] = sxp.child_value(dev, 'func')
            if ppci.get_name() == pci_dict_to_bdf_str(pci_dev):
                target_dev = dev
            else:
                new_pci_sxp.append(dev)

        if target_dev is None:
            raise XendError('Failed to destroy device')

        target_pci_sxp = ['pci', target_dev, ['state', 'Closing']]

        if self._stateGet() != XEN_API_VM_POWER_STATE_RUNNING:

            self.info.device_update(dev_uuid, new_pci_sxp)
            if len(sxp.children(new_pci_sxp, 'dev')) == 0:
                del self.info['devices'][dev_uuid]
            xen.xend.XendDomain.instance().managed_config_save(self)

        else:
            try:
                self.device_configure(target_pci_sxp)

            except Exception, exn:
                raise XendError('Failed to destroy device')

    def destroy_dscsi(self, dev_uuid):
        dscsi = XendAPIStore.get(dev_uuid, 'DSCSI')
        devid = dscsi.get_virtual_host()
        vHCTL = dscsi.get_virtual_HCTL()
        cur_vscsi_sxp = self._getDeviceInfo_vscsi(devid)
        dev_uuid = sxp.child_value(cur_vscsi_sxp, 'uuid')

        target_dev = None
        new_vscsi_sxp = ['vscsi', ['feature-host', 0]]
        for dev in sxp.children(cur_vscsi_sxp, 'dev'):
            if vHCTL == sxp.child_value(dev, 'v-dev'):
                target_dev = dev
            else:
                new_vscsi_sxp.append(dev)

        if target_dev is None:
            raise XendError('Failed to destroy device')

        target_dev.append(['state', xenbusState['Closing']])
        target_vscsi_sxp = ['vscsi', target_dev, ['feature-host', 0]]

        if self._stateGet() != XEN_API_VM_POWER_STATE_RUNNING:

            self.info.device_update(dev_uuid, new_vscsi_sxp)
            if len(sxp.children(new_vscsi_sxp, 'dev')) == 0:
                del self.info['devices'][dev_uuid]
            xen.xend.XendDomain.instance().managed_config_save(self)

        else:
            try:
                self.device_configure(target_vscsi_sxp)
            except Exception, exn:
                log.exception('destroy_dscsi: %s', exn)
                raise XendError('Failed to destroy device')

    def destroy_dscsi_HBA(self, dev_uuid):
        dscsi_HBA = XendAPIStore.get(dev_uuid, 'DSCSI_HBA')
        devid = dscsi_HBA.get_virtual_host()
        cur_vscsi_sxp = self._getDeviceInfo_vscsi(devid)
        feature_host = sxp.child_value(cur_vscsi_sxp, 'feature-host')

        if self._stateGet() != XEN_API_VM_POWER_STATE_RUNNING:
            new_vscsi_sxp = ['vscsi', ['feature-host', feature_host]]
            self.info.device_update(dev_uuid, new_vscsi_sxp)
            del self.info['devices'][dev_uuid]
            xen.xend.XendDomain.instance().managed_config_save(self)
        else:
            # If feature_host is 1, all devices are destroyed by just
            # one reconfiguration.
            # If feature_host is 0, we should reconfigure all devices
            # one-by-one to destroy all devices.
            # See reconfigureDevice@VSCSIController. 
            for dev in sxp.children(cur_vscsi_sxp, 'dev'):
                target_vscsi_sxp = [
                    'vscsi',
                    dev + [['state', xenbusState['Closing']]],
                    ['feature-host', feature_host]
                ]
                try:
                    self.device_configure(target_vscsi_sxp)
                except Exception, exn:
                    log.exception('destroy_dscsi_HBA: %s', exn)
                    raise XendError('Failed to destroy device')
                if feature_host:
                    break

    def destroy_xapi_instances(self):
        """Destroy Xen-API instances stored in XendAPIStore.
        """
        # Xen-API classes based on XendBase have their instances stored
        # in XendAPIStore. Cleanup these instances here, if they are supposed
        # to be destroyed when the parent domain is dead.
        #
        # Most of the virtual devices (vif, vbd, vfb, etc) are not based on
        # XendBase and there's no need to remove them from XendAPIStore.

        from xen.xend import XendDomain
        if XendDomain.instance().is_valid_vm(self.info.get('uuid')):
            # domain still exists.
            return

        # Destroy the VMMetrics instance.
        if XendAPIStore.get(self.metrics.get_uuid(), self.metrics.getClass()) \
                is not None:
            self.metrics.destroy()

        # Destroy DPCI instances.
        for dpci_uuid in XendDPCI.get_by_VM(self.info.get('uuid')):
            XendAPIStore.deregister(dpci_uuid, "DPCI")
            
        # Destroy DSCSI instances.
        for dscsi_uuid in XendDSCSI.get_by_VM(self.info.get('uuid')):
            XendAPIStore.deregister(dscsi_uuid, "DSCSI")
            
        # Destroy DSCSI_HBA instances.
        for dscsi_HBA_uuid in XendDSCSI_HBA.get_by_VM(self.info.get('uuid')):
            XendAPIStore.deregister(dscsi_HBA_uuid, "DSCSI_HBA")
            
    def has_device(self, dev_class, dev_uuid):
        return (dev_uuid in self.info['%s_refs' % dev_class.lower()])

    def __str__(self):
        return '<domain id=%s name=%s memory=%s state=%s>' % \
               (str(self.domid), self.info['name_label'],
                str(self.info['memory_dynamic_max']), DOM_STATES[self._stateGet()])

    __repr__ = __str__

