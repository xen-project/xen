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
# Copyright (C) 2005 XenSource Ltd
#============================================================================


import types
import time

from xen.xend import sxp
from xen.xend import XendOptions
xoptions = XendOptions.instance()

from xen.xend import arch
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log
from xen.xend.XendConstants import *

from xen.xend.server.DevController import DevController
from xen.xend.server.DevConstants import xenbusState

import xen.lowlevel.xc

from xen.util.pci import *
import resource
import re

from xen.xend.server.pciquirk import *
from xen.xend.xenstore.xstransact import xstransact
from xen.xend.xenstore.xswatch import xswatch

xc = xen.lowlevel.xc.xc()

#Calculate PAGE_SHIFT: number of bits to shift an address to get the page number
PAGE_SIZE = resource.getpagesize()
PAGE_SHIFT = 0
t = PAGE_SIZE
while not (t&1):
    t>>=1
    PAGE_SHIFT+=1

def parse_hex(val):
    try:
        if isinstance(val, types.StringTypes):
            return int(val, 16)
        else:
            return val
    except ValueError:
        return None

def get_assigned_pci_devices(domid):
    dev_str_list = []
    path = '/local/domain/0/backend/pci/%u/0/' % domid
    num_devs = xstransact.Read(path + 'num_devs');
    if num_devs is None or num_devs == "":
        return dev_str_list
    num_devs = int(num_devs)
    for i in range(num_devs):
        dev_str = xstransact.Read(path + 'dev-%i' % i)
        dev_str_list = dev_str_list + [dev_str]
    return dev_str_list

def get_all_assigned_pci_devices(domid = 0):
    dom_list = xstransact.List('/local/domain')
    pci_str_list = []
    ti = 0
    ts = xstransact.Read('/local/domain/' + str(domid) + '/target')
    if ts is not None :
        ti = int(ts)
    for d in dom_list:
        target = xstransact.Read('/local/domain/' + d + '/target')
        if int(d) is not ti and target is None :
            pci_str_list = pci_str_list + get_assigned_pci_devices(int(d))
    return pci_str_list

class PciController(DevController):

    def __init__(self, vm):
        self.aerStateWatch = None
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        back = {}
        pcidevid = 0
        for pci_config in config.get('devs', []):
            domain = parse_hex(pci_config.get('domain', 0))
            bus = parse_hex(pci_config.get('bus', 0))
            slot = parse_hex(pci_config.get('slot', 0))
            func = parse_hex(pci_config.get('func', 0))            
            vdevfn = parse_hex(pci_config.get('vdevfn', \
                                              '0x%02x' % AUTO_PHP_SLOT))

            if pci_config.has_key('opts'):
                opts = serialise_pci_opts(pci_config['opts'])
                back['opts-%i' % pcidevid] = opts

            back['dev-%i' % pcidevid] = "%04x:%02x:%02x.%01x" % \
                                        (domain, bus, slot, func)
            back['uuid-%i' % pcidevid] = pci_config.get('uuid', '')
            back['key-%i' % pcidevid] = pci_config.get('key', '')
            back['vdevfn-%i' % pcidevid] = "%02x" % vdevfn
            pcidevid += 1

        back['num_devs']=str(pcidevid)
        back['uuid'] = config.get('uuid','')
        if 'pci_msitranslate' in self.vm.info['platform']:
            back['msitranslate']=str(self.vm.info['platform']['pci_msitranslate'])
        if 'pci_power_mgmt' in self.vm.info['platform']:
            back['power_mgmt']=str(self.vm.info['platform']['pci_power_mgmt'])

        return (0, back, {})

    def reconfigureDevice_find(self, devid, nsearch_dev, match_dev):
        for j in range(nsearch_dev):
            if match_dev == self.readBackend(devid, 'dev-%i' % j):
                return j
        return None

    def reconfigureDevice(self, _, config):
        """@see DevController.reconfigureDevice"""
        (devid, back, front) = self.getDeviceDetails(config)
        num_devs = int(back['num_devs'])
        states = config.get('states', [])
        num_olddevs = int(self.readBackend(devid, 'num_devs'))

        for i in range(num_devs):
            try:
                dev = back['dev-%i' % i]
                state = states[i]
                uuid = back['uuid-%i' %i]
                key = back['key-%i' %i]
                opts = ''
                if 'opts-%i' % i in back:
                    opts = back['opts-%i' % i]
            except:
                raise XendError('Error reading config')

            if state == 'Initialising':
                devno = self.reconfigureDevice_find(devid, num_olddevs, dev)
                if devno == None:
                    devno = num_olddevs + i
                    log.debug('Attaching PCI device %s.' % dev)
                    attaching = True
                else:
                    log.debug('Reconfiguring PCI device %s.' % dev)
                    attaching = False

                self.setupOneDevice(parse_pci_name(dev))

                self.writeBackend(devid, 'dev-%i' % devno, dev)
                self.writeBackend(devid, 'state-%i' % devno,
                                  str(xenbusState['Initialising']))
                self.writeBackend(devid, 'uuid-%i' % devno, uuid)
                self.writeBackend(devid, 'key-%i' % devno, key)
                if len(opts) > 0:
                    self.writeBackend(devid, 'opts-%i' % devno, opts)
                if back.has_key('vdevfn-%i' % i):
                    self.writeBackend(devid, 'vdevfn-%i' % devno,
                                      back['vdevfn-%i' % i])

                # If a device is being attached then num_devs will grow
                if attaching:
                    self.writeBackend(devid, 'num_devs', str(devno + 1))

            elif state == 'Closing':
                # PCI device detachment
                devno = self.reconfigureDevice_find(devid, num_olddevs, dev)
                if devno == None:
                    raise XendError('Device %s is not connected' % dev)
                log.debug('Detaching device %s' % dev)
                self.writeBackend(devid, 'state-%i' % devno,
                                  str(xenbusState['Closing']))

            else:
                raise XendError('Error configuring device %s: invalid state %s'
                                % (dev,state))

        self.writeBackend(devid, 'state', str(xenbusState['Reconfiguring']))

        return self.readBackend(devid, 'uuid')


    def getDeviceConfiguration(self, devid, transaction = None):
        result = DevController.getDeviceConfiguration(self, devid, transaction)
        num_devs = self.readBackend(devid, 'num_devs')
        pci_devs = []

        for i in range(int(num_devs)):
            pci_dev = parse_pci_name(self.readBackend(devid, 'dev-%d' % i))

            # Per device uuid info
            pci_dev['uuid'] = self.readBackend(devid, 'uuid-%d' % i)
            pci_dev['key'] = self.readBackend(devid, 'key-%d' % i)
            pci_dev['vdevfn'] = '0x%s' % self.readBackend(devid,
                                                          'vdevfn-%d' % i)

            #append opts info
            opts = self.readBackend(devid, 'opts-%d' % i)
            if opts is not None:
                pci_dev['opts'] = opts

            pci_devs.append(pci_dev)

        result['devs'] = pci_devs
        result['uuid'] = self.readBackend(devid, 'uuid')
        return result

    def configuration(self, devid, transaction = None):
        """Returns SXPR for devices on domain.

        @note: we treat this dict especially to convert to
        SXP because it is not a straight dict of strings."""
        
        configDict = self.getDeviceConfiguration(devid, transaction)
        sxpr = [self.deviceClass]

        # remove devs
        devs = configDict.pop('devs', [])
        
        for dev in devs:
            dev_sxpr = ['dev']
            for dev_key, dev_val in dev.items():
                if dev_key == 'opts':
                    opts_sxpr = pci_opts_list_to_sxp(split_pci_opts(dev_val))
                    dev_sxpr = sxp.merge(dev_sxpr, opts_sxpr)
                else:
                    dev_sxpr.append([dev_key, dev_val])
            sxpr.append(dev_sxpr)
        
        for key, val in configDict.items():
            if type(val) == type(list()):
                for v in val:
                    sxpr.append([key, v])
            else:
                sxpr.append([key, val])

        return sxpr    

    def CheckSiblingDevices(self, domid, dev):
        """ Check if all sibling devices of dev are owned by pciback or pci-stub
        """
        if not self.vm.info.is_hvm():
            return

        group_str = xc.get_device_group(domid, dev.domain, dev.bus, dev.slot, dev.func)
        if group_str == "":
            return

        #group string format xx:xx.x,xx:xx.x,
        for i in group_str.split(','):
            if i == '':
                continue
            pci_dev = parse_pci_name(i)
            pci_dev['domain'] = '%04x' % dev.domain
            try:
                sdev = PciDevice(pci_dev)
            except Exception, e:
                #no dom0 drivers bound to sdev
                continue

            if sdev.driver!='pciback' and sdev.driver!='pci-stub':
                raise VmError(("pci: PCI Backend and pci-stub don't\n "+ \
                    "own sibling device %s of device %s\n"\
                    )%(sdev.name, dev.name))
        return

    def setupOneDevice(self, pci_dev):
        """ Attach I/O resources for device to frontend domain
        """
        fe_domid = self.getDomid()

        try:
            dev = PciDevice(pci_dev)
        except Exception, e:
            raise VmError("pci: failed to locate device and "+
                    "parse its resources - "+str(e))

        if dev.driver!='pciback' and dev.driver!='pci-stub':
            raise VmError(("pci: PCI Backend and pci-stub don't own "+ \
                    "device %s\n") %(dev.name))

        self.CheckSiblingDevices(fe_domid, dev)

        # We don't do FLR when we create domain and hotplug device into guest,
        # namely, we only do FLR when we destroy domain or hotplug device from
        # guest. This is mainly to work around the race condition in hotplug code
        # paths. See the changeset's description for details.
        # if arch.type != "ia64":
        #    dev.do_FLR()

        if dev.driver == 'pciback':
            PCIQuirk(dev)

        if not self.vm.info.is_hvm() and not self.vm.info.is_stubdom() :
            # Setup IOMMU device assignment
            bdf = xc.assign_device(fe_domid, pci_dict_to_xc_str(pci_dev))
            pci_str = pci_dict_to_bdf_str(pci_dev)
            if bdf > 0:
                raise VmError("Failed to assign device to IOMMU (%s)" % pci_str)
            log.debug("pci: assign device %s" % pci_str)

        for (start, size) in dev.ioports:
            log.debug('pci: enabling ioport 0x%x/0x%x'%(start,size))
            rc = xc.domain_ioport_permission(domid = fe_domid, first_port = start,
                    nr_ports = size, allow_access = True)
            if rc<0:
                raise VmError(('pci: failed to configure I/O ports on device '+
                            '%s - errno=%d')%(dev.name,rc))
            
        for (start, size) in dev.iomem:
            # Convert start/size from bytes to page frame sizes
            start_pfn = start>>PAGE_SHIFT
            # Round number of pages up to nearest page boundary (if not on one)
            nr_pfns = (size+(PAGE_SIZE-1))>>PAGE_SHIFT

            log.debug('pci: enabling iomem 0x%x/0x%x pfn 0x%x/0x%x'% \
                    (start,size,start_pfn,nr_pfns))
            rc = xc.domain_iomem_permission(domid =  fe_domid,
                    first_pfn = start_pfn,
                    nr_pfns = nr_pfns,
                    allow_access = True)
            if rc<0:
                raise VmError(('pci: failed to configure I/O memory on device '+
                            '%s - errno=%d')%(dev.name,rc))

        if not self.vm.info.is_hvm() and dev.irq:
            rc = xc.physdev_map_pirq(domid = fe_domid,
                                   index = dev.irq,
                                   pirq  = dev.irq)
            if rc < 0:
                raise VmError(('pci: failed to map irq on device '+
                            '%s - errno=%d')%(dev.name,rc))
        if dev.irq>0:
            log.debug('pci: enabling irq %d'%dev.irq)
            rc = xc.domain_irq_permission(domid =  fe_domid, pirq = dev.irq,
                    allow_access = True)
            if rc<0:
                raise VmError(('pci: failed to configure irq on device '+
                            '%s - errno=%d')%(dev.name,rc))

    def setupDevice(self, config):
        """Setup devices from config
        """
        pci_dev_list = config.get('devs', [])
        pci_str_list = map(pci_dict_to_bdf_str, pci_dev_list)

        if len(pci_str_list) != len(set(pci_str_list)):
            raise VmError('pci: duplicate devices specified in guest config?')

        strict_check = xoptions.get_pci_dev_assign_strict_check()
        for pci_dev in pci_dev_list:
            try:
                dev = PciDevice(pci_dev)
            except Exception, e:
                raise VmError("pci: failed to locate device and "+
                        "parse its resources - "+str(e))

            if dev.has_non_page_aligned_bar and strict_check:
                raise VmError("pci: %s: non-page-aligned MMIO BAR found." % dev.name)

            # Check if there is intermediate PCIe switch bewteen the device and
            # Root Complex.
            if self.vm.info.is_hvm() and dev.is_behind_switch_lacking_acs() \
                and strict_check:
                err_msg = 'pci: to avoid potential security issue, %s is not'+\
                        ' allowed to be assigned to guest since it is behind'+\
                        ' PCIe switch that does not support or enable ACS.'
                raise VmError(err_msg % dev.name)

            if (dev.dev_type == DEV_TYPE_PCIe_ENDPOINT) and not dev.pcie_flr:
                if dev.bus == 0:
                    # We cope with this case by using the Dstate transition
                    # method or some vendor specific methods for now.
                    err_msg = 'pci: %s: it is on bus 0, but has no PCIe' +\
                        ' FLR Capability. Will try the Dstate transition'+\
                        ' method or some vendor specific methods if available.'
                    log.warn(err_msg % dev.name)
                else:
                    if not self.vm.info.is_hvm():
                        continue
                    if not strict_check:
                        continue

                    funcs = dev.find_all_the_multi_functions()
                    dev.devs_check_driver(funcs)
                    for f in funcs:
                        if not f in pci_str_list:
                            # f has been assigned to other guest?
                            if f in get_all_assigned_pci_devices():
                                err_msg = 'pci: %s must be co-assigned to' + \
                                    ' the same guest with %s'
                                raise VmError(err_msg % (f, dev.name))
            elif dev.dev_type == DEV_TYPE_PCI:
                if dev.bus == 0 or arch.type == "ia64":
                    if not dev.pci_af_flr:
                        # We cope with this case by using the Dstate transition
                        # method or some vendor specific methods for now.
                        err_msg = 'pci: %s: it is on bus 0, but has no PCI' +\
                            ' Advanced Capabilities for FLR. Will try the'+\
                            ' Dstate transition method or some vendor' +\
                            ' specific methods if available.'
                        log.warn(err_msg % dev.name)
                else:
                    if not self.vm.info.is_hvm():
                        continue
                    if not strict_check:
                        continue

                    # All devices behind the uppermost PCI/PCI-X bridge must be\
                    # co-assigned to the same guest.
                    devs_str = dev.find_coassigned_pci_devices(True)
                    # Remove the element 0 which is a bridge
                    del devs_str[0]

                    dev.devs_check_driver(devs_str)
                    for s in devs_str:
                        if not s in pci_str_list:
                            # s has been assigned to other guest?
                            if s in get_all_assigned_pci_devices():
                                err_msg = 'pci: %s must be co-assigned to the'+\
                                    ' same guest with %s'
                                raise VmError(err_msg % (s, dev.name))

        # Assigning device staticaly (namely, the pci string in guest config
        # file) to PV guest needs this setupOneDevice().
        # Assigning device dynamically (namely, 'xm pci-attach') to PV guest
        #  would go through reconfigureDevice().
        #
        # For hvm guest, (from c/s 19679 on) assigning device statically and
        # dynamically both go through reconfigureDevice(), so HERE the
        # setupOneDevice() is not necessary.
        if not self.vm.info.is_hvm():
            for d in pci_dev_list:
                self.setupOneDevice(d)
        wPath = '/local/domain/0/backend/pci/%u/0/aerState' % (self.getDomid())
        self.aerStateWatch = xswatch(wPath, self._handleAerStateWatch)
        log.debug('pci: register aer watch %s', wPath)
        return

    def _handleAerStateWatch(self, _):
        log.debug('XendDomainInfo.handleAerStateWatch')
        if self.getDomid() == 0:
            raise XendError('Domain 0 cannot be shutdown')
        readPath = '/local/domain/0/backend/pci/%u/0/aerState' % (self.getDomid())
        action = xstransact.Read(readPath)
        if action and action=='aerfail':
            log.debug('shutdown domain because of aer handle error')
            self.vm.shutdown('poweroff')
        return True


    def cleanupOneDevice(self, pci_dev):
        """ Detach I/O resources for device from frontend domain
        """
        fe_domid = self.getDomid()

        try:
            dev = PciDevice(pci_dev)
        except Exception, e:
            raise VmError("pci: failed to locate device and "+
                    "parse its resources - "+str(e))

        if dev.driver!='pciback' and dev.driver!='pci-stub':
            raise VmError(("pci: PCI Backend and pci-stub don't own device "+ \
                    "%s\n") %(dev.name))

        # Need to do FLR here before deassign device in order to terminate
        # DMA transaction, etc
        dev.do_FLR(self.vm.info.is_hvm(),
            xoptions.get_pci_dev_assign_strict_check())

        if not self.vm.info.is_stubdom() :
            bdf = xc.deassign_device(fe_domid, pci_dict_to_xc_str(pci_dev))
            pci_str = pci_dict_to_bdf_str(pci_dev)
            if bdf > 0:
                raise VmError("Failed to deassign device from IOMMU (%s)" % pci_str)
            log.debug("pci: Deassign device %s" % pci_str)

        for (start, size) in dev.ioports:
            log.debug('pci: disabling ioport 0x%x/0x%x'%(start,size))
            rc = xc.domain_ioport_permission(domid = fe_domid, first_port = start,
                    nr_ports = size, allow_access = False)
            if rc<0:
                raise VmError(('pci: failed to configure I/O ports on device '+
                            '%s - errno=%d')%(dev.name,rc))

        for (start, size) in dev.iomem:
            # Convert start/size from bytes to page frame sizes
            start_pfn = start>>PAGE_SHIFT
            # Round number of pages up to nearest page boundary (if not on one)
            nr_pfns = (size+(PAGE_SIZE-1))>>PAGE_SHIFT

            log.debug('pci: disabling iomem 0x%x/0x%x pfn 0x%x/0x%x'% \
                    (start,size,start_pfn,nr_pfns))
            rc = xc.domain_iomem_permission(domid =  fe_domid,
                    first_pfn = start_pfn,
                    nr_pfns = nr_pfns,
                    allow_access = False)
            if rc<0:
                raise VmError(('pci: failed to configure I/O memory on device '+
                            '%s - errno=%d')%(dev.name,rc))

        if dev.irq>0:
            log.debug('pci: disabling irq %d'%dev.irq)
            rc = xc.domain_irq_permission(domid =  fe_domid, pirq = dev.irq,
                    allow_access = False)
            if rc<0:
                raise VmError(('pci: failed to configure irq on device '+
                            '%s - errno=%d')%(dev.name,rc))

    def cleanupDevice(self, devid):
        """ Detach I/O resources for device and cleanup xenstore nodes
        after reconfigure.

        @param devid: The device ID
        @type devid:  int
        @return:      Return the number of devices connected
        @rtype:       int
        """
        num_devs = int(self.readBackend(devid, 'num_devs'))
        new_num_devs = 0
        for i in range(num_devs):
            try:
                state = int(self.readBackend(devid, 'state-%i' % i))
            except:
                state = xenbusState['Unknown']

            if state == xenbusState['Closing']:
                # Detach I/O resources.
                pci_dev = parse_pci_name(self.readBackend(devid, 'dev-%i' % i))
                # In HVM case, I/O resources are disabled in ioemu.
                self.cleanupOneDevice(pci_dev)
                # Remove xenstore nodes.
                list = ['dev', 'vdev', 'state', 'uuid', 'vdevfn', 'key']
                if self.readBackend(devid, 'opts-%i' % i) is not None:
                    list.append('opts')
                for key in list:
                    self.removeBackend(devid, '%s-%i' % (key, i))
            else:
                new_num_devs = new_num_devs + 1
                if new_num_devs == i + 1:
                    continue

                list = ['dev', 'vdev', 'state', 'uuid', 'opts', 'vdevfn', 'key']
                for key in list:
                    tmp = self.readBackend(devid, '%s-%i' % (key, i))
                    if tmp is None:
                        continue
                    self.removeBackend(devid, '%s-%i' % (key, i))
                    self.writeBackend(devid,
                                      '%s-%i' % (key, new_num_devs - 1), tmp)

        self.writeBackend(devid, 'num_devs', str(new_num_devs))

        return new_num_devs

    def destroyDevice(self, devid, force):
        DevController.destroyDevice(self, devid, True)
        log.debug('pci: unregister aer watch')
        self.unwatchAerState()

    def unwatchAerState(self):
        """Remove the watch on the domain's aerState node, if any."""
        try:
            try:
                if self.aerStateWatch:
                    self.aerStateWatch.unwatch()
            finally:
                self.aerStateWatch = None
        except:
            log.exception("Unwatching aerState failed.")
  
    def waitForBackend(self,devid):
        return (0, "ok - no hotplug")

    def migrate(self, config, network, dst, step, domName):
        raise XendError('Migration not permitted with assigned PCI device.')
