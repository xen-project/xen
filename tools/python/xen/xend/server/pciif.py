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
            vslot = parse_hex(pci_config.get('vslot',
                                             '0x' + AUTO_PHP_SLOT_STR))

            if pci_config.has_key('opts'):
                opts = serialise_pci_opts(pci_config['opts'])
                back['opts-%i' % pcidevid] = opts

            back['dev-%i' % pcidevid] = "%04x:%02x:%02x.%01x" % \
                                        (domain, bus, slot, func)
            back['uuid-%i' % pcidevid] = pci_config.get('uuid', '')
            back['vslot-%i' % pcidevid] = "%02x" % vslot
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

                (domain, bus, slotfunc) = dev.split(':')
                (slot, func) = slotfunc.split('.')
                domain = parse_hex(domain)
                bus = parse_hex(bus)
                slot = parse_hex(slot)
                func = parse_hex(func)
                self.setupOneDevice(domain, bus, slot, func)

                self.writeBackend(devid, 'dev-%i' % devno, dev)
                self.writeBackend(devid, 'state-%i' % devno,
                                  str(xenbusState['Initialising']))
                self.writeBackend(devid, 'uuid-%i' % devno, uuid)
                if len(opts) > 0:
                    self.writeBackend(devid, 'opts-%i' % devno, opts)
                if back.has_key('vslot-%i' % i):
                    self.writeBackend(devid, 'vslot-%i' % devno,
                                      back['vslot-%i' % i])

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
            dev_config = self.readBackend(devid, 'dev-%d' % i)

            pci_match = re.match(r"((?P<domain>[0-9a-fA-F]{1,4})[:,])?" +
                                 r"(?P<bus>[0-9a-fA-F]{1,2})[:,]" + 
                                 r"(?P<slot>[0-9a-fA-F]{1,2})[.,]" + 
                                 r"(?P<func>[0-7]{1,2})$", dev_config)
            
            if pci_match!=None:
                pci_dev_info = pci_match.groupdict()
                dev_dict = {'domain': '0x%(domain)s' % pci_dev_info,
                                 'bus': '0x%(bus)s' % pci_dev_info,
                                 'slot': '0x%(slot)s' % pci_dev_info,
                                 'func': '0x%(func)s' % pci_dev_info}

                # Per device uuid info
                dev_dict['uuid'] = self.readBackend(devid, 'uuid-%d' % i)
                dev_dict['vslot'] = '0x%s' % \
                                    self.readBackend(devid, 'vslot-%d' % i)

                #append opts info
                opts = self.readBackend(devid, 'opts-%d' % i)
                if opts is not None:
                    dev_dict['opts'] = opts

                pci_devs.append(dev_dict)

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
                    dev_sxpr.append(['opts', split_pci_opts(dev_val)])
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
        """ Check if all sibling devices of dev are owned by pciback
        """
        if not self.vm.info.is_hvm():
            return

        group_str = xc.get_device_group(domid, dev.domain, dev.bus, dev.slot, dev.func)
        if group_str == "":
            return

        #group string format xx:xx.x,xx:xx.x,
        devstr_len = group_str.find(',')
        for i in range(0, len(group_str), devstr_len + 1):
            (bus, slotfunc) = group_str[i:i + devstr_len].split(':')
            (slot, func) = slotfunc.split('.')
            b = parse_hex(bus)
            d = parse_hex(slot)
            f = parse_hex(func)
            try:
                sdev = PciDevice(dev.domain, b, d, f)
            except Exception, e:
                #no dom0 drivers bound to sdev
                continue

            if sdev.driver!='pciback':
                raise VmError(("pci: PCI Backend does not own\n "+ \
                    "sibling device %s of device %s\n"+ \
                    "See the pciback.hide kernel "+ \
                    "command-line parameter or\n"+ \
                    "bind your slot/device to the PCI backend using sysfs" \
                    )%(sdev.name, dev.name))
        return

    def setupOneDevice(self, domain, bus, slot, func):
        """ Attach I/O resources for device to frontend domain
        """
        fe_domid = self.getDomid()

        try:
            dev = PciDevice(domain, bus, slot, func)
        except Exception, e:
            raise VmError("pci: failed to locate device and "+
                    "parse it's resources - "+str(e))

        if dev.driver!='pciback':
            raise VmError(("pci: PCI Backend does not own device "+ \
                    "%s\n"+ \
                    "See the pciback.hide kernel "+ \
                    "command-line parameter or\n"+ \
                    "bind your slot/device to the PCI backend using sysfs" \
                    )%(dev.name))

        if dev.has_non_page_aligned_bar and arch.type != "ia64":
            raise VmError("pci: %s: non-page-aligned MMIO BAR found." % dev.name)

        self.CheckSiblingDevices(fe_domid, dev)

        # We don't do FLR when we create domain and hotplug device into guest,
        # namely, we only do FLR when we destroy domain or hotplug device from
        # guest. This is mainly to work around the race condition in hotplug code
        # paths. See the changeset's description for details.
        # if arch.type != "ia64":
        #    dev.do_FLR()

        PCIQuirk(dev.vendor, dev.device, dev.subvendor, dev.subdevice, domain, 
                bus, slot, func)

        if not self.vm.info.is_hvm():
            # Setup IOMMU device assignment
            pci_str = "0x%x, 0x%x, 0x%x, 0x%x" % (domain, bus, slot, func)
            bdf = xc.assign_device(fe_domid, pci_str)
            if bdf > 0:
                raise VmError("Failed to assign device to IOMMU (%x:%x.%x)"
                              % (bus, slot, func))
            log.debug("pci: assign device %x:%x.%x" % (bus, slot, func))

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

        if dev.msix:
            for (start, size) in dev.msix_iomem:
                start_pfn = start>>PAGE_SHIFT
                nr_pfns = (size+(PAGE_SIZE-1))>>PAGE_SHIFT
                log.debug('pci-msix: remove permission for 0x%x/0x%x 0x%x/0x%x' % \
                         (start,size, start_pfn, nr_pfns))
                rc = xc.domain_iomem_permission(domid = fe_domid,
                                                first_pfn = start_pfn,
                                                nr_pfns = nr_pfns,
                                                allow_access = False)
                if rc<0:
                    raise VmError(('pci: failed to remove msi-x iomem'))

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
        pci_str_list = []
        pci_dev_list = []
        for pci_config in config.get('devs', []):
            domain = parse_hex(pci_config.get('domain', 0))
            bus = parse_hex(pci_config.get('bus', 0))
            slot = parse_hex(pci_config.get('slot', 0))
            func = parse_hex(pci_config.get('func', 0))            
            pci_str = '%04x:%02x:%02x.%01x' % (domain, bus, slot, func)
            pci_str_list = pci_str_list + [pci_str]
            pci_dev_list = pci_dev_list + [(domain, bus, slot, func)]

        if len(pci_str_list) != len(set(pci_str_list)):
            raise VmError('pci: duplicate devices specified in guest config?')

        for (domain, bus, slot, func) in pci_dev_list:
            try:
                dev = PciDevice(domain, bus, slot, func)
            except Exception, e:
                raise VmError("pci: failed to locate device and "+
                        "parse it's resources - "+str(e))
            if (dev.dev_type == DEV_TYPE_PCIe_ENDPOINT) and not dev.pcie_flr:
                if dev.bus == 0:
                    # We cope with this case by using the Dstate transition
                    # method or some vendor specific methods for now.
                    err_msg = 'pci: %s: it is on bus 0, but has no PCIe' +\
                        ' FLR Capability. Will try the Dstate transition'+\
                        ' method or some vendor specific methods if available.'
                    log.warn(err_msg % dev.name)
                else:
                    funcs = dev.find_all_the_multi_functions()
                    dev.devs_check_driver(funcs)
                    for f in funcs:
                        if not f in pci_str_list:
                            (f_dom, f_bus, f_slot, f_func) = parse_pci_name(f)
                            f_pci_str = '0x%x,0x%x,0x%x,0x%x' % \
                                (f_dom, f_bus, f_slot, f_func)
                            # f has been assigned to other guest?
                            if xc.test_assign_device(0, f_pci_str) != 0:
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
                    # All devices behind the uppermost PCI/PCI-X bridge must be\
                    # co-assigned to the same guest.
                    devs_str = dev.find_coassigned_pci_devices(True)
                    # Remove the element 0 which is a bridge
                    del devs_str[0]

                    dev.devs_check_driver(devs_str)
                    for s in devs_str:
                        if not s in pci_str_list:
                            (s_dom, s_bus, s_slot, s_func) = parse_pci_name(s)
                            s_pci_str = '0x%x,0x%x,0x%x,0x%x' % \
                                (s_dom, s_bus, s_slot, s_func)
                            # s has been assigned to other guest?
                            if xc.test_assign_device(0, s_pci_str) != 0:
                                err_msg = 'pci: %s must be co-assigned to the'+\
                                    ' same guest with %s'
                                raise VmError(err_msg % (s, dev.name))

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


    def cleanupOneDevice(self, domain, bus, slot, func):
        """ Detach I/O resources for device from frontend domain
        """
        fe_domid = self.getDomid()

        try:
            dev = PciDevice(domain, bus, slot, func)
        except Exception, e:
            raise VmError("pci: failed to locate device and "+
                    "parse it's resources - "+str(e))

        if dev.driver!='pciback':
            raise VmError(("pci: PCI Backend does not own device "+ \
                    "%s\n"+ \
                    "See the pciback.hide kernel "+ \
                    "command-line parameter or\n"+ \
                    "bind your slot/device to the PCI backend using sysfs" \
                    )%(dev.name))

        # Need to do FLR here before deassign device in order to terminate
        # DMA transaction, etc
        dev.do_FLR()

        pci_str = "0x%x, 0x%x, 0x%x, 0x%x" % (domain, bus, slot, func)
        bdf = xc.deassign_device(fe_domid, pci_str)
        if bdf > 0:
            raise VmError("Failed to deassign device from IOMMU (%x:%x.%x)"
                          % (bus, slot, func))
        log.debug("pci: Deassign device %x:%x.%x" % (bus, slot, func))

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
            state = int(self.readBackend(devid, 'state-%i' % i))
            if state == xenbusState['Closing']:
                # Detach I/O resources.
                dev = self.readBackend(devid, 'dev-%i' % i)
                (domain, bus, slotfunc) = dev.split(':')
                (slot, func) = slotfunc.split('.')
                domain = parse_hex(domain)
                bus = parse_hex(bus)
                slot = parse_hex(slot)
                func = parse_hex(func)            
                # In HVM case, I/O resources are disabled in ioemu.
                self.cleanupOneDevice(domain, bus, slot, func)
                # Remove xenstore nodes.
                self.removeBackend(devid, 'dev-%i' % i)
                self.removeBackend(devid, 'vdev-%i' % i)
                self.removeBackend(devid, 'state-%i' % i)
                self.removeBackend(devid, 'uuid-%i' % i)
                tmpopts = self.readBackend(devid, 'opts-%i' % i)
                if tmpopts is not None:
                    self.removeBackend(devid, 'opts-%i' % i)
            else:
                if new_num_devs != i:
                    tmpdev = self.readBackend(devid, 'dev-%i' % i)
                    self.writeBackend(devid, 'dev-%i' % new_num_devs, tmpdev)
                    self.removeBackend(devid, 'dev-%i' % i)
                    tmpvdev = self.readBackend(devid, 'vdev-%i' % i)
                    if tmpvdev is not None:
                        self.writeBackend(devid, 'vdev-%i' % new_num_devs,
                                          tmpvdev)
                    self.removeBackend(devid, 'vdev-%i' % i)
                    tmpstate = self.readBackend(devid, 'state-%i' % i)
                    self.writeBackend(devid, 'state-%i' % new_num_devs, tmpstate)
                    self.removeBackend(devid, 'state-%i' % i)
                    tmpuuid = self.readBackend(devid, 'uuid-%i' % i)
                    self.writeBackend(devid, 'uuid-%i' % new_num_devs, tmpuuid)
                    self.removeBackend(devid, 'uuid-%i' % i)
                    tmpopts = self.readBackend(devid, 'opts-%i' % i)
                    if tmpopts is not None:
                        self.removeBackend(devid, 'opts-%i' % i)
                new_num_devs = new_num_devs + 1

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
