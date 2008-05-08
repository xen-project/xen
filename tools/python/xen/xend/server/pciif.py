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
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log

from xen.xend.server.DevController import DevController, xenbusState

import xen.lowlevel.xc

from xen.util.pci import PciDevice
import resource
import re

from xen.xend.server.pciquirk import *

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
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        back = {}
        pcidevid = 0
        vslots = ""
        for pci_config in config.get('devs', []):
            domain = parse_hex(pci_config.get('domain', 0))
            bus = parse_hex(pci_config.get('bus', 0))
            slot = parse_hex(pci_config.get('slot', 0))
            func = parse_hex(pci_config.get('func', 0))            

            vslt = pci_config.get('vslt')
            if vslt is not None:
                vslots = vslots + vslt + ";"

            back['dev-%i' % pcidevid] = "%04x:%02x:%02x.%02x" % \
                                        (domain, bus, slot, func)
            pcidevid += 1

        if vslots != "":
            back['vslots'] = vslots

        back['num_devs']=str(pcidevid)
        back['uuid'] = config.get('uuid','')
        return (0, back, {})


    def reconfigureDevice(self, _, config):
        """@see DevController.reconfigureDevice"""
        (devid, back, front) = self.getDeviceDetails(config)
        num_devs = int(back['num_devs'])
        states = config.get('states', [])

        old_vslots = self.readBackend(devid, 'vslots')
        if old_vslots is None:
            old_vslots = ''
        num_olddevs = int(self.readBackend(devid, 'num_devs'))

        for i in range(num_devs):
            try:
                dev = back['dev-%i' % i]
                state = states[i]
            except:
                raise XendError('Error reading config')

            if state == 'Initialising':
                # PCI device attachment
                for j in range(num_olddevs):
                    if dev == self.readBackend(devid, 'dev-%i' % j):
                        raise XendError('Device %s is already connected.' % dev)
                log.debug('Attaching PCI device %s.' % dev)
                (domain, bus, slotfunc) = dev.split(':')
                (slot, func) = slotfunc.split('.')
                domain = parse_hex(domain)
                bus = parse_hex(bus)
                slot = parse_hex(slot)
                func = parse_hex(func)
                self.setupOneDevice(domain, bus, slot, func)

                self.writeBackend(devid, 'dev-%i' % (num_olddevs + i), dev)
                self.writeBackend(devid, 'state-%i' % (num_olddevs + i),
                                  str(xenbusState['Initialising']))
                self.writeBackend(devid, 'num_devs', str(num_olddevs + i + 1))

                # Update vslots
                if back['vslots'] is not None:
                    vslots = old_vslots + back['vslots']
                    self.writeBackend(devid, 'vslots', vslots)

            elif state == 'Closing':
                # PCI device detachment
                found = False
                for j in range(num_olddevs):
                    if dev == self.readBackend(devid, 'dev-%i' % j):
                        found = True
                        log.debug('Detaching device %s' % dev)
                        self.writeBackend(devid, 'state-%i' % j,
                                          str(xenbusState['Closing']))
                if not found:
                    raise XendError('Device %s is not connected' % dev)

                # Update vslots
                if back['vslots'] is not None:
                    vslots = old_vslots
                    for vslt in back['vslots'].split(';'):
                        if vslt != '':
                            vslots = vslots.replace(vslt + ';', '', 1)
                    if vslots == '':
                        self.removeBackend(devid, 'vslots')
                    else:
                        self.writeBackend(devid, 'vslots', vslots)

            else:
                raise XendError('Error configuring device %s: invalid state %s'
                                % (dev,state))

        self.writeBackend(devid, 'state', str(xenbusState['Reconfiguring']))

        return self.readBackend(devid, 'uuid')


    def getDeviceConfiguration(self, devid, transaction = None):
        result = DevController.getDeviceConfiguration(self, devid, transaction)
        num_devs = self.readBackend(devid, 'num_devs')
        pci_devs = []
        
        vslots = self.readBackend(devid, 'vslots')
        if vslots is not None:
            if vslots[-1] == ";":
                vslots = vslots[:-1]
            slot_list = vslots.split(';')

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

                #append vslot info
                if vslots is not None:
                    try:
                        dev_dict['vslt'] = slot_list[i]
                    except IndexError:
                        dev_dict['vslt'] = '0x0'

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
            for dev_item in dev.items():
                dev_sxpr.append(list(dev_item))
            sxpr.append(dev_sxpr)
        
        for key, val in configDict.items():
            if type(val) == type(list()):
                for v in val:
                    sxpr.append([key, v])
            else:
                sxpr.append([key, val])

        return sxpr    

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

        PCIQuirk(dev.vendor, dev.device, dev.subvendor, dev.subdevice, domain, 
                bus, slot, func)

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
            rc = xc.physdev_map_pirq(domid = fe_domid,
                                   index = dev.irq,
                                   pirq  = dev.irq)
            if rc < 0:
                raise VmError(('pci: failed to map irq on device '+
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
        for pci_config in config.get('devs', []):
            domain = parse_hex(pci_config.get('domain', 0))
            bus = parse_hex(pci_config.get('bus', 0))
            slot = parse_hex(pci_config.get('slot', 0))
            func = parse_hex(pci_config.get('func', 0))            
            self.setupOneDevice(domain, bus, slot, func)

        return

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
                new_num_devs = new_num_devs + 1

        self.writeBackend(devid, 'num_devs', str(new_num_devs))

        return new_num_devs

    def waitForBackend(self,devid):
        return (0, "ok - no hotplug")

    def migrate(self, config, network, dst, step, domName):
        raise XendError('Migration not permitted with assigned PCI device.')
