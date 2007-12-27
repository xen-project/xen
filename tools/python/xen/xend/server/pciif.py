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

from xen.xend import sxp
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log

from xen.xend.server.DevController import DevController

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

class PciController(DevController):

    def __init__(self, vm):
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        def parse_hex(val):
            try:
                if isinstance(val, types.StringTypes):
                    return int(val, 16)
                else:
                    return val
            except ValueError:
                return None
            
        back = {}
        pcidevid = 0
        for pci_config in config.get('devs', []):
            domain = parse_hex(pci_config.get('domain', 0))
            bus = parse_hex(pci_config.get('bus', 0))
            slot = parse_hex(pci_config.get('slot', 0))
            func = parse_hex(pci_config.get('func', 0))            
            self.setupDevice(domain, bus, slot, func)
            back['dev-%i' % pcidevid] = "%04x:%02x:%02x.%02x" % \
                                        (domain, bus, slot, func)
            pcidevid += 1

        back['num_devs']=str(pcidevid)
        back['uuid'] = config.get('uuid','')
        return (0, back, {})

    def getDeviceConfiguration(self, devid, transaction = None):
        result = DevController.getDeviceConfiguration(self, devid, transaction)
        num_devs = self.readBackend(devid, 'num_devs')
        pci_devs = []
        
        for i in range(int(num_devs)):
            dev_config = self.readBackend(devid, 'dev-%d' % i)

            pci_match = re.match(r"((?P<domain>[0-9a-fA-F]{1,4})[:,])?" +
                                 r"(?P<bus>[0-9a-fA-F]{1,2})[:,]" + 
                                 r"(?P<slot>[0-9a-fA-F]{1,2})[.,]" + 
                                 r"(?P<func>[0-9a-fA-F]{1,2})", dev_config)
            
            if pci_match!=None:
                pci_dev_info = pci_match.groupdict()
                pci_devs.append({'domain': '0x%(domain)s' % pci_dev_info,
                                 'bus': '0x%(bus)s' % pci_dev_info,
                                 'slot': '0x%(slot)s' % pci_dev_info,
                                 'func': '0x%(func)s' % pci_dev_info})

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

    def setupDevice(self, domain, bus, slot, func):
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

        if dev.irq>0:
            log.debug('pci: enabling irq %d'%dev.irq)
            rc = xc.domain_irq_permission(domid =  fe_domid, pirq = dev.irq,
                    allow_access = True)
            if rc<0:
                raise VmError(('pci: failed to configure irq on device '+
                            '%s - errno=%d')%(dev.name,rc))

    def waitForBackend(self,devid):
        return (0, "ok - no hotplug")

    def migrate(self, config, network, dst, step, domName):
        raise XendError('Migration not permitted with assigned PCI device.')
