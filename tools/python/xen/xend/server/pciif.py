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

from xen.xend.xenstore.xstransact import xstransact

from xen.xend.server.DevController import DevController

import xen.lowlevel.xc

from xen.util.pci import PciDevice
import resource

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
        #log.debug('pci config='+sxp.to_string(config))

        def get_param(config, field, default=None):
            try:
                val = sxp.child_value(config, field)

                if not val:
                    if default==None:
                        raise VmError('pci: Missing %s config setting' % field)
                    else:
                        return default

                if isinstance(val, types.StringType):
                    return int(val, 16)
                else:
                    return val
            except:
                if default==None:
                    raise VmError('pci: Invalid config setting %s: %s' %
                              (field, val))
                else:
                    return default
        
        back = {}

        val = sxp.child_value(config, 'dev')
        if isinstance(val, list):
            pcidevid = 0
            for dev_config in sxp.children(config, 'dev'):
                domain = get_param(dev_config, 'domain', 0)
                bus = get_param(dev_config,'bus')
                slot = get_param(dev_config,'slot')
                func = get_param(dev_config,'func')

                self.setupDevice(domain, bus, slot, func)

                back['dev-%i'%(pcidevid)]="%04x:%02x:%02x.%02x"% \
                        (domain, bus, slot, func)
                pcidevid+=1
            
            back['num_devs']=str(pcidevid)

        else:
            # Xen 2.0 configuration compatibility
            domain = get_param(dev_config, 'domain', 0)
            bus  = get_param(config, 'bus')
            slot = get_param(config, 'dev')
            func = get_param(config, 'func')

            self.setupDevice(domain, bus, slot, func)

            back['dev-0']="%04x:%02x:%02x.%02x"%(domain, bus, slot, func)
            back['num_devs']=str(1)

        return (0, back, {})

    def setupDevice(self, domain, bus, slot, func):
        """ Attach I/O resources for device to frontend domain
        """
        fe_domid = self.getDomid()

        try:
            dev = PciDevice(domain, bus, slot, func)
        except Exception, e:
            raise VmError("pci: failed to locate device and "+
                    "parse it's resources - %s"+str(e))

        if dev.driver!='pciback':
            raise VmError(("pci: PCI Backend does not own device "+ \
                    "%s\n"+ \
                    "See the pciback.hide kernel "+ \
                    "command-line parameter or\n"+ \
                    "bind your slot/device to the PCI backend using sysfs" \
                    )%(dev.name))

        for (start, size) in dev.ioports:
            log.debug('pci: enabling ioport 0x%x/0x%x'%(start,size))
            rc = xc.domain_ioport_permission(dom = fe_domid, first_port = start,
                    nr_ports = size, allow_access = True)
            if rc<0:
                raise VmError(('pci: failed to configure I/O ports on device '+
                            '%s - errno=%d')&(dev.name,rc))
            
        for (start, size) in dev.iomem:
            # Convert start/size from bytes to page frame sizes
            start_pfn = start>>PAGE_SHIFT
            # Round number of pages up to nearest page boundary (if not on one)
            nr_pfns = (size+(PAGE_SIZE-1))>>PAGE_SHIFT

            log.debug('pci: enabling iomem 0x%x/0x%x pfn 0x%x/0x%x'% \
                    (start,size,start_pfn,nr_pfns))
            rc = xc.domain_iomem_permission(dom = fe_domid,
                    first_pfn = start_pfn,
                    nr_pfns = nr_pfns,
                    allow_access = True)
            if rc<0:
                raise VmError(('pci: failed to configure I/O memory on device '+
                            '%s - errno=%d')&(dev.name,rc))

        if dev.irq>0:
            log.debug('pci: enabling irq %d'%dev.irq)
            rc = xc.domain_irq_permission(dom = fe_domid, pirq = dev.irq,
                    allow_access = True)
            if rc<0:
                raise VmError(('pci: failed to configure irq on device '+
                            '%s - errno=%d')&(dev.name,rc))

    def waitForBackend(self,devid):
        return (0, "ok - no hotplug")
