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
# Copyright (C) 2006 XenSource Ltd
#============================================================================

#
# A collection of DevControllers 
#

from xen.xend.server import blkif, netif, tpmif, pciif, iopif, irqif, vfbif, vscsiif, netif2, vusbif
from xen.xend.server.BlktapController import BlktapController, Blktap2Controller
from xen.xend.server.ConsoleController import ConsoleController


class XendDevices:
    """ An ugly halfway point between the module local device name
    to class map we used to have in XendDomainInfo and something
    slightly more managable.

    This class should contain all the functions that have to do
    with managing devices in Xend. Right now it is only a factory
    function.
    """

    controllers = {
        'vbd': blkif.BlkifController,
        'vif': netif.NetifController,
        'vif2': netif2.NetifController2,
        'vtpm': tpmif.TPMifController,
        'pci': pciif.PciController,
        'ioports': iopif.IOPortsController,
        'irq': irqif.IRQController,
        'tap': BlktapController,
        'tap2': Blktap2Controller,
        'vfb': vfbif.VfbifController,
        'vkbd': vfbif.VkbdifController,
        'console': ConsoleController,
        'vscsi': vscsiif.VSCSIController,
        'vusb': vusbif.VUSBController,
    }

    #@classmethod
    def valid_devices(cls):
        return cls.controllers.keys()
    valid_devices = classmethod(valid_devices)

    #@classmethod
    def make_controller(cls, name, domain):
        """Factory function to make device controllers per domain.

        @param name: device class name in L{VALID_DEVICES}
        @type name: String
        @param domain: domain this controller is handling devices for.
        @type domain: XendDomainInfo
        @return: DevController of class 'name' or None
        @rtype: subclass of DevController
        """
        if name in cls.controllers.keys():
            cls.controllers[name].deviceClass = name
            return cls.controllers[name](domain)
        return None

    make_controller = classmethod(make_controller)

    def destroy_device_state(cls, domain):
        """Destroy the state of (external) devices. This is necessary
           to do when a VM's configuration is destroyed.
        
        @param domain: domain this controller is handling devices for.
        @type domain: XendDomainInfo
        """
        from xen.xend.XendLogging import log
        tpmif.destroy_vtpmstate(domain.info.get('vtpm_refs'))

    destroy_device_state = classmethod(destroy_device_state)
