import types

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()

from xen.xend import sxp
from xen.xend.XendError import VmError

from controller import Dev, DevController

def parse_pci(val):
    """Parse a pci field.
    """
    if isinstance(val, types.StringType):
        radix = 10
        if val.startswith('0x') or val.startswith('0X'):
            radix = 16
        v = int(val, radix)
    else:
        v = val
    return v

class PciDev(Dev):

    def __init__(self, controller, id, config, recreate=False):
        Dev.__init__(self, controller, id, config, recreate=recreate)
        bus = sxp.child_value(self.config, 'bus')
        if not bus:
            raise VmError('pci: Missing bus')
        dev = sxp.child_value(self.config, 'dev')
        if not dev:
            raise VmError('pci: Missing dev')
        func = sxp.child_value(self.config, 'func')
        if not func:
            raise VmError('pci: Missing func')
        try:
            bus = parse_pci(bus)
            dev = parse_pci(dev)
            func = parse_pci(func)
        except:
            raise VmError('pci: invalid parameter')

    def attach(self, recreate=False, change=False):
        rc = xc.physdev_pci_access_modify(dom    = self.getDomain(),
                                          bus    = bus,
                                          dev    = dev,
                                          func   = func,
                                          enable = True)
        if rc < 0:
            #todo non-fatal
            raise VmError('pci: Failed to configure device: bus=%s dev=%s func=%s' %
                          (bus, dev, func))

    def destroy(self, change=False, reboot=False):
        pass

class PciController(DevController):

    def newDevice(self, id, config, recreate=False):
        return PciDev(self, id, config, recreate=recreate)
