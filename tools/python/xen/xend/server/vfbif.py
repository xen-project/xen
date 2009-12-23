from xen.xend.server.DevController import DevController
from xen.xend.XendLogging import log

from xen.xend.XendError import VmError
import xen.xend
import os

CONFIG_ENTRIES = ['type', 'vncdisplay', 'vnclisten', 'vncpasswd', 'vncunused',
                  'display', 'xauthority', 'keymap', 'vnc', 'sdl', 'uuid',
                  'location', 'protocol', 'opengl']

class VfbifController(DevController):
    """Virtual frame buffer controller. Handles all vfb devices for a domain.
    Note that we only support a single vfb per domain at the moment.
    """

    def __init__(self, vm):
        DevController.__init__(self, vm)
        
    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        back = dict([(k, str(config[k])) for k in CONFIG_ENTRIES
                     if config.has_key(k)])

        devid = 0
        return (devid, back, {})


    def getDeviceConfiguration(self, devid, transaction = None):
        result = DevController.getDeviceConfiguration(self, devid, transaction)

        if transaction is None:
            devinfo = self.readBackend(devid, *CONFIG_ENTRIES)
        else:
            devinfo = self.readBackendTxn(transaction, devid, *CONFIG_ENTRIES)
        return dict([(CONFIG_ENTRIES[i], devinfo[i])
                     for i in range(len(CONFIG_ENTRIES))
                     if devinfo[i] is not None])

    def waitForDevice(self, devid):
        # is a qemu-dm managed device, don't wait for hotplug for these.
        return

    def reconfigureDevice(self, _, config):
        """ Only allow appending location information of vnc port into
        xenstore."""

        if 'location' in config:
            (devid, back, front) = self.getDeviceDetails(config)
            self.writeBackend(devid, 'location', config['location'])
            return back.get('uuid')

        raise VmError('Refusing to reconfigure device vfb:%d' % devid)

    def destroyDevice(self, devid, force):
        # remove the backend xenstore entries no matter what
        # because we kill qemu-dm with extreme prejudice
        # not giving it a chance to remove them itself
        DevController.destroyDevice(self, devid, True)


    def migrate(self, deviceConfig, network, dst, step, domName):
        # Handled by qemu-dm so no action needed
        return 0

    
class VkbdifController(DevController):
    """Virtual keyboard controller. Handles all vkbd devices for a domain.
    """

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        devid = 0
        back = {}
        front = {}
        return (devid, back, front)

    def waitForDevice(self, config):
        # is a qemu-dm managed device, don't wait for hotplug for these.
        return

    def destroyDevice(self, devid, force):
        # remove the backend xenstore entries no matter what
        # because we kill qemu-dm with extreme prejudice
        # not giving it a chance to remove them itself
        DevController.destroyDevice(self, devid, True)

    def migrate(self, deviceConfig, network, dst, step, domName):
        # Handled by qemu-dm so no action needed
        return 0
