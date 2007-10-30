from xen.xend.server.DevController import DevController
from xen.xend.XendLogging import log

from xen.xend.XendError import VmError

class ConsoleController(DevController):
    """A dummy controller for us to represent serial and vnc
    console devices with persistent UUIDs.
    """

    valid_cfg = ['location', 'uuid', 'protocol']

    def __init__(self, vm):
        DevController.__init__(self, vm)
        self.hotplug = False

    def getDeviceDetails(self, config):
        back = dict([(k, config[k]) for k in self.valid_cfg if k in config])
        return (self.allocateDeviceID(), back, {})


    def getDeviceConfiguration(self, devid, transaction = None):
        result = DevController.getDeviceConfiguration(self, devid, transaction)
        if transaction is None:
            devinfo = self.readBackend(devid, *self.valid_cfg)
        else:
            devinfo = self.readBackendTxn(transaction, devid, *self.valid_cfg)
        config = dict(zip(self.valid_cfg, devinfo))
        config = dict([(key, val) for key, val in config.items()
                       if val != None])
        return config

    def migrate(self, deviceConfig, network, dst, step, domName):
        return 0

    def destroyDevice(self, devid, force):
        DevController.destroyDevice(self, devid, True)
        
