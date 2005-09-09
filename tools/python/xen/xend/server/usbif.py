# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2004 Intel Research Cambridge
# Copyright (C) 2004 Mark Williamson <mark.williamson@cl.cam.ac.uk>
"""Support for virtual USB hubs.
"""

from xen.xend import sxp
from xen.xend.XendLogging import log
from xen.xend.XendError import XendError
from xen.xend.xenstore import DBVar

from xen.xend.server.controller import Dev, DevController

class UsbBackend:
    """Handler for the 'back-end' channel to a USB device driver domain
    on behalf of a front-end domain.
    """
    def __init__(self, controller, id, dom):
        self.controller = controller
        self.id = id
        self.destroyed = False
        self.connected = False
        self.connecting = False
        self.frontendDomain = self.controller.getDomain()
        self.backendDomain = dom

    def init(self, recreate=False, reboot=False):
        pass
    
    def __str__(self):
        return ('<UsbifBackend frontend=%d backend=%d id=%d>'
                % (self.frontendDomain,
                   self.backendDomain,
                   self.id))

    def connect(self, recreate=False):
        """Connect the controller to the usbif control interface.

        @param recreate: true if after xend restart
        """
        log.debug("Connecting usbif %s", str(self))
        if recreate or self.connected or self.connecting:
            pass
        
    def destroy(self, reboot=False):
        """Disconnect from the usbif control interface and destroy it.
        """
        self.destroyed = True
        
    def interfaceChanged(self):
        pass


class UsbDev(Dev):

    __exports__ = Dev.__exports__ + [
        DBVar('port', ty='int'),
        DBVar('path', ty='str'),
        ]
    
    def __init__(self, controller, id, config, recreate=False):
        Dev.__init__(self, controller, id, config, recreate=recreate)
        self.port = id
        self.path = None
        self.frontendDomain = self.getDomain()
        self.backendDomain = 0
        self.configure(self.config, recreate=recreate)

    def init(self, recreate=False, reboot=False):
        self.destroyed = False
        self.frontendDomain = self.getDomain()
        
    def configure(self, config, change=False, recreate=False):
        if change:
            raise XendError("cannot reconfigure usb")
        #todo: FIXME: Use sxp access methods to get this value.
        # Must not use direct indexing.
        self.path = config[1][1]
        
        #todo: FIXME: Support configuring the backend domain.
##         try:
##             self.backendDomain = int(sxp.child_value(config, 'backend', '0'))
##         except:
##             raise XendError('invalid backend domain')

    def attach(self, recreate=False, change=False):
        if recreate:
            pass
        else:
            self.attachBackend()
        if change:
            self.interfaceChanged()
            
    def sxpr(self):
        val = ['usb',
               ['id', self.id],
               ['port', self.port],
               ['path', self.path],
               ]
        return val

    def getBackend(self):
        return self.controller.getBackend(self.backendDomain)

    def destroy(self, change=False, reboot=False):
        """Destroy the device. If 'change' is true notify the front-end interface.

        @param change: change flag
        """
        self.destroyed = True
        log.debug("Destroying usb domain=%d id=%s", self.frontendDomain, self.id)
        if change:
            self.interfaceChanged()

    def interfaceChanged(self):
        """Tell the back-end to notify the front-end that a device has been
        added or removed.
        """
        self.getBackend().interfaceChanged()

    def attachBackend(self):
        """Attach the device to its controller.

        """
        self.getBackend().connect()

class UsbifController(DevController):
    """USB device interface controller. Handles all USB devices
    for a domain.
    """
    
    def __init__(self, vm, recreate=False):
        """Create a USB device controller.
        """
        DevController.__init__(self, vm, recreate=recreate)
        self.backends = {}
        self.backendId = 0

    def init(self, recreate=False, reboot=False):
        self.destroyed = False
        if reboot:
            self.rebootBackends()
            self.rebootDevices()

    def sxpr(self):
        val = ['usbif',
               ['dom', self.getDomain()]]
        return val

    def newDevice(self, id, config, recreate=False):
        return UsbDev(self, id, config, recreate=recreate)

    def destroyController(self, reboot=False):
        """Destroy the controller and all devices.
        """
        self.destroyed = True
        log.debug("Destroying blkif domain=%d", self.getDomain())
        self.destroyDevices(reboot=reboot)
        self.destroyBackends(reboot=reboot)

    def rebootBackends(self):
        for backend in self.backends.values():
            backend.init(reboot=True)

    def getBackendById(self, id):
        return self.backends.get(id)

    def getBackendByDomain(self, dom):
        for backend in self.backends.values():
            if backend.backendDomain == dom:
                return backend
        return None

    def getBackend(self, dom):
        backend = self.getBackendByDomain(dom)
        if backend: return backend
        backend = UsbBackend(self, self.backendId, dom)
        self.backendId += 1
        self.backends[backend.getId()] = backend
        backend.init()
        return backend
    
    def destroyBackends(self, reboot=False):
        for backend in self.backends.values():
            backend.destroy(reboot=reboot)
