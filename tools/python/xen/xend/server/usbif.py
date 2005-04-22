# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2004 Intel Research Cambridge
# Copyright (C) 2004 Mark Williamson <mark.williamson@cl.cam.ac.uk>
"""Support for virtual USB hubs.
"""

from xen.xend import sxp
from xen.xend.XendLogging import log
from xen.xend.XendError import XendError

import channel
from controller import Dev, DevController
from messages import *

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
        self.frontendChannel = None
        self.backendChannel = None

    def init(self, recreate=False, reboot=False):
        self.frontendChannel = self.controller.getChannel()
        cf = channel.channelFactory()
        self.backendChannel = cf.openChannel(self.backendDomain)

    def __str__(self):
        return ('<UsbifBackend frontend=%d backend=%d id=%d>'
                % (self.frontendDomain,
                   self.backendDomain,
                   self.id))

    def closeEvtchn(self):
        if self.evtchn:
            channel.eventChannelClose(self.evtchn)
            self.evtchn = None

    def openEvtchn(self):
        self.evtchn = channel.eventChannel(self.backendDomain, self.frontendDomain)
        
    def getEventChannelBackend(self):
        val = 0
        if self.evtchn:
            val = self.evtchn['port1']
        return val

    def getEventChannelFrontend(self):
        val = 0
        if self.evtchn:
            val = self.evtchn['port2']
        return val

    def connect(self, recreate=False):
        """Connect the controller to the usbif control interface.

        @param recreate: true if after xend restart
        """
        log.debug("Connecting usbif %s", str(self))
        if recreate or self.connected or self.connecting:
            pass
        else:
            self.send_be_create()
        
    def send_be_create(self):
        msg = packMsg('usbif_be_create_t',
                      { 'domid'        : self.frontendDomain })
        msg = self.backendChannel.requestResponse(msg)
        val = unpackMsg('usbif_be_create_t', msg)
        log.debug('>UsbifBackendController>respond_be_create> %s', str(val))
        self.connected = True
    
    def destroy(self, reboot=False):
        """Disconnect from the usbif control interface and destroy it.
        """
        self.destroyed = True
        self.send_be_disconnect()
        self.send_be_destroy()
        self.closeEvtchn()
        
    def send_be_disconnect(self):
        log.debug('>UsbifBackendController>send_be_disconnect> %s', str(self))
        msg = packMsg('usbif_be_disconnect_t',
                      { 'domid'        : self.frontendDomain })
        self.backendChannel.writeRequest(msg)

    def send_be_destroy(self, response=None):
        log.debug('>UsbifBackendController>send_be_destroy> %s', str(self))
        msg = packMsg('usbif_be_destroy_t',
                      { 'domid'        : self.frontendDomain })
        self.backendChannel.writeRequest(msg, response=response)

    
    def connectInterface(self, val):
        self.openEvtchn()
        log.debug(">UsbifBackendController>connectInterface> connecting usbif to event channel %s ports=%d:%d",
                  str(self),
                  self.getEventChannelBackend(),
                  self.getEventChannelFrontend())
        msg = packMsg('usbif_be_connect_t',
                      { 'domid'        : self.frontendDomain,
                        'evtchn'       : self.getEventChannelBackend(),
                        'shmem_frame'  : val['shmem_frame'],
                        'bandwidth'    : 500 # XXX fix bandwidth!
                        })
        msg = self.backendChannel.requestResponse(msg)
        self.respond_be_connect(msg)

    def respond_be_connect(self, msg):
        """Response handler for a be_connect message.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('usbif_be_connect_t', msg)
        log.debug('>UsbifBackendController>respond_be_connect> %s, %s', str(self), str(val))
        self.send_fe_interface_status_changed()
        log.debug(">UsbifBackendController> Successfully connected USB interface for domain %d" % self.frontendDomain)
        self.controller.claim_ports()
            
    def send_fe_interface_status_changed(self):
        msg = packMsg('usbif_fe_interface_status_changed_t',
                      { 'status'    : USBIF_INTERFACE_STATUS_CONNECTED,
                        'domid'     : self.backendDomain,
                        'evtchn'    : self.getEventChannelFrontend(),
                        'bandwidth' : 500,
                        'num_ports' : len(self.controller.devices)
                        })
        self.frontendChannel.writeRequest(msg)

    def interfaceChanged(self):
        self.send_fe_interface_status_changed()


class UsbDev(Dev):
    
    def __init__(self, controller, id, config, recreate=False):
        Dev.__init__(self, controller, id, config, recreate=recreate)
        self.port = id
        self.path = None
        self.frontendDomain = self.getDomain()
        self.frontendChannel = None
        self.backendDomain = 0
        self.backendChannel = None
        self.configure(self.config, recreate=recreate)

    def init(self, recreate=False, reboot=False):
        self.destroyed = False
        self.frontendDomain = self.getDomain()
        self.frontendChannel = self.getChannel()
        backend = self.getBackend()
        self.backendChannel = backend.backendChannel
        
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
        val.append(['index', self.getIndex()])
        return val

    def getBackend(self):
        return self.controller.getBackend(self.backendDomain)

    def destroy(self, change=False, reboot=False):
        """Destroy the device. If 'change' is true notify the front-end interface.

        @param change: change flag
        """
        self.destroyed = True
        log.debug("Destroying usb domain=%d id=%s", self.frontendDomain, self.id)
        self.send_be_release_port()
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

    def send_be_claim_port(self):
        log.debug(">UsbifBackendController>send_be_claim_port> about to claim port %s" % self.path)
        msg = packMsg('usbif_be_claim_port_t',
                      { 'domid'        : self.frontendDomain,
                        'path'         : self.path,
                        'usbif_port'   : self.port,
                        'status'       : 0})
        self.backendChannel.writeRequest(msg)
        log.debug(">UsbifBackendController> Claim port completed")
        # No need to add any callbacks, since the guest polls its virtual ports
        # anyhow, somewhat like a UHCI controller ;-)

    def send_be_release_port(self):
        msg = packMsg('usbif_be_release_port_t',
                      { 'domid'        : self.frontendDomain,
                        'path'         : self.path })
        self.backendChannel.writeRequest(msg)        
        log.debug(">UsbifBackendController> Release port completed")
        # No need to add any callbacks, since the guest polls its virtual ports
        # anyhow, somewhat like a UHCI controller ;-)

class UsbifController(DevController):
    """USB device interface controller. Handles all USB devices
    for a domain.
    """
    
    def __init__(self, dctype, vm, recreate=False):
        """Create a USB device controller.
        """
        DevController.__init__(self, dctype, vm, recreate=recreate)
        self.backends = {}
        self.backendId = 0
        self.rcvr = None

    def init(self, recreate=False, reboot=False):
        self.destroyed = False
        self.rcvr = CtrlMsgRcvr(self.getChannel())
        self.rcvr.addHandler(CMSG_USBIF_FE,
                             CMSG_USBIF_FE_DRIVER_STATUS_CHANGED,
                             self.recv_fe_driver_status_changed)
        self.rcvr.addHandler(CMSG_USBIF_FE,
                             CMSG_USBIF_FE_INTERFACE_CONNECT,
                             self.recv_fe_interface_connect)
        self.rcvr.registerChannel()
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
        if self.rcvr:
            self.rcvr.deregisterChannel()

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

    def recv_fe_driver_status_changed(self, msg):
        val = unpackMsg('usbif_fe_driver_status_changed_t', msg)
        log.debug('>UsbifController>recv_fe_driver_status_changed> %s', str(val))
        #todo: FIXME: For each backend?
        msg = packMsg('usbif_fe_interface_status_changed_t',
                      { 'status' : USBIF_INTERFACE_STATUS_DISCONNECTED,
                        'domid'  : 0, #todo: FIXME: should be domid of backend
                        'evtchn' : 0 })
        msg = self.getChannel().requestResponse(msg)
        self.disconnected_resp(msg)

    def disconnected_resp(self, msg):
        val = unpackMsg('usbif_fe_interface_status_changed_t', msg)
        if val['status'] != USBIF_INTERFACE_STATUS_DISCONNECTED:
            log.error(">UsbifController>disconnected_resp> unexpected status change")
        else:
            log.debug(">UsbifController>disconnected_resp> interface disconnected OK")

    def recv_fe_interface_connect(self, msg):
        val = unpackMsg('usbif_fe_interface_status_changed_t', msg)
        log.debug(">UsbifController>recv_fe_interface_connect> notifying backend")
        #todo: FIXME: generalise to more than one backend.
        id = 0
        backend = self.getBackendById(id)
        if backend:
            try:
                backend.connectInterface(val)
            except IOError, ex:
                log.error("Exception connecting backend: %s", ex)
        else:
            log.error('interface connect on unknown interface: id=%d', id)

    def claim_ports(self):
        for dev in self.devices.values():
            dev.send_be_claim_port()

