# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2004 Intel Research Cambridge
# Copyright (C) 2004 Mark Williamson <mark.williamson@cl.cam.ac.uk>
"""Support for virtual USB hubs.
"""

from twisted.internet import defer
#defer.Deferred.debug = 1

from xen.xend import sxp
from xen.xend.XendLogging import log
from xen.xend.XendError import XendError

import channel
import controller
from messages import *

class UsbifBackendController(controller.BackendController):
    """ Handler for the 'back-end' channel to a USB hub domain.
    Must be connected using connect() before it can be used.
    Do not create directly - use getBackend() on the UsbifController.
    """

    def __init__(self, ctrl, dom):
        controller.BackendController.__init__(self, ctrl, dom)
        self.connected = 0
        self.evtchn = None
        self.addMethod(CMSG_USBIF_BE,
                       CMSG_USBIF_BE_DRIVER_STATUS_CHANGED,
                       self.recv_be_driver_status_changed)
        self.registerChannel()

    def __str__(self):
        return '<UsbifBackendController %d>' % (self.dom)

    def recv_be_driver_status_changed(self, msg, req):
        """Request handler for be_driver_status_changed messages.
        
        @param msg: message
        @type  msg: xu message
        @param req: request flag (true if the msg is a request)
        @type  req: bool
        """
        val = unpackMsg('usbif_be_driver_status_changed_t', msg)
        status = val['status']

class UsbifBackendInterface(controller.BackendInterface):
    """Handler for the 'back-end' channel to a network device driver domain
    on behalf of a front-end domain.

    Each network device is handled separately, so we add no functionality
    here.
    """
    def __init__(self, ctrl, dom):
        controller.BackendInterface.__init__(self, ctrl, dom, 0)
        self.connected = 0
        self.connecting = False

    def connect(self, recreate=0):
        """Connect the controller to the usbif control interface.

        @param recreate: true if after xend restart
        @return: deferred
        """
        log.debug("Connecting usbif %s", str(self))
        if recreate or self.connected or self.connecting:
            d = defer.succeed(self)
        else:
            self.connecting = True
            d = self.send_be_create()
            d.addCallback(self.respond_be_create)
        return d
        
    def send_be_create(self):
        d = defer.Deferred()
        msg = packMsg('usbif_be_create_t',
                      { 'domid'        : self.controller.dom })
        self.writeRequest(msg, response=d)
        return d

    def respond_be_create(self, msg):
        val = unpackMsg('usbif_be_create_t', msg)
        log.debug('>UsbifBackendController>respond_be_create> %s', str(val))
        self.connected = True
        return self
    
    def destroy(self):
        """Disconnect from the usbif control interface and destroy it.
        """
        def cb_destroy(val):
            self.send_be_destroy()
        d = defer.Deferred()
        d.addCallback(cb_destroy)
        self.send_be_disconnect(response=d)
        
    def send_be_disconnect(self, response=None):
        log.debug('>UsbifBackendController>send_be_disconnect> %s', str(self))
        msg = packMsg('usbif_be_disconnect_t',
                      { 'domid'        : self.controller.dom })
        self.writeRequest(msg, response=response)

    def send_be_destroy(self, response=None):
        log.debug('>UsbifBackendController>send_be_destroy> %s', str(self))
        msg = packMsg('usbif_be_destroy_t',
                      { 'domid'        : self.controller.dom })
        self.writeRequest(msg, response=response)

    def send_be_claim_port(self, path):
        d=defer.Deferred()
        log.debug(">UsbifBackendController>send_be_claim_port> about to claim port %s" % path)
        def cb(blah): log.debug(">UsbifBackendController> Claim port completed")
        d.addCallback(cb)
        msg = packMsg('usbif_be_claim_port_t',
                      { 'domid'        : self.controller.dom,
                        'path'         : path,
                        'usbif_port'   : self.controller.devices[path],
                        'status'       : 0})
        self.writeRequest(msg, response=d)
        # No need to add any callbacks, since the guest polls its virtual ports
        # anyhow, somewhat like a UHCI controller ;-)
        return d

    def send_be_release_port(self, path):
        d=defer.Deferred()
        def cb(blah): log.debug(">UsbifBackendController> Release port completed")
        d.addCallback(cb)
        msg = packMsg('usbif_be_release_port_t',
                      { 'domid'        : self.controller.dom,
                        'path'         : path })
        self.writeRequest(msg, response)        
        # No need to add any callbacks, since the guest polls its virtual ports
        # anyhow, somewhat like a UHCI controller ;-)
    
    def connectInterface(self, val):
        self.evtchn = channel.eventChannel(0, self.controller.dom)
        log.debug(">UsbifBackendController>connectInterface> connecting usbif to event channel %s ports=%d:%d",
                  str(self), self.evtchn['port1'], self.evtchn['port2'])
        msg = packMsg('usbif_be_connect_t',
                      { 'domid'        : self.controller.dom,
                        'evtchn'       : self.evtchn['port1'],
                        'shmem_frame'  : val['shmem_frame'],
                        'bandwidth'    : 500 # XXX fix bandwidth!
                        })
        d = defer.Deferred()
        d.addCallback(self.respond_be_connect)
        self.writeRequest(msg, response=d)

    def respond_be_connect(self, msg):
        """Response handler for a be_connect message.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('usbif_be_connect_t', msg)
        log.debug('>UsbifBackendController>respond_be_connect> %s, %s', str(self), str(val))
        d = defer.Deferred()
        def cb(blah):
            log.debug(">UsbifBackendController> Successfully connected USB interface for domain %d" % self.controller.dom)
            self.controller.claim_ports()
        d.addCallback(cb)
        self.send_fe_interface_status_changed(d)
            
    def send_fe_interface_status_changed(self, response=None):
        msg = packMsg('usbif_fe_interface_status_changed_t',
                      { 'status' : USBIF_INTERFACE_STATUS_CONNECTED,
                        'domid'  : 0, ## FIXME: should be domid of backend
                        'evtchn' : self.evtchn['port2'],
                        'bandwidth' : 500,
                        'num_ports'    : len(self.controller.devices.keys())})
        self.controller.writeRequest(msg, response=response)

        
class UsbifControllerFactory(controller.SplitControllerFactory):
    """Factory for creating USB interface controllers.
    """

    def __init__(self):
        controller.ControllerFactory.__init__(self)
        self.backendControllers = {}

    def createController(self, dom, recreate=0):
        """Create a USB device controller for a domain.

        @param dom: domain
        @type  dom: int
        @param recreate: if true it's a recreate (after xend restart)
        @type  recreate: bool
        @return: block device controller
        @rtype: UsbifController
        """
        usbif = self.getControllerByDom(dom)
        if usbif is None:
            usbif = UsbifController(self, dom)
            self.addController(usbif)
        return usbif

    def getDomainDevices(self, dom):
        """Get the block devices for a domain.

        @param dom: domain
        @type  dom: int
        @return: devices
        @rtype:  [device]
        """
        usbif = self.getControllerByDom(dom)
        return (usbif and usbif.getDevices()) or []

    def getDomainDevice(self, dom, vdev):
        """Get a block device from a domain.

        @param dom: domain
        @type  dom: int
        @param vdev: device index
        @type  vdev: int
        @return: device
        @rtype:  device
        """
        usbif = self.getControllerByDom(dom)
        return (usbif and usbif.getDevice(vdev)) or None
    
    def createBackendInterface(self, ctrl, dom, handle):
        """Create a network device backend interface.

        @param ctrl: controller
        @param dom: backend domain
        @param handle: interface handle
        @return: backend interface
        """
        return UsbifBackendInterface(ctrl, dom)

    def getBackendController(self, dom):
        """Get the backend controller for a domain, creating
        if necessary.

        @param dom: backend domain
        @return: backend controller
        """
        b = self.getBackendControllerByDomain(dom)
        if b is None:
            b = self.createBackendController(dom)
            self.backendControllers[b.dom] = b
        return b

    def createBackendController(self, dom):
        return UsbifBackendController(self, dom)

class UsbifController(controller.SplitController):
    """USB device interface controller. Handles all USB devices
    for a domain.
    """
    
    def __init__(self, factory, dom):
        """Create a USB device controller.
        Do not call directly - use createController() on the factory instead.
        """
        controller.SplitController.__init__(self, factory, dom)
        self.num_ports = 0
        self.devices = {}
        self.addMethod(CMSG_USBIF_FE,
                       CMSG_USBIF_FE_DRIVER_STATUS_CHANGED,
                       self.recv_fe_driver_status_changed)
        self.addMethod(CMSG_USBIF_FE,
                       CMSG_USBIF_FE_INTERFACE_CONNECT,
                       self.recv_fe_interface_connect)
        self.registerChannel()
        try:
            self.backendDomain = 0 #int(sxp.child_value(config, 'backend', '0')) TODO: configurable backends
        except:
            raise XendError('invalid backend domain')


    def sxpr(self):
        val = ['usbif', ['dom', self.dom]]
        return val

    def createBackend(self, dom, handle):
        return UsbifBackendController(self, dom, handle)

    def getDevices(self):
        return self.devices.values()

    def attachDevice(self, path, recreate=0):
        """Add privileges for a particular device to the domain.
        @param path: the Linux-style path to the device port
        """
        self.devices[path[1][1]] = self.num_ports
        self.num_ports += 1
        log.debug(">UsbifController>attachDevice> device: %s, port: %d" %
                  (str(path), self.num_ports ) )

        backend =self.getBackendInterface(self.backendDomain)

        def cb(blah):
            log.debug(">UsbifController> Backend created")
            pass
        d = backend.connect()
        d.addCallback(cb) # Chaining the claim port operation
        return d


    def removeDevice(self, path):
        self.delDevice(path)
        backend = self.getBackendInterface(self.backendDomain)
        return backend.send_be_release_port(path)

    def delDevice(self, path):
        if path in self.devices:
            del self.devices[path]

    def attachPort(self, path, recreate=0):
        """Attach a device to the specified interface.
        On success the returned deferred will be called with the device.

        @return: deferred
        @rtype:  Deferred
        """
        return self.attachDevice(path)

    def destroy(self):
        """Destroy the controller and all devices.
        """
        log.debug("Destroying usbif domain=%d", self.dom)
        self.destroyBackends()

    def destroyDevices(self):
        """Destroy all devices.
        """
        for path in self.getDevices():
            self.removeDevice(path)

    def destroyBackends(self):
        for backend in self.getBackendInterfaces():
            backend.destroy()

    def recv_fe_driver_status_changed(self, msg, req):
        val = unpackMsg('usbif_fe_driver_status_changed_t', msg)
        log.debug('>UsbifController>recv_fe_driver_status_changed> %s', str(val))
        # For each backend?
        msg = packMsg('usbif_fe_interface_status_changed_t',
                      { 'status' : USBIF_INTERFACE_STATUS_DISCONNECTED,
                        'domid'  : 0, ## FIXME: should be domid of backend
                        'evtchn' : 0 })
        d = defer.Deferred()
        d.addCallback(self.disconnected_resp)
        self.writeRequest(msg)

    def disconnected_resp(self, msg):
        val = unpackMsg('usbif_fe_interface_status_changed_t', msg)
        if val['status'] != USBIF_INTERFACE_STATUS_DISCONNECTED:
            log.error(">UsbifController>disconnected_resp> unexpected status change")
        else:
            log.debug(">UsbifController>disconnected_resp> interface disconnected OK")

    def recv_fe_interface_connect(self, msg, req):
        val = unpackMsg('usbif_fe_interface_status_changed_t', msg)
        log.debug(">UsbifController>recv_fe_interface_connect> notifying backend")
        backend = self.getBackendInterfaceByHandle(0)
        if backend:
            d = backend.connectInterface(val)
        else:
            log.error('>UsbifController>recv_fe_interface_connect> unknown interface')

    def claim_ports(self):
        backend = self.getBackendInterfaceByHandle(0)
        for path in self.devices.keys():
            log.debug(">UsbifController>claim_ports> claiming port... %s" % path)
            backend.send_be_claim_port(path)

