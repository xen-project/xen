# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Support for virtual block devices.
"""

from twisted.internet import defer
#defer.Deferred.debug = 1

from xen.xend import sxp
from xen.xend.XendLogging import log
from xen.xend.XendError import XendError

import channel
import controller
from messages import *

class BlkifBackendController(controller.BackendController):
    """ Handler for the 'back-end' channel to a device driver domain.
    """

    def __init__(self, factory, dom):
        controller.BackendController.__init__(self, factory, dom)
        self.addMethod(CMSG_BLKIF_BE,
                       CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED,
                       self.recv_be_driver_status_changed)
        self.registerChannel()

    def recv_be_driver_status_changed(self, msg, req):
        """Request handler for be_driver_status_changed messages.
        
        @param msg: message
        @type  msg: xu message
        @param req: request flag (true if the msg is a request)
        @type  req: bool
        """
        val = unpackMsg('blkif_be_driver_status_changed_t', msg)
        status = val['status']

class BlkifControllerFactory(controller.SplitControllerFactory):
    """Factory for creating block device interface controllers.
    """

    def __init__(self):
        controller.SplitControllerFactory.__init__(self)

    def createInstance(self, dom, recreate=0, backend=0):
        """Create a block device controller for a domain.

        @param dom: domain
        @type  dom: int
        @param recreate: if true it's a recreate (after xend restart)
        @type  recreate: bool
        @return: deferred
        @rtype: twisted.internet.defer.Deferred
        """
        blkif = self.getInstanceByDom(dom)
        if blkif:
            d = defer.Deferred()
            d.callback(blkif)
        else:
            blkif = BlkifController(self, dom, backend)
            self.addInstance(blkif)
            d = blkif.connect(recreate=recreate)
        return d

    def getDomainDevices(self, dom):
        """Get the block devices for a domain.

        @param dom: domain
        @type  dom: int
        @return: devices
        @rtype:  [device]
        """
        blkif = self.getInstanceByDom(dom)
        return (blkif and blkif.getDevices()) or []

    def getDomainDevice(self, dom, vdev):
        """Get a block device from a domain.

        @param dom: domain
        @type  dom: int
        @param vdev: device index
        @type  vdev: int
        @return: device
        @rtype:  device
        """
        blkif = self.getInstanceByDom(dom)
        return (blkif and blkif.getDevice(vdev)) or None

    def createBackendController(self, dom):
        return BlkifBackendController(self, dom)

class BlkDev(controller.Dev):
    """Info record for a block device.
    """

    def __init__(self, ctrl, vdev, mode, segment):
        controller.Dev.__init__(self,  segment['device'], ctrl)
        self.dev = None
        self.uname = None
        self.vdev = vdev
        self.mode = mode
        self.device = segment['device']
        self.start_sector = segment['start_sector']
        self.nr_sectors = segment['nr_sectors']

    def getBackendController(self):
        return self.controller.backendController

    def readonly(self):
        return 'w' not in self.mode

    def sxpr(self):
        val = ['blkdev',
               ['idx', self.idx],
               ['vdev', self.vdev],
               ['device', self.device],
               ['mode', self.mode]]
        if self.dev:
            val.append(['dev', self.dev])
        if self.uname:
            val.append(['uname', self.uname])
        return val

    def destroy(self):
        log.debug("Destroying vbd domain=%d vdev=%d", self.controller.dom, self.vdev)
        self.send_be_vbd_destroy()

    def attach(self, d):
        """Attach the device to its controller.

        @param d: deferred to call with the device on success
        """
        d1 = defer.Deferred()
        d1.addCallback(self.respond_be_vbd_create, d)
        d1.addErrback(d.errback)
        self.send_be_vbd_create(response=d1)
        
    def send_be_vbd_create(self, response=None):
        msg = packMsg('blkif_be_vbd_create_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.controller.handle,
                        'vdevice'      : self.vdev,
                        'readonly'     : self.readonly() })
        self.getBackendController().writeRequest(msg, response=response)
        
    def respond_be_vbd_create(self, msg, d):
        """Response handler for a be_vbd_create message.
        Tries to grow the vbd.

        @param msg: message
        @type  msg: xu message
        @param d: deferred to call
        @type  d: Deferred
        """
        val = unpackMsg('blkif_be_vbd_create_t', msg)
        d1 = defer.Deferred()
        d1.addCallback(self.respond_be_vbd_grow, d)
        if d: d1.addErrback(d.errback)
        self.send_be_vbd_grow(response=d1)
    
    def send_be_vbd_grow(self, response=None):
        msg = packMsg('blkif_be_vbd_grow_t',
                      { 'domid'                : self.controller.dom,
                        'blkif_handle'         : self.controller.handle,
                        'vdevice'              : self.vdev,
                        'extent.device'        : self.device,
                        'extent.sector_start'  : self.start_sector,
                        'extent.sector_length' : self.nr_sectors })
        self.getBackendController().writeRequest(msg, response=response)

    def respond_be_vbd_grow(self, msg, d):
        """Response handler for a be_vbd_grow message.

        @param msg: message
        @type  msg: xu message
        @param d: deferred to call
        @type  d: Deferred or None
        """
        val = unpackMsg('blkif_be_vbd_grow_t', msg)
	status = val['status']
	if status != BLKIF_BE_STATUS_OKAY:
            err = XendError("Adding extent to vbd failed: device %d, error %d"
                            % (self.vdev, status))
            #if(d):
            #    d.errback(err)
            raise err
        if d:
            d.callback(self)

    def send_be_vbd_destroy(self, response=None):
        log.debug('>BlkDev>send_be_vbd_destroy> dom=%d vdev=%d',
                  self.controller.dom, self.vdev)
        msg = packMsg('blkif_be_vbd_destroy_t',
                      { 'domid'                : self.controller.dom,
                        'blkif_handle'         : self.controller.handle,
                        'vdevice'              : self.vdev })
        self.controller.delDevice(self.vdev)
        self.getBackendController().writeRequest(msg, response=response)
        
        
class BlkifController(controller.SplitController):
    """Block device interface controller. Handles all block devices
    for a domain.
    """
    
    def __init__(self, factory, dom, backend):
        """Create a block device controller.
        The controller must be connected using connect() before it can be used.
        Do not call directly - use createInstance() on the factory instead.
        """
        controller.SplitController.__init__(self, factory, dom, backend)
        self.devices = {}
        self.addMethod(CMSG_BLKIF_FE,
                       CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED,
                       self.recv_fe_driver_status_changed)
        self.addMethod(CMSG_BLKIF_FE,
                       CMSG_BLKIF_FE_INTERFACE_CONNECT,
                       self.recv_fe_interface_connect)
        self.handle = 0
        self.evtchn = None
        self.registerChannel()

    def sxpr(self):
        val = ['blkif', ['dom', self.dom]]
        if self.evtchn:
            val.append(['evtchn',
                        self.evtchn['port1'],
                        self.evtchn['port2']])
        return val

    def getDevices(self):
        return self.devices.values()

    def getDevice(self, vdev):
        return self.devices.get(vdev)

    def addDevice(self, vdev, mode, segment):
        """Add a device to the device table.

        @param vdev:     device index
        @type  vdev:     int
        @param mode:     read/write mode
        @type  mode:     string
        @param segment:  segment
        @type  segment:  int
        @return: device
        @rtype:  BlkDev
        """
        if vdev in self.devices: return None
        dev = BlkDev(self, vdev, mode, segment)
        self.devices[vdev] = dev
        return dev

    def delDevice(self, vdev):
        if vdev in self.devices:
            del self.devices[vdev]

    def attachDevice(self, vdev, mode, segment, recreate=0):
        """Attach a device to the specified interface.
        On success the returned deferred will be called with the device.

        @param vdev:     device index
        @type  vdev:     int
        @param mode:     read/write mode
        @type  mode:     string
        @param segment:  segment
        @type  segment:  int
        @param recreate: if true it's being recreated (after xend restart)
        @type  recreate: bool
        @return: deferred
        @rtype:  Deferred
        """
        dev = self.addDevice(vdev, mode, segment)
        if not dev: return -1
        d = defer.Deferred()
        if recreate:
            d.callback(dev)
        else:
            dev.attach(d)
        return d

    def destroy(self):
        """Destroy the controller and all devices.
        """
        log.debug("Destroying blkif domain=%d", self.dom)
        self.destroyDevices()
        self.disconnect()

    def destroyDevices(self):
        """Destroy all devices.
        """
        for dev in self.getDevices():
            dev.destroy()

    def connect(self, recreate=0):
        """Connect the controller to the blkif control interface.

        @param recreate: true if after xend restart
        @return: deferred
        """
        log.debug("Connecting blkif domain=%d", self.dom)
        d = defer.Deferred()
        if recreate:
            d.callback(self)
        else:
            def cbresp(msg):
                return self
            d.addCallback(cbresp)
            self.send_be_create(response=d)
        return d
        
    def send_be_create(self, response=None):
        msg = packMsg('blkif_be_create_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : self.handle })
        self.backendController.writeRequest(msg, response=response)
    
    def disconnect(self):
        """Disconnect from the blkif control interface and destroy it.
        """
        def cb_destroy(val):
            self.send_be_destroy()
        d = defer.Deferred()
        d.addCallback(cb_destroy)
        self.send_be_disconnect(response=d)
        
    def send_be_disconnect(self, response=None):
        log.debug('>BlkifController>send_be_disconnect> dom=%d', self.dom)
        msg = packMsg('blkif_be_disconnect_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : self.handle })
        self.backendController.writeRequest(msg, response=response)

    def send_be_destroy(self, response=None):
        log.debug('>BlkifController>send_be_destroy> dom=%d', self.dom)
        msg = packMsg('blkif_be_destroy_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : self.handle })
        self.backendController.writeRequest(msg, response=response)
        
    def recv_fe_driver_status_changed(self, msg, req):
        msg = packMsg('blkif_fe_interface_status_changed_t',
                      { 'handle' : self.handle,
                        'status' : BLKIF_INTERFACE_STATUS_DISCONNECTED,
                        'evtchn' : 0 })
        self.writeRequest(msg)

    def recv_fe_interface_connect(self, msg, req):
        val = unpackMsg('blkif_fe_interface_connect_t', msg)
        self.evtchn = channel.eventChannel(0, self.dom)
        log.debug("Connecting blkif to event channel dom=%d ports=%d:%d",
                  self.dom, self.evtchn['port1'], self.evtchn['port2'])
        msg = packMsg('blkif_be_connect_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : val['handle'],
                        'evtchn'       : self.evtchn['port1'],
                        'shmem_frame'  : val['shmem_frame'] })
        d = defer.Deferred()
        d.addCallback(self.respond_be_connect)
        self.backendController.writeRequest(msg, response=d)

    def respond_be_connect(self, msg):
        """Response handler for a be_connect message.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('blkif_be_connect_t', msg)
        self.send_fe_interface_status_changed()
            
    def send_fe_interface_status_changed(self, response=None):
        msg = packMsg('blkif_fe_interface_status_changed_t',
                      { 'handle' : self.handle,
                        'status' : BLKIF_INTERFACE_STATUS_CONNECTED,
                        'evtchn' : self.evtchn['port2'] })
        self.writeRequest(msg, response=response)
    

