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

    def __init__(self, ctrl, dom, handle):
        controller.BackendController.__init__(self, ctrl, dom, handle)
        self.connected = 0
        self.evtchn = None
        self.handle = handle
        self.addMethod(CMSG_BLKIF_BE,
                       CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED,
                       self.recv_be_driver_status_changed)
        self.registerChannel()

    def __str__(self):
        return '<BlkifBackendController %d %d>' % (self.controller.dom, self.dom)

    def recv_be_driver_status_changed(self, msg, req):
        """Request handler for be_driver_status_changed messages.
        
        @param msg: message
        @type  msg: xu message
        @param req: request flag (true if the msg is a request)
        @type  req: bool
        """
        val = unpackMsg('blkif_be_driver_status_changed_t', msg)
        status = val['status']

    def connect(self, recreate=0):
        """Connect the controller to the blkif control interface.

        @param recreate: true if after xend restart
        @return: deferred
        """
        log.debug("Connecting blkif %s", str(self))
        if recreate or self.connected:
            d = defer.succeed(self)
        else:
            d = self.send_be_create()
            d.addCallback(self.respond_be_create)
        return d
        
    def send_be_create(self):
        d = defer.Deferred()
        msg = packMsg('blkif_be_create_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.handle })
        self.writeRequest(msg, response=d)
        return d

    def respond_be_create(self, msg):
        val = unpackMsg('blkif_be_create_t', msg)
        print 'respond_be_create>', val
        self.connected = 1
        return self
    
    def destroy(self):
        """Disconnect from the blkif control interface and destroy it.
        """
        def cb_destroy(val):
            self.send_be_destroy()
        d = defer.Deferred()
        d.addCallback(cb_destroy)
        self.send_be_disconnect(response=d)
        
    def send_be_disconnect(self, response=None):
        log.debug('>BlkifBackendController>send_be_disconnect> %s', str(self))
        msg = packMsg('blkif_be_disconnect_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.handle })
        self.writeRequest(msg, response=response)

    def send_be_destroy(self, response=None):
        log.debug('>BlkifBackendController>send_be_destroy> %s', str(self))
        msg = packMsg('blkif_be_destroy_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.handle })
        self.writeRequest(msg, response=response)

    def connectInterface(self, val):
        self.evtchn = channel.eventChannel(0, self.controller.dom)
        log.debug("Connecting blkif to event channel %s ports=%d:%d",
                  str(self), self.evtchn['port1'], self.evtchn['port2'])
        msg = packMsg('blkif_be_connect_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.handle,
                        'evtchn'       : self.evtchn['port1'],
                        'shmem_frame'  : val['shmem_frame'] })
        d = defer.Deferred()
        d.addCallback(self.respond_be_connect)
        self.writeRequest(msg, response=d)

    def respond_be_connect(self, msg):
        """Response handler for a be_connect message.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('blkif_be_connect_t', msg)
        print 'respond_be_connect>', str(self), val
        self.send_fe_interface_status_changed()
            
    def send_fe_interface_status_changed(self, response=None):
        msg = packMsg('blkif_fe_interface_status_changed_t',
                      { 'handle' : self.handle,
                        'status' : BLKIF_INTERFACE_STATUS_CONNECTED,
                        'evtchn' : self.evtchn['port2'] })
        self.controller.writeRequest(msg, response=response)
        
class BlkifControllerFactory(controller.ControllerFactory):
    """Factory for creating block device interface controllers.
    """

    def __init__(self):
        controller.ControllerFactory.__init__(self)

    def createInstance(self, dom, recreate=0):
        """Create a block device controller for a domain.

        @param dom: domain
        @type  dom: int
        @param recreate: if true it's a recreate (after xend restart)
        @type  recreate: bool
        @return: block device controller
        @rtype: BlkifController
        """
        blkif = self.getInstanceByDom(dom)
        if blkif is None:
            blkif = BlkifController(self, dom)
            self.addInstance(blkif)
        return blkif

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

class BlkDev(controller.SplitDev):
    """Info record for a block device.
    """

    def __init__(self, ctrl, config, vdev, mode, segment):
        controller.SplitDev.__init__(self,  segment['device'], ctrl)
        self.config = config
        self.dev = None
        self.uname = None
        self.vdev = vdev
        self.mode = mode
        self.device = segment['device']
        self.start_sector = segment['start_sector']
        self.nr_sectors = segment['nr_sectors']
        try:
            self.backendDomain = int(sxp.child_value(config, 'backend', '0'))
        except:
            raise XendError('invalid backend domain')

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

    def attach(self):
        """Attach the device to its controller.

        """
        backend = self.getBackend()
        d1 = backend.connect()
        d2 = defer.Deferred()
        d2.addCallback(self.send_be_vbd_create)
        d1.chainDeferred(d2)
        return d2
        
    def send_be_vbd_create(self, val):
        d = defer.Deferred()
        d.addCallback(self.respond_be_vbd_create)
        backend = self.getBackend()
        msg = packMsg('blkif_be_vbd_create_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : backend.handle,
                        'vdevice'      : self.vdev,
                        'readonly'     : self.readonly() })
        backend.writeRequest(msg, response=d)
        return d
        
    def respond_be_vbd_create(self, msg):
        """Response handler for a be_vbd_create message.
        Tries to grow the vbd.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('blkif_be_vbd_create_t', msg)
        d = self.send_be_vbd_grow()
        d.addCallback(self.respond_be_vbd_grow)
        return d
    
    def send_be_vbd_grow(self):
        d = defer.Deferred()
        backend = self.getBackend()
        msg = packMsg('blkif_be_vbd_grow_t',
                      { 'domid'                : self.controller.dom,
                        'blkif_handle'         : backend.handle,
                        'vdevice'              : self.vdev,
                        'extent.device'        : self.device,
                        'extent.sector_start'  : self.start_sector,
                        'extent.sector_length' : self.nr_sectors })
        backend.writeRequest(msg, response=d)
        return d

    def respond_be_vbd_grow(self, msg):
        """Response handler for a be_vbd_grow message.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('blkif_be_vbd_grow_t', msg)
	status = val['status']
	if status != BLKIF_BE_STATUS_OKAY:
            raise XendError("Adding extent to vbd failed: device %d, error %d"
                            % (self.vdev, status))
        return self

    def send_be_vbd_destroy(self, response=None):
        log.debug('>BlkDev>send_be_vbd_destroy> dom=%d vdev=%d',
                  self.controller.dom, self.vdev)
        backend = self.getBackend()
        msg = packMsg('blkif_be_vbd_destroy_t',
                      { 'domid'                : self.controller.dom,
                        'blkif_handle'         : backend.handle,
                        'vdevice'              : self.vdev })
        self.controller.delDevice(self.vdev)
        backend.writeRequest(msg, response=response)
        
        
class BlkifController(controller.SplitController):
    """Block device interface controller. Handles all block devices
    for a domain.
    """
    
    def __init__(self, factory, dom):
        """Create a block device controller.
        The controller must be connected using connect() before it can be used.
        Do not call directly - use createInstance() on the factory instead.
        """
        controller.SplitController.__init__(self, factory, dom)
        self.devices = {}
        self.addMethod(CMSG_BLKIF_FE,
                       CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED,
                       self.recv_fe_driver_status_changed)
        self.addMethod(CMSG_BLKIF_FE,
                       CMSG_BLKIF_FE_INTERFACE_CONNECT,
                       self.recv_fe_interface_connect)
        self.registerChannel()

    def sxpr(self):
        val = ['blkif', ['dom', self.dom]]
        return val

    def createBackend(self, dom, handle):
        return BlkifBackendController(self, dom, handle)

    def getDevices(self):
        return self.devices.values()

    def getDevice(self, vdev):
        return self.devices.get(vdev)

    def addDevice(self, config, vdev, mode, segment):
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
        if vdev in self.devices:
            raise XendError('device exists: ' + str(vdev))
        dev = BlkDev(self, config, vdev, mode, segment)
        self.devices[vdev] = dev
        return dev

    def delDevice(self, vdev):
        if vdev in self.devices:
            del self.devices[vdev]

    def attachDevice(self, config, vdev, mode, segment, recreate=0):
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
        dev = self.addDevice(config, vdev, mode, segment)
        if recreate:
            d = defer.succeed(dev)
        else:
            d = dev.attach()
        return d

    def destroy(self):
        """Destroy the controller and all devices.
        """
        log.debug("Destroying blkif domain=%d", self.dom)
        self.destroyDevices()
        self.destroyBackends()

    def destroyDevices(self):
        """Destroy all devices.
        """
        for dev in self.getDevices():
            dev.destroy()

    def destroyBackends(self):
        for backend in self.getBackends():
            backend.destroy()

    def recv_fe_driver_status_changed(self, msg, req):
        val = unpackMsg('blkif_fe_driver_status_changed_t', msg)
        print 'recv_fe_driver_status_changed>', val
        # For each backend?
        msg = packMsg('blkif_fe_interface_status_changed_t',
                      { 'handle' : 0,
                        'status' : BLKIF_INTERFACE_STATUS_DISCONNECTED,
                        'evtchn' : 0 })
        self.writeRequest(msg)

    def recv_fe_interface_connect(self, msg, req):
        val = unpackMsg('blkif_fe_interface_connect_t', msg)
        handle = val['handle']
        backend = self.getBackendByHandle(handle)
        if backend:
            backend.connectInterface(val)
        else:
            log.error('interface connect on unknown interface: handle=%d', handle)

    

