# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from twisted.internet import defer
#defer.Deferred.debug = 1

from xen.xend import sxp
from xen.xend.XendLogging import log

import channel
import controller
from messages import *

class BlkifControllerFactory(controller.ControllerFactory):
    """Factory for creating block device interface controllers.
    Also handles the 'back-end' channel to the device driver domain.
    """

    def __init__(self):
        controller.ControllerFactory.__init__(self)

        self.majorTypes = [ CMSG_BLKIF_BE ]

        self.subTypes = {
            CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED: self.recv_be_driver_status_changed,
            }
        self.attached = 1
        self.registerChannel()

    def createInstance(self, dom, recreate=0):
        """Create a block device controller for a domain.

        @param dom: domain
        @type  dom: int
        @param recreate: if true it's a recreate (after xend restart)
        @type  recreate: bool
        @return: deferred
        @rtype: twisted.internet.defer.Deferred
        """
        d = defer.Deferred()
        blkif = self.getInstanceByDom(dom)
        if blkif:
            d.callback(blkif)
        else:
            blkif = BlkifController(self, dom)
            self.addInstance(blkif)
            if recreate:
                d.callback(blkif)
            else:
                d1 = defer.Deferred()
                d1.addCallback(self.respond_be_create, d)
                d1.addErrback(d.errback)
                blkif.send_be_create(response=d1)
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
        @type  vedv: int
        @return: device
        @rtype:  device
        """
        blkif = self.getInstanceByDom(dom)
        return (blkif and blkif.getDevice(vdev)) or None

    def setControlDomain(self, dom, recreate=0):
        """Set the back-end block device controller domain.

        @param dom: domain
        @type  dom: int
        @param recreate: if true it's a recreate (after xend restart)
        @type  recreate: int
        """
        if self.dom == dom: return
        self.deregisterChannel()
        if not recreate:
            self.attached = 0
        self.dom = dom
        self.registerChannel()

    def getControlDomain(self):
        """Get the back-end block device controller domain.

        @return: domain
        @rtype:  int
        """
        return self.dom

    def reattachDevice(self, dom, vdev):
        """Reattach a device (on changing control domain).

        @param dom: domain
        @type  dom: int
        @param vdev: device index
        @type  vdev: int
        """
        blkif = self.getInstanceByDom(dom)
        if blkif:
            blkif.reattachDevice(vdev)
        self.attached = self.devicesAttached()
        if self.attached:
            self.reattached()

    def devicesAttached(self):
        """Check if all devices are attached.

        @return: true if all devices attached
        @rtype:  bool
        """
        attached = 1
        for blkif in self.getInstances():
            if not blkif.attached:
                attached = 0
                break
        return attached
                         
    def reattached(self):
        """Notify all block interfaces we have been reattached
        (after changing control domain).
        """
        for blkif in self.getInstances():
            blkif.reattached()

    def respond_be_create(self, msg, d):
        """Response handler for a be_create message.
        Calls I{d} with the block interface created.

        @param msg: message
        @type  msg: xu message
        @param d: deferred to call
        @type  d: Deferred
        """
        val = unpackMsg('blkif_be_create_t', msg)
        blkif = self.getInstanceByDom(val['domid'])
        d.callback(blkif)
    
    def respond_be_connect(self, msg):
        """Response handler for a be_connect message.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('blkif_be_connect_t', msg)
        blkif = self.getInstanceByDom(val['domid'])
        if blkif:
            blkif.send_fe_interface_status_changed()
        else:
            pass
    
    def respond_be_vbd_create(self, msg, d):
        """Response handler for a be_vbd_create message.
        Tries to grow the vbd, and passes the deferred I{d} on for
        the grow to call.

        @param msg: message
        @type  msg: xu message
        @param d: deferred to call
        @type  d: Deferred
        """
        val = unpackMsg('blkif_be_vbd_create_t', msg)
        blkif = self.getInstanceByDom(val['domid'])
        if blkif:
            d1 = defer.Deferred()
            d1.addCallback(self.respond_be_vbd_grow, d)
            if d: d1.addErrback(d.errback)
            blkif.send_be_vbd_grow(val['vdevice'], response=d1)
        else:
            pass
    
    def respond_be_vbd_grow(self, msg, d):
        """Response handler for a be_vbd_grow message.

        @param msg: message
        @type  msg: xu message
        @param d: deferred to call
        @type  d: Deferred or None
        """
        val = unpackMsg('blkif_be_vbd_grow_t', msg)
        # Check status?
        if self.attached:
            if d:
                d.callback(0)
        else:
            self.reattachDevice(val['domid'], val['vdevice'])

    def recv_be_driver_status_changed(self, msg, req):
        """Request handler for be_driver_status_changed messages.
        
        @param msg: message
        @type  msg: xu message
        @param req: request flag (true if the msg is a request)
        @type  req: bool
        """
        val = unpackMsg('blkif_be_driver_status_changed_t', msg)
        status = val['status']
        if status == BLKIF_DRIVER_STATUS_UP and not self.attached:
            for blkif in self.getInstances():
                blkif.detach()

class BlkDev(controller.Dev):
    """Info record for a block device.
    """

    def __init__(self, ctrl, vdev, mode, segment):
        controller.Dev.__init__(self,  segment['device'], ctrl)
        self.vdev = vdev
        self.mode = mode
        self.device = segment['device']
        self.start_sector = segment['start_sector']
        self.nr_sectors = segment['nr_sectors']
        self.attached = 1

    def readonly(self):
        return 'w' not in self.mode

    def sxpr(self):
        val = ['blkdev',
               ['idx', self.idx],
               ['vdev', self.vdev],
               ['device', self.device],
               ['mode', self.mode]]
        return val

    def destroy(self):
        log.debug("Destroying vbd domain=%d vdev=%d", self.controller.dom, self.vdev)
        self.controller.send_be_vbd_destroy(self.vdev)
        
class BlkifController(controller.Controller):
    """Block device interface controller. Handles all block devices
    for a domain.
    """
    
    def __init__(self, factory, dom):
        controller.Controller.__init__(self, factory, dom)
        self.devices = {}

        self.majorTypes = [ CMSG_BLKIF_FE ]

        self.subTypes = {
            CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED:
                self.recv_fe_driver_status_changed,
            CMSG_BLKIF_FE_INTERFACE_CONNECT    :
                self.recv_fe_interface_connect,
            }
        self.attached = 1
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

    def attachDevice(self, vdev, mode, segment, recreate=0):
        """Attach a device to the specified interface.

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
            d.callback(self)
        else:
            d1 = defer.Deferred()
            d1.addCallback(self.factory.respond_be_vbd_create, d)
            d1.addErrback(d.errback)
            self.send_be_vbd_create(vdev, response=d1)
        return d

    def destroy(self):
        def cb_destroy(val):
            self.send_be_destroy()
        log.debug("Destroying blkif domain=%d", self.dom)
        d = defer.Deferred()
        d.addCallback(cb_destroy)
        self.send_be_disconnect(response=d)

    def destroyDevices(self):
        for dev in self.getDevices():
            dev.destroy()

    def detach(self):
        """Detach all devices, when the back-end control domain has changed.
        """
        self.attached = 0
        for dev in self.devices.values():
            dev.attached = 0
            d1 = defer.Deferred()
            d1.addCallback(self.factory.respond_be_vbd_create, None)
            self.send_be_vbd_create(vdev, response=d1)

    def reattachDevice(self, vdev):
        """Reattach a device, when the back-end control domain has changed.
        """
        dev = self.devices[vdev]
        dev.attached = 1
        attached = 1
        for dev in self.devices.values():
            if not dev.attached:
                attached = 0
                break
        self.attached = attached
        return self.attached

    def reattached(self):
        """All devices have been reattached after the back-end control
        domain has changed.
        """
        msg = packMsg('blkif_fe_interface_status_changed_t',
                      { 'handle' : 0,
                        'status' : BLKIF_INTERFACE_STATUS_DISCONNECTED})
        self.writeRequest(msg)

    def recv_fe_driver_status_changed(self, msg, req):
        msg = packMsg('blkif_fe_interface_status_changed_t',
                      { 'handle' : 0,
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
        d.addCallback(self.factory.respond_be_connect)
        self.factory.writeRequest(msg, response=d)

    def send_fe_interface_status_changed(self, response=None):
        msg = packMsg('blkif_fe_interface_status_changed_t',
                      { 'handle' : 0,
                        'status' : BLKIF_INTERFACE_STATUS_CONNECTED,
                        'evtchn' : self.evtchn['port2'] })
        self.writeRequest(msg, response=response)

    def send_be_create(self, response=None):
        msg = packMsg('blkif_be_create_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : 0 })
        self.factory.writeRequest(msg, response=response)

    def send_be_disconnect(self, response=None):
        log.debug('>BlkifController>send_be_disconnect> dom=%d', self.dom)
        msg = packMsg('blkif_be_disconnect_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : 0 })
        self.factory.writeRequest(msg, response=response)

    def send_be_destroy(self, response=None):
        log.debug('>BlkifController>send_be_destroy> dom=%d', self.dom)
        msg = packMsg('blkif_be_destroy_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : 0 })
        self.factory.writeRequest(msg, response=response)

    def send_be_vbd_create(self, vdev, response=None):
        dev = self.devices[vdev]
        msg = packMsg('blkif_be_vbd_create_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : 0,
                        'vdevice'      : dev.vdev,
                        'readonly'     : dev.readonly() })
        self.factory.writeRequest(msg, response=response)
        
    def send_be_vbd_grow(self, vdev, response=None):
        dev = self.devices[vdev]
        msg = packMsg('blkif_be_vbd_grow_t',
                      { 'domid'                : self.dom,
                        'blkif_handle'         : 0,
                        'vdevice'              : dev.vdev,
                        'extent.device'        : dev.device,
                        'extent.sector_start'  : dev.start_sector,
                        'extent.sector_length' : dev.nr_sectors })
        self.factory.writeRequest(msg, response=response)

    def send_be_vbd_destroy(self, vdev, response=None):
        log.debug('>BlkifController>send_be_vbd_destroy> dom=%d vdev=%d', self.dom, vdev)
        dev = self.devices[vdev]
        msg = packMsg('blkif_be_vbd_destroy_t',
                      { 'domid'                : self.dom,
                        'blkif_handle'         : 0,
                        'vdevice'              : dev.vdev })
        del self.devices[vdev]
        self.factory.writeRequest(msg, response=response)
    
