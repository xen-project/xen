from twisted.internet import defer

from xenmgr import sxp
from xenmgr import PrettyPrint

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
            CMSG_BLKIF_BE_CREATE     : self.recv_be_create,
            CMSG_BLKIF_BE_CONNECT    : self.recv_be_connect,
            CMSG_BLKIF_BE_VBD_CREATE : self.recv_be_vbd_create,
            CMSG_BLKIF_BE_VBD_GROW   : self.recv_be_vbd_grow,
            CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED: self.recv_be_driver_status_changed,
            }
        self.attached = 1
        self.registerChannel()

    def createInstance(self, dom, recreate=0):
        d = self.addDeferred()
        blkif = self.getInstanceByDom(dom)
        if blkif:
            self.callDeferred(blkif)
        else:
            blkif = BlkifController(self, dom)
            self.addInstance(blkif)
            if recreate:
                self.callDeferred(blkif)
            else:
                blkif.send_be_create()
        return d

    def getDomainDevices(self, dom):
        blkif = self.getInstanceByDom(dom)
        return (blkif and blkif.getDevices()) or []

    def getDomainDevice(self, dom, vdev):
        blkif = self.getInstanceByDom(dom)
        return (blkif and blkif.getDevice(vdev)) or None

    def setControlDomain(self, dom, recreate=0):
        if self.dom == dom: return
        self.deregisterChannel()
        if not recreate:
            self.attached = 0
        self.dom = dom
        self.registerChannel()
        #
        #if xend.blkif.be_port:
        #    xend.blkif.recovery = True
        #xend.blkif.be_port = xend.main.port_from_dom(dom)

    def getControlDomain(self):
        return self.dom

    def reattachDevice(self, dom, vdev):
        blkif = self.getInstanceByDom(dom)
        if blkif:
            blkif.reattachDevice(vdev)
        self.attached = self.devicesAttached()
        if self.attached:
            self.reattached()

    def devicesAttached(self):
        """Check if all devices are attached.
        """
        attached = 1
        for blkif in self.getInstances():
            if not blkif.attached:
                attached = 0
                break
        return attached
                         
    def reattached(self):
        for blkif in self.getInstances():
            blkif.reattached()

    def recv_be_create(self, msg, req):
        #print 'recv_be_create>'
        val = unpackMsg('blkif_be_create_t', msg)
        blkif = self.getInstanceByDom(val['domid'])
        self.callDeferred(blkif)
    
    def recv_be_connect(self, msg, req):
        #print 'recv_be_create>'
        val = unpackMsg('blkif_be_connect_t', msg)
        blkif = self.getInstanceByDom(val['domid'])
        if blkif:
            blkif.send_fe_interface_status_changed()
        else:
            pass
    
    def recv_be_vbd_create(self, msg, req):
        #print 'recv_be_vbd_create>'
        val = unpackMsg('blkif_be_vbd_create_t', msg)
        blkif = self.getInstanceByDom(val['domid'])
        if blkif:
            blkif.send_be_vbd_grow(val['vdevice'])
        else:
            pass
    
    def recv_be_vbd_grow(self, msg, req):
        #print 'recv_be_vbd_grow>'
        val = unpackMsg('blkif_be_vbd_grow_t', msg)
        # Check status?
        if self.attached:
            self.callDeferred(0)
        else:
            self.reattachDevice(val['domid'], val['vdevice'])

    def recv_be_driver_status_changed(self, msg, req):
        val = unpackMsg('blkif_be_driver_status_changed_t', msg)
        status = val['status']
        if status == BLKIF_DRIVER_STATUS_UP and not self.attached:
            for blkif in self.getInstances():
                blkif.detach()

class BlkDev(controller.Dev):
    """Info record for a block device.
    """

    def __init__(self, ctrl, vdev, mode, segment):
        controller.Dev.__init__(self, ctrl)
        self.vdev = vdev
        self.mode = mode
        self.device = segment['device']
        self.start_sector = segment['start_sector']
        self.nr_sectors = segment['nr_sectors']
        self.attached = 1

    def readonly(self):
        return 'w' not in self.mode

    def sxpr(self):
        val = ['blkdev', ['vdev', self.vdev], ['mode', self.mode] ]
        return val

    def destroy(self):
        print 'BlkDev>destroy>', self.vdev
        PrettyPrint.prettyprint(self.sxpr())
        self.controller.send_be_vbd_destroy(self.vdev)
        
class BlkifController(controller.Controller):
    """Block device interface controller. Handles all block devices
    for a domain.
    """
    
    def __init__(self, factory, dom):
        #print 'BlkifController> dom=', dom
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
        #print 'BlkifController<', 'dom=', self.dom, 'idx=', self.idx

    def sxpr(self):
        val = ['blkif', ['dom', self.dom]]
        if self.evtchn:
            val.append(['evtchn',
                        self.evtchn['port1'],
                        self.evtchn['port2']])
        return val

    def lostChannel(self):
        print 'BlkifController>lostChannel>', 'dom=', self.dom
        #self.destroyDevices()
        controller.Controller.lostChannel(self)

    def getDevices(self):
        return self.devices.values()

    def getDevice(self, vdev):
        return self.devices.get(vdev)

    def addDevice(self, vdev, mode, segment):
        if vdev in self.devices: return None
        dev = BlkDev(self, vdev, mode, segment)
        self.devices[vdev] = dev
        return dev

    def attachDevice(self, vdev, mode, segment, recreate=0):
        """Attach a device to the specified interface.
        """
        #print 'BlkifController>attach_device>', self.dom, vdev, mode, segment
        dev = self.addDevice(vdev, mode, segment)
        if not dev: return -1
        if recreate:
            d = defer.Deferred()
            d.callback(self)
        else:
            self.send_be_vbd_create(vdev)
            d = self.factory.addDeferred()
        return d

    def destroy(self):
        print 'BlkifController>destroy> dom=', self.dom
        self.destroyDevices()
        self.send_be_destroy()

    def destroyDevices(self):
        for dev in self.getDevices():
            dev.destroy()

    def detach(self):
        """Detach all devices, when the back-end control domain has changed.
        """
        self.attached = 0
        for dev in self.devices.values():
            dev.attached = 0
            self.send_be_vbd_create(vdev)

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
        print 'recv_fe_interface_connect>'
        PrettyPrint.prettyprint(self.sxpr())
        msg = packMsg('blkif_be_connect_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : val['handle'],
                        'evtchn'       : self.evtchn['port1'],
                        'shmem_frame'  : val['shmem_frame'] })
        self.factory.writeRequest(msg)
        pass

    #def recv_fe_interface_status_changed(self, msg, req):
    #    (hnd, status, chan) = unpackMsg('blkif_fe_interface_status_changed_t', msg)
    #    print 'recv_fe_interface_status_changed>', hnd, status, chan
    #   pass

    def send_fe_interface_status_changed(self):
        msg = packMsg('blkif_fe_interface_status_changed_t',
                      { 'handle' : 0,
                        'status' : BLKIF_INTERFACE_STATUS_CONNECTED,
                        'evtchn' : self.evtchn['port2'] })
        self.writeRequest(msg)

    def send_be_create(self):
        msg = packMsg('blkif_be_create_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : 0 })
        self.factory.writeRequest(msg)

    def send_be_destroy(self):
        print '>BlkifController>send_be_destroy>', 'dom=', self.dom
        msg = packMsg('blkif_be_destroy_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : 0 })
        self.factory.writeRequest(msg)

    def send_be_vbd_create(self, vdev):
        dev = self.devices[vdev]
        msg = packMsg('blkif_be_vbd_create_t',
                      { 'domid'        : self.dom,
                        'blkif_handle' : 0,
                        'vdevice'      : dev.vdev,
                        'readonly'     : dev.readonly() })
        self.factory.writeRequest(msg)
        
    def send_be_vbd_grow(self, vdev):
        dev = self.devices[vdev]
        msg = packMsg('blkif_be_vbd_grow_t',
                      { 'domid'                : self.dom,
                        'blkif_handle'         : 0,
                        'vdevice'              : dev.vdev,
                        'extent.device'        : dev.device,
                        'extent.sector_start'  : dev.start_sector,
                        'extent.sector_length' : dev.nr_sectors })
        self.factory.writeRequest(msg)

    def send_be_vbd_destroy(self, vdev):
        print '>BlkifController>send_be_vbd_destroy>', 'dom=', self.dom, 'vdev=', vdev
        PrettyPrint.prettyprint(self.sxpr())
        dev = self.devices[vdev]
        msg = packMsg('blkif_be_vbd_destroy_t',
                      { 'domid'                : self.dom,
                        'blkif_handle'         : 0,
                        'vdevice'              : dev.vdev })
        del self.devices[vdev]
        self.factory.writeRequest(msg)
    
