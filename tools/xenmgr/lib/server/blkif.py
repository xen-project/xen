import channel
import controller
from messages import *

class BlkifControllerFactory(controller.ControllerFactory):
    """Factory for creating block device interface controllers.
    Also handles the 'back-end' channel to dom0.
    """

    # todo: add support for setting dom controlling blkifs (don't assume 0).
    # todo: add support for 'recovery'.

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

    def createInstance(self, dom):
        d = self.addDeferred()
        blkif = self.getInstanceByDom(dom)
        if blkif:
            self.callDeferred(blkif)
        else:
            blkif = BlkifController(self, dom)
            self.addInstance(blkif)
            blkif.send_be_create()
        return d

    def setControlDomain(self, dom):
        if self.channel:
            self.deregisterChannel()
            self.attached = 0
        self.dom = dom
        self.registerChannel()
        #
        #if xend.blkif.be_port:
        #    xend.blkif.recovery = True
        #xend.blkif.be_port = xend.main.port_from_dom(dom)

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
            self.reattach_device(val['domid'], val['vdevice'])

    def reattach_device(self, dom, vdev):
        blkif = self.getInstanceByDom(dom)
        if blkif:
            blkif.reattach_device(vdev)
        attached = 1
        for blkif in self.getInstances():
            if not blkif.attached:
                attached = 0
                break
        self.attached = attached
        if self.attached:
            self.reattached()

    def reattached(self):
        for blkif in self.getInstances():
            blkif.reattached()

    def recv_be_driver_status_changed(self, msg, req):
        val = unpackMsg('blkif_be_driver_status_changed_t', msg)
        status = val['status']
        if status == BLKIF_DRIVER_STATUS_UP and not self.attached:
            for blkif in self.getInstances():
                blkif.detach()

class BlkDev:
    """Info record for a block device.
    """

    def __init__(self, vdev, mode, segment):
        self.vdev = vdev
        self.mode = mode
        self.device = segment['device']
        self.start_sector = segment['start_sector']
        self.nr_sectors = segment['nr_sectors']
        self.attached = 1

    def readonly(self):
        return 'w' not in self.mode
        
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
        self.registerChannel()
        #print 'BlkifController<', 'dom=', self.dom, 'idx=', self.idx

    def attach_device(self, vdev, mode, segment):
        """Attach a device to the specified interface.
        """
        #print 'BlkifController>attach_device>', self.dom, vdev, mode, segment
        if vdev in self.devices: return -1
        dev = BlkDev(vdev, mode, segment)
        self.devices[vdev] = dev
        self.send_be_vbd_create(vdev)
        return self.factory.addDeferred()

    def detach(self):
        self.attached = 0
        for dev in self.devices.values():
            dev.attached = 0
            self.send_be_vbd_create(vdev)

    def reattach_device(self, vdev):
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
    
