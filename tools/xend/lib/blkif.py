
#################################################################
## xend/blkif.py -- Block-interface management functions for Xend
## Copyright (c) 2004, K A Fraser (University of Cambridge)
#################################################################

import errno, re, os, select, signal, socket, sys
import xend.main, xend.console, xend.manager, xend.utils, Xc

CMSG_BLKIF_BE = 1
CMSG_BLKIF_FE = 2
CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED =  0
CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED    = 32
CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED    = 32
CMSG_BLKIF_FE_INTERFACE_CONNECT        = 33
CMSG_BLKIF_FE_INTERFACE_DISCONNECT     = 34
CMSG_BLKIF_BE_CREATE      = 0
CMSG_BLKIF_BE_DESTROY     = 1
CMSG_BLKIF_BE_CONNECT     = 2
CMSG_BLKIF_BE_DISCONNECT  = 3
CMSG_BLKIF_BE_VBD_CREATE  = 4
CMSG_BLKIF_BE_VBD_DESTROY = 5
CMSG_BLKIF_BE_VBD_GROW    = 6
CMSG_BLKIF_BE_VBD_SHRINK  = 7

BLKIF_DRIVER_STATUS_DOWN  = 0
BLKIF_DRIVER_STATUS_UP    = 1

pendmsg = None
pendaddr = None

recovery = False # Is a recovery in progress? (if so we'll need to notify guests)
be_port  = None  # Port object for backend domain

def backend_tx_req(msg):
    port = xend.blkif.be_port
    if not port:
        print "BUG: attempt to transmit request to non-existant blkif driver"
    if port.space_to_write_request():
        port.write_request(msg)
        port.notify()
    else:
        xend.blkif.pendmsg = msg

def backend_rx_req(port, msg):
    port.write_response(msg)
    subtype = (msg.get_header())['subtype']
    print "Received blkif-be request, subtype %d" % subtype
    if subtype == CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED:
        status = (msg.get_payload())['status']
        if status == BLKIF_DRIVER_STATUS_UP:
            if xend.blkif.recovery:
                # Nasty hack: we count the number of VBDs we reattach so that
                # we'll know when to notify the guests.  Must make this better!
                interface.rebuilt_so_far = 0
                interface.nr_to_rebuild  = 0
                print "New blkif backend now UP, rebuilding VBDs:"
                for blkif_key in interface.list.keys():
                    blkif = interface.list[blkif_key]
                    blkif.create()
                    for vdev in blkif.devices.keys():
                        blkif.reattach_device(vdev)
                        interface.nr_to_rebuild += 1
        else:
            print "Unexpected block backend driver status: %d" % status


def backend_rx_rsp(port, msg):
    subtype = (msg.get_header())['subtype']
    print "Received blkif-be response, subtype %d" % subtype
    if subtype == CMSG_BLKIF_BE_CREATE:
        rsp = { 'success': True }
        xend.main.send_management_response(rsp, xend.blkif.pendaddr)
    elif subtype == CMSG_BLKIF_BE_CONNECT:
        pl = msg.get_payload()
        (dom, hnd, frame, evtchn, st) = (pl['domid'], pl['blkif_handle'],
                                         pl['shmem_frame'], pl['evtchn'],
                                         pl['status'])
        blkif = interface.list[xend.main.port_from_dom(dom).local_port]
        msg = xend.utils.message(CMSG_BLKIF_FE,
                                 CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED, 0,
                                 { 'handle' : 0, 'status' : 2,
                                   'evtchn' : blkif.evtchn['port2'] })
        blkif.ctrlif_tx_req(xend.main.port_list[blkif.key], msg)
    elif subtype == CMSG_BLKIF_BE_VBD_CREATE:
        pl = msg.get_payload()
        (dom, hnd, vdev, ro, st) = (pl['domid'], pl['blkif_handle'],
                                    pl['vdevice'], pl['readonly'],
                                    pl['status'])
        blkif = interface.list[xend.main.port_from_dom(dom).local_port]
        (pdev, start_sect, nr_sect, readonly) = blkif.devices[vdev]
        msg = xend.utils.message(CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_GROW, 0,
                                 { 'domid' : dom, 'blkif_handle' : 0,
                                   'vdevice' : vdev,
                                   'extent.sector_start' : start_sect,
                                   'extent.sector_length' : nr_sect,
                                   'extent.device' : pdev })
        backend_tx_req(msg)
    elif subtype == CMSG_BLKIF_BE_VBD_GROW:
       if not xend.blkif.recovery:
           rsp = { 'success': True }
           xend.main.send_management_response(rsp, xend.blkif.pendaddr)
       else:
           interface.rebuilt_so_far += 1
           if interface.rebuilt_so_far == interface.nr_to_rebuild:
               print "Rebuilt VBDs, notifying guests:"
               for blkif_key in interface.list.keys():
                   blkif = interface.list[blkif_key]
                   print "  Notifying %d" % blkif.dom
                   msg = xend.utils.message(CMSG_BLKIF_FE,
                                            CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED,
                                            0, { 'handle' : 0, 'status' : 1 })
                   blkif.ctrlif_tx_req(xend.main.port_from_dom(blkif.dom),msg)
               xend.blkif.recovery = False
               print "Done notifying guests"


def backend_do_work(port):
    global pendmsg
    if pendmsg and port.space_to_write_request():
        port.write_request(pendmsg)
        pendmsg = None
        return True
    return False


class interface:

    # Dictionary of all block-device interfaces.
    list = {}

    # NB. 'key' is an opaque value that has no meaning in this class.
    def __init__(self, dom, key):
        self.dom     = dom
        self.key     = key
        self.devices = {}
        self.pendmsg = None
        interface.list[key] = self
        self.create()

    def create(self):
        msg = xend.utils.message(CMSG_BLKIF_BE, CMSG_BLKIF_BE_CREATE, 0,
                                 { 'domid' : self.dom, 'blkif_handle' : 0 })
        xend.blkif.pendaddr = xend.main.mgmt_req_addr
        backend_tx_req(msg)

    # Attach a device to the specified interface
    def attach_device(self, vdev, pdev, start_sect, nr_sect, readonly):
        if self.devices.has_key(vdev):
            return False
        self.devices[vdev] = (pdev, start_sect, nr_sect, readonly)
        msg = xend.utils.message(CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_CREATE, 0,
                                 { 'domid' : self.dom, 'blkif_handle' : 0,
                                   'vdevice' : vdev, 'readonly' : readonly })
        xend.blkif.pendaddr = xend.main.mgmt_req_addr
        backend_tx_req(msg)
        return True

    def reattach_device(self, vdev):
        (pdev, start_sect, nr_sect, readonly) = self.devices[vdev]
        msg = xend.utils.message(CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_CREATE,
                                 0, { 'domid' : self.dom,
                                      'blkif_handle' : 0,
                                      'vdevice' : vdev,
                                      'readonly' : readonly })
        xend.blkif.pendaddr = xend.main.mgmt_req_addr
        backend_tx_req(msg)

    # Completely destroy this interface.
    def destroy(self):
        del interface.list[self.key]
        msg = xend.utils.message(CMSG_BLKIF_BE, CMSG_BLKIF_BE_DESTROY, 0,
                                 { 'domid' : self.dom, 'blkif_handle' : 0 })
        backend_tx_req(msg)        


    # The parameter @port is the control-interface event channel. This method
    # returns True if messages were written to the control interface.
    def ctrlif_transmit_work(self, port):
        if self.pendmsg and port.space_to_write_request():
            port.write_request(self.pendmsg)
            self.pendmsg = None
            return True
        return False

    def ctrlif_tx_req(self, port, msg):
        if port.space_to_write_request():
            port.write_request(msg)
            port.notify()
        else:
            self.pendmsg = msg

    def ctrlif_rx_req(self, port, msg):
        port.write_response(msg)
        subtype = (msg.get_header())['subtype']
        if subtype == CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED:
            msg = xend.utils.message(CMSG_BLKIF_FE,
                                     CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED,
                                     0,
                                     { 'handle' : 0, 'status' : 1 })
            self.ctrlif_tx_req(port, msg)
        elif subtype == CMSG_BLKIF_FE_INTERFACE_CONNECT:
            pl = msg.get_payload()
            (hnd, frame) = (pl['handle'], pl['shmem_frame'])
            xc = Xc.new()
            self.evtchn = xc.evtchn_bind_interdomain(
                                            dom1=xend.blkif.be_port.remote_dom,
                                            dom2=self.dom)
            msg = xend.utils.message(CMSG_BLKIF_BE,
                                     CMSG_BLKIF_BE_CONNECT, 0,
                                     { 'domid' : self.dom, 'blkif_handle' : 0,
                                       'shmem_frame' : frame,
                                       'evtchn' : self.evtchn['port1'] })
            backend_tx_req(msg)
