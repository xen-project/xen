
###################################################################
## xend/netif.py -- Network-interface management functions for Xend
## Copyright (c) 2004, K A Fraser (University of Cambridge)
###################################################################

import errno, random, re, os, select, signal, socket, struct, sys
import xend.main, xend.console, xend.manager, xend.utils, Xc

CMSG_NETIF_BE = 3
CMSG_NETIF_FE = 4
CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED =  0
CMSG_NETIF_FE_DRIVER_STATUS_CHANGED    = 32
CMSG_NETIF_FE_INTERFACE_CONNECT        = 33
CMSG_NETIF_FE_INTERFACE_DISCONNECT     = 34
CMSG_NETIF_BE_CREATE      = 0
CMSG_NETIF_BE_DESTROY     = 1
CMSG_NETIF_BE_CONNECT     = 2
CMSG_NETIF_BE_DISCONNECT  = 3

pendmsg = None
pendaddr = None

def backend_tx_req(msg):
    port = xend.main.dom0_port
    if port.space_to_write_request():
        port.write_request(msg)
        port.notify()
    else:
        xend.netif.pendmsg = msg

def backend_rx_req(port, msg):
    port.write_response(msg)

def backend_rx_rsp(port, msg):
    subtype = (msg.get_header())['subtype']
    print "Received netif-be response, subtype %d" % subtype
    if subtype == CMSG_NETIF_BE_CREATE:
        rsp = { 'success': True }
        xend.main.send_management_response(rsp, xend.netif.pendaddr)
    elif subtype == CMSG_NETIF_BE_CONNECT:
        (dom,hnd,evtchn,tx_frame,rx_frame,st) = \
           struct.unpack("QIILLI", msg.get_payload())
        netif = interface.list[xend.main.port_from_dom(dom).local_port]
        msg = xend.utils.message(CMSG_NETIF_FE, \
                                 CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED, 0)
        msg.append_payload(struct.pack("IIIBBBBBBBB",0,2, \
                                       netif.evtchn['port2'], \
                                       netif.mac[0],netif.mac[1], \
                                       netif.mac[2],netif.mac[3], \
                                       netif.mac[4],netif.mac[5], \
                                       0,0))
        netif.ctrlif_tx_req(xend.main.port_list[netif.key], msg)

def backend_do_work(port):
    global pendmsg
    if pendmsg and port.space_to_write_request():
        port.write_request(pendmsg)
        pendmsg = None
        return True
    return False


class interface:

    # Dictionary of all network-device interfaces.
    list = {}


    # NB. 'key' is an opaque value that has no meaning in this class.
    def __init__(self, dom, key):
        self.dom     = dom
        self.key     = key
        self.pendmsg = None

        # VIFs get a random MAC address with a "special" vendor id.
        # 
        # NB. The vendor is currently an "obsolete" one that used to belong
        # to DEC (AA-00-00). Using it is probably a bit rude :-)
        # 
        # NB2. The first bit of the first random octet is set to zero for
        # all dynamic MAC addresses. This may allow us to manually specify
        # MAC addresses for some VIFs with no fear of clashes.
        self.mac = [ 0xaa, 0x00, 0x00 ]
        self.mac.append(int(random.random()*128))
        self.mac.append(int(random.random()*256))
        self.mac.append(int(random.random()*256))
                
        interface.list[key] = self
        msg = xend.utils.message(CMSG_NETIF_BE, CMSG_NETIF_BE_CREATE, 0)
        msg.append_payload(struct.pack("QIBBBBBBBBI",dom,0, \
                                       self.mac[0],self.mac[1], \
                                       self.mac[2],self.mac[3], \
                                       self.mac[4],self.mac[5], \
                                       0,0,0))
        xend.netif.pendaddr = xend.main.mgmt_req_addr
        backend_tx_req(msg)


    # Completely destroy this interface.
    def destroy(self):
        del interface.list[self.key]
        msg = xend.utils.message(CMSG_NETIF_BE, CMSG_NETIF_BE_DESTROY, 0)
        msg.append_payload(struct.pack("QII",self.dom,0,0))
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
        if subtype == CMSG_NETIF_FE_DRIVER_STATUS_CHANGED:
            msg = xend.utils.message(CMSG_NETIF_FE, \
                                     CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED, 0)
            msg.append_payload(struct.pack("IIIBBBBBBBB",0,1,0,self.mac[0], \
                                           self.mac[1],self.mac[2], \
                                           self.mac[3],self.mac[4], \
                                           self.mac[5],0,0))
            self.ctrlif_tx_req(port, msg)
        elif subtype == CMSG_NETIF_FE_INTERFACE_CONNECT:
            (hnd,tx_frame,rx_frame) = struct.unpack("ILL", msg.get_payload())
            xc = Xc.new()
            self.evtchn = xc.evtchn_bind_interdomain(dom1=0,dom2=self.dom)
            msg = xend.utils.message(CMSG_NETIF_BE, \
                                     CMSG_NETIF_BE_CONNECT, 0)
            msg.append_payload(struct.pack("QIILLI",self.dom,0, \
                                           self.evtchn['port1'],tx_frame, \
                                           rx_frame,0))
            backend_tx_req(msg)
