import random

from twisted.internet import defer

from xenmgr import sxp
from xenmgr import PrettyPrint
from xenmgr import XendBridge

import channel
import controller
from messages import *

class NetifControllerFactory(controller.ControllerFactory):
    """Factory for creating network interface controllers.
    Also handles the 'back-end' channel to the device driver domain.
    """

    def __init__(self):
        controller.ControllerFactory.__init__(self)

        self.majorTypes = [ CMSG_NETIF_BE ]

        self.subTypes = {
            CMSG_NETIF_BE_CREATE : self.recv_be_create,
            CMSG_NETIF_BE_CONNECT: self.recv_be_connect,
            CMSG_NETIF_BE_DRIVER_STATUS_CHANGED: self.recv_be_driver_status_changed,
            }
        self.attached = 1
        self.registerChannel()

    def createInstance(self, dom, recreate=0):
        """Create or find the network interface controller for a domain.
        """
        #print 'netif>createInstance> dom=', dom
        netif = self.getInstanceByDom(dom)
        if netif is None:
            netif = NetifController(self, dom)
            self.addInstance(netif)
        return netif

    def getDomainDevices(self, dom):
        netif = self.getInstanceByDom(dom)
        return (netif and netif.getDevices()) or []

    def getDomainDevice(self, dom, vif):
        netif = self.getInstanceByDom(dom)
        return (netif and netif.getDevice(vif)) or None
        
    def setControlDomain(self, dom, recreate=0):
        """Set the 'back-end' device driver domain.
        """
        if self.dom == dom: return
        self.deregisterChannel()
        if not recreate:
            self.attached = 0
        self.dom = dom
        self.registerChannel()
        #
        #if xend.netif.be_port.remote_dom != 0:
        #    xend.netif.recovery = True
        #    xend.netif.be_port = xend.main.port_from_dom(dom)
        #

    def getControlDomain(self):
        return self.dom

    def recv_be_create(self, msg, req):
        self.callDeferred(0)
    
    def recv_be_connect(self, msg, req):
        val = unpackMsg('netif_be_connect_t', msg)
        dom = val['domid']
        vif = val['netif_handle']
        netif = self.getInstanceByDom(dom)
        if netif:
            netif.send_interface_connected(vif)
        else:
            print "recv_be_connect> unknown vif=", vif
            pass

    def recv_be_driver_status_changed(self, msg, req):
        val = unpackMsg('netif_be_driver_status_changed_t', msg)
        status = val['status']
        if status == NETIF_DRIVER_STATUS_UP and not self.attached:
            # If we are not attached the driver domain was changed, and
            # this signals the new driver domain is ready.
            for netif in self.getInstances():
                netif.reattach_devices()
            self.attached = 1

##         pl = msg.get_payload()
##         status = pl['status']
##         if status == NETIF_DRIVER_STATUS_UP:
##             if xend.netif.recovery:
##                 print "New netif backend now UP, notifying guests:"
##                 for netif_key in interface.list.keys():
##                     netif = interface.list[netif_key]
##                     netif.create()
##                     print "  Notifying %d" % netif.dom
##                     msg = xend.utils.message(
##                         CMSG_NETIF_FE,
##                         CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED, 0,
##                         { 'handle' : 0, 'status' : 1 })
##                     netif.ctrlif_tx_req(xend.main.port_from_dom(netif.dom),msg)
##                 print "Done notifying guests"
##                 recovery = False
                
class NetDev(controller.Dev):
    """Info record for a network device.
    """

    def __init__(self, ctrl, vif, mac):
        controller.Dev.__init__(self, ctrl)
        self.vif = vif
        self.mac = mac
        self.evtchn = None
        self.bridge = None

    def sxpr(self):
        vif = str(self.vif)
        mac = ':'.join(map(lambda x: "%x" % x, self.mac))
        val = ['netdev', ['vif', vif], ['mac', mac]]
        if self.bridge:
            val.append(['bridge', self.bridge])
        if self.evtchn:
            val.append(['evtchn',
                        self.evtchn['port1'],
                        self.evtchn['port2']])
        return val

    def bridge_add(self, bridge):
        self.bridge = XendBridge.vif_bridge_add(self.controller.dom, self.vif, bridge)

    def bridge_rem(self):
        if not self.bridge: return
        XendBridge.vif_bridge_rem(self.controller.dom, self.vif, self.bridge)
        self.bridge = None

    def destroy(self):
        def cb_destroy(val):
            self.controller.send_be_destroy(self.vif)
        print 'NetDev>destroy>', 'vif=', self.vif
        PrettyPrint.prettyprint(self.sxpr())
        self.bridge_rem()
        d = self.controller.factory.addDeferred()
        d.addCallback(cb_destroy)
        self.controller.send_be_disconnect(self.vif)
        #self.controller.send_be_destroy(self.vif)
        

class NetifController(controller.Controller):
    """Network interface controller. Handles all network devices for a domain.
    """
    
    def __init__(self, factory, dom):
        #print 'NetifController> dom=', dom
        controller.Controller.__init__(self, factory, dom)
        self.devices = {}
        
        self.majorTypes = [ CMSG_NETIF_FE ]

        self.subTypes = {
            CMSG_NETIF_FE_DRIVER_STATUS_CHANGED:
                self.recv_fe_driver_status_changed,
            CMSG_NETIF_FE_INTERFACE_CONNECT    :
                self.recv_fe_interface_connect,
            }
        self.registerChannel()
        #print 'NetifController<', 'dom=', self.dom, 'idx=', self.idx

    def sxpr(self):
        val = ['netif', ['dom', self.dom]]
        return val
    
    def randomMAC(self):
        # VIFs get a random MAC address with a "special" vendor id.
        # 
        # NB. The vendor is currently an "obsolete" one that used to belong
        # to DEC (AA-00-00). Using it is probably a bit rude :-)
        # 
        # NB2. The first bit of the first random octet is set to zero for
        # all dynamic MAC addresses. This may allow us to manually specify
        # MAC addresses for some VIFs with no fear of clashes.
        mac = [ 0xaa, 0x00, 0x00,
                random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff) ]
        return mac

    def lostChannel(self):
        print 'NetifController>lostChannel>', 'dom=', self.dom
        #self.destroyDevices()
        controller.Controller.lostChannel(self)

    def getDevices(self):
        return self.devices.values()

    def getDevice(self, vif):
        return self.devices.get(vif)

    def addDevice(self, vif, vmac):
        if vmac is None:
            mac = self.randomMAC()
        else:
            mac = [ int(x, 16) for x in vmac.split(':') ]
        if len(mac) != 6: raise ValueError("invalid mac")
        #print "attach_device>", "vif=", vif, "mac=", mac
        dev = NetDev(self, vif, mac)
        self.devices[vif] = dev
        return dev

    def destroy(self):
        print 'NetifController>destroy>', 'dom=', self.dom
        self.destroyDevices()
        
    def destroyDevices(self):
        for dev in self.getDevices():
            dev.destroy()

    def attachDevice(self, vif, vmac, recreate=0):
        """Attach a network device.
        If vmac is None a random mac address is assigned.

        @param vif interface index
        @param vmac mac address (string)
        """
        self.addDevice(vif, vmac)
        if recreate:
            d = defer.Deferred()
            d.callback(self)
        else:
            d = self.factory.addDeferred()
            self.send_be_create(vif)
        return d

    def reattach_devices(self):
        """Reattach all devices when the back-end control domain has changed.
        """
        d = self.factory.addDeferred()
        self.send_be_create(vif)
        self.attach_fe_devices(0)

    def attach_fe_devices(self):
        for dev in self.devices.values():
            msg = packMsg('netif_fe_interface_status_changed_t',
                          { 'handle' : dev.vif,
                            'status' : NETIF_INTERFACE_STATUS_DISCONNECTED,
                            'evtchn' : 0,
                            'mac'    : dev.mac })
            self.writeRequest(msg)
    
    def recv_fe_driver_status_changed(self, msg, req):
        if not req: return
        msg = packMsg('netif_fe_driver_status_changed_t',
                      { 'status'        : NETIF_DRIVER_STATUS_UP,
                        'nr_interfaces' : len(self.devices) })
        self.writeRequest(msg)
        self.attach_fe_devices()

    def recv_fe_interface_connect(self, msg, req):
        val = unpackMsg('netif_fe_interface_connect_t', msg)
        dev = self.devices[val['handle']]
        dev.evtchn = channel.eventChannel(0, self.dom)
        msg = packMsg('netif_be_connect_t',
                      { 'domid'          : self.dom,
                        'netif_handle'   : dev.vif,
                        'evtchn'         : dev.evtchn['port1'],
                        'tx_shmem_frame' : val['tx_shmem_frame'],
                        'rx_shmem_frame' : val['rx_shmem_frame'] })
        self.factory.writeRequest(msg)

    def send_interface_connected(self, vif):
        dev = self.devices[vif]
        msg = packMsg('netif_fe_interface_status_changed_t',
                      { 'handle' : dev.vif,
                        'status' : NETIF_INTERFACE_STATUS_CONNECTED,
                        'evtchn' : dev.evtchn['port2'],
                        'mac'    : dev.mac })
        self.writeRequest(msg)

    def send_be_create(self, vif):
        dev = self.devices[vif]
        msg = packMsg('netif_be_create_t',
                      { 'domid'        : self.dom,
                        'netif_handle' : dev.vif,
                        'mac'          : dev.mac })
        self.factory.writeRequest(msg)

    def send_be_disconnect(self, vif):
        dev = self.devices[vif]
        msg = packMsg('netif_be_disconnect_t',
                      { 'domid'        : self.dom,
                        'netif_handle' : dev.vif })
        self.factory.writeRequest(msg)

    def send_be_destroy(self, vif):
        print 'NetifController>send_be_destroy>', 'dom=', self.dom, 'vif=', vif
        PrettyPrint.prettyprint(self.sxpr())
        dev = self.devices[vif]
        del self.devices[vif]
        msg = packMsg('netif_be_destroy_t',
                      { 'domid'        : self.dom,
                        'netif_handle' : vif })
        self.factory.writeRequest(msg)
