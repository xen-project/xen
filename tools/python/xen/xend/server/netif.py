# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import random

from twisted.internet import defer

from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend import Vifctl

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

        dom      domain
        recreate if true this is a recreate (xend restarted)

        returns netif controller
        """
        netif = self.getInstanceByDom(dom)
        if netif is None:
            netif = NetifController(self, dom)
            self.addInstance(netif)
        return netif

    def getDomainDevices(self, dom):
        """Get the network device controllers for a domain.

        dom  domain
        
        returns netif controller
        """
        netif = self.getInstanceByDom(dom)
        return (netif and netif.getDevices()) or []

    def getDomainDevice(self, dom, vif):
        """Get a virtual network interface device for a domain.

        dom domain
        vif virtual interface index

        returns NetDev
        """
        netif = self.getInstanceByDom(dom)
        return (netif and netif.getDevice(vif)) or None
        
    def setControlDomain(self, dom, recreate=0):
        """Set the 'back-end' device driver domain.

        dom      domain
        recreate if true this is a recreate (xend restarted)
        """
        if self.dom == dom: return
        self.deregisterChannel()
        if not recreate:
            self.attached = 0
        self.dom = dom
        self.registerChannel()

    def getControlDomain(self):
        """Get the domain id of the back-end control domain.
        """
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

class NetDev(controller.Dev):
    """Info record for a network device.
    """

    def __init__(self, ctrl, vif, mac):
        controller.Dev.__init__(self, ctrl)
        self.vif = vif
        self.mac = mac
        self.evtchn = None
        self.bridge = None
        self.ipaddr = []

    def sxpr(self):
        vif = str(self.vif)
        mac = self.get_mac()
        val = ['netdev', ['vif', vif], ['mac', mac]]
        if self.bridge:
            val.append(['bridge', self.bridge])
        if self.evtchn:
            val.append(['evtchn',
                        self.evtchn['port1'],
                        self.evtchn['port2']])
        return val

    def get_vifname(self):
        """Get the virtual interface device name.
        """
        return "vif%d.%d" % (self.controller.dom, self.vif)

    def get_mac(self):
        """Get the MAC address as a string.
        """
        return ':'.join(map(lambda x: "%x" % x, self.mac))

    def vifctl_params(self):
        return { 'mac'   : self.get_mac(),
                 'bridge': self.bridge,
                 'ipaddr': self.ipaddr }

    def up(self, bridge=None, ipaddr=[]):
        """Bring the device up.

        bridge ethernet bridge to connect to
        ipaddr list of ipaddrs to filter using iptables
        """
        self.bridge = bridge
        self.ipaddr = ipaddr
        Vifctl.up(self.get_vifname(), **self.vifctl_params())

    def down(self):
        """Bring the device down.
        """
        Vifctl.down(self.get_vifname(), **self.vifctl_params())

    def destroy(self):
        """Destroy the device's resources and disconnect from the back-end
        device controller.
        """
        def cb_destroy(val):
            self.controller.send_be_destroy(self.vif)
        self.down()
        d = self.controller.factory.addDeferred()
        d.addCallback(cb_destroy)
        self.controller.send_be_disconnect(self.vif)
        

class NetifController(controller.Controller):
    """Network interface controller. Handles all network devices for a domain.
    """
    
    def __init__(self, factory, dom):
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

    def sxpr(self):
        val = ['netif', ['dom', self.dom]]
        return val
    
    def randomMAC(self):
        """Generate a random MAC address.

        Uses OUI (Organizationally Unique Identifier) AA:00:00, an
        unassigned one that used to belong to DEC. The OUI list is
        available at 'standards.ieee.org'.

        The remaining 3 fields are random, with the first bit of the first
        random field set 0.

        returns array of 6 ints
        """
        mac = [ 0xaa, 0x00, 0x00,
                random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff) ]
        return mac

    def lostChannel(self):
        """Method called when the channel has been lost.
        """
        controller.Controller.lostChannel(self)

    def getDevices(self):
        """Get a list of the devices.
        """
        return self.devices.values()

    def getDevice(self, vif):
        """Get a device.

        vif device index

        returns device (or None)
        """
        return self.devices.get(vif)

    def addDevice(self, vif, vmac):
        """Add a network interface. If vmac is None a random MAC is
        assigned. If specified, vmac must be a string of the form
        XX:XX:XX:XX:XX where X is hex digit.

        vif device index
        vmac device MAC 

        returns device
        """
        if vmac is None:
            mac = self.randomMAC()
        else:
            mac = [ int(x, 16) for x in vmac.split(':') ]
        if len(mac) != 6: raise ValueError("invalid mac")
        dev = NetDev(self, vif, mac)
        self.devices[vif] = dev
        return dev

    def destroy(self):
        """Destroy the controller and all devices.
        """
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
        PrettyPrint.prettyprint(self.sxpr())
        dev = self.devices[vif]
        del self.devices[vif]
        msg = packMsg('netif_be_destroy_t',
                      { 'domid'        : self.dom,
                        'netif_handle' : vif })
        self.factory.writeRequest(msg)
