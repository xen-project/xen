# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import random

from twisted.internet import defer
#defer.Deferred.debug = 1

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
            #CMSG_NETIF_BE_CREATE : self.recv_be_create,
            #CMSG_NETIF_BE_CONNECT: self.recv_be_connect,
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

    def respond_be_connect(self, msg):
        val = unpackMsg('netif_be_connect_t', msg)
        dom = val['domid']
        vif = val['netif_handle']
        netif = self.getInstanceByDom(dom)
        if netif:
            netif.send_interface_connected(vif)
        else:
            print "respond_be_connect> unknown vif=", vif
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

    def __init__(self, ctrl, vif, config):
        controller.Dev.__init__(self, ctrl)
        self.vif = vif
        self.evtchn = None
        self.configure(config)

    def configure(self, config):
        self.config = config
        self.mac = None
        self.bridge = None
        self.script = None
        self.ipaddr = None
        
        vmac = sxp.child_value(config, 'mac')
        if not vmac: raise ValueError("invalid mac")
        mac = [ int(x, 16) for x in vmac.split(':') ]
        if len(mac) != 6: raise ValueError("invalid mac")
        self.mac = mac

        self.bridge = sxp.child_value(config, 'bridge')
        self.script = sxp.child_value(config, 'script')

        ipaddrs = sxp.children(config, elt='ip')
        for ipaddr in ipaddrs:
            self.ipaddr.append(sxp.child0(ipaddr))
        
    def sxpr(self):
        vif = str(self.vif)
        mac = self.get_mac()
        val = ['vif', ['idx', vif], ['mac', mac]]
        if self.bridge:
            val.append(['bridge', self.bridge])
        if self.script:
            val.append(['script', self.script])
        for ip in self.ipaddr:
            val.append(['ip', ip])
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
        from xen.xend import XendDomain
        xd = XendDomain.instance()
        dom = self.controller.dom
        dominfo = xd.domain_get(dom)
        name = (dominfo and dominfo.name) or ('DOM%d' % dom)
        return { 'domain': name,
                 'vif'   : self.get_vifname(), 
                 'mac'   : self.get_mac(),
                 'bridge': self.bridge,
                 'script': self.script,
                 'ipaddr': self.ipaddr, }

    def vifctl(self, op):
        """Bring the device up or down.
        """
        Vifctl.vifctl(op, **self.vifctl_params())

    def destroy(self):
        """Destroy the device's resources and disconnect from the back-end
        device controller.
        """
        def cb_destroy(val):
            self.controller.send_be_destroy(self.vif)
        self.vifctl('down')
        #d = self.controller.factory.addDeferred()
        d = defer.Deferred()
        d.addCallback(cb_destroy)
        self.controller.send_be_disconnect(self.vif, response=d)
        

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

    def addDevice(self, vif, config):
        """Add a network interface.

        vif device index
        config device configuration 

        returns device
        """
        dev = NetDev(self, vif, config)
        self.devices[vif] = dev
        return dev

    def destroy(self):
        """Destroy the controller and all devices.
        """
        self.destroyDevices()
        
    def destroyDevices(self):
        for dev in self.getDevices():
            dev.destroy()

    def attachDevice(self, vif, config, recreate=0):
        """Attach a network device.
        If vmac is None a random mac address is assigned.

        @param vif interface index
        @param vmac mac address (string)
        """
        self.addDevice(vif, config)
        d = defer.Deferred()
        if recreate:
            d.callback(self)
        else:
            self.send_be_create(vif, response=d)
        return d

    def reattach_devices(self):
        """Reattach all devices when the back-end control domain has changed.
        """
        #d = self.factory.addDeferred()
        self.send_be_create(vif)
        self.attach_fe_devices()

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
        d = defer.Deferred()
        d.addCallback(self.factory.respond_be_connect)
        self.factory.writeRequest(msg, response=d)

    def send_interface_connected(self, vif, response=None):
        dev = self.devices[vif]
        msg = packMsg('netif_fe_interface_status_changed_t',
                      { 'handle' : dev.vif,
                        'status' : NETIF_INTERFACE_STATUS_CONNECTED,
                        'evtchn' : dev.evtchn['port2'],
                        'mac'    : dev.mac })
        self.writeRequest(msg, response=response)

    def send_be_create(self, vif, response=None):
        dev = self.devices[vif]
        msg = packMsg('netif_be_create_t',
                      { 'domid'        : self.dom,
                        'netif_handle' : dev.vif,
                        'mac'          : dev.mac })
        self.factory.writeRequest(msg, response=response)

    def send_be_disconnect(self, vif, response=None):
        dev = self.devices[vif]
        msg = packMsg('netif_be_disconnect_t',
                      { 'domid'        : self.dom,
                        'netif_handle' : dev.vif })
        self.factory.writeRequest(msg, response=response)

    def send_be_destroy(self, vif, response=None):
        PrettyPrint.prettyprint(self.sxpr())
        dev = self.devices[vif]
        del self.devices[vif]
        msg = packMsg('netif_be_destroy_t',
                      { 'domid'        : self.dom,
                        'netif_handle' : vif })
        self.factory.writeRequest(msg, response=response)
