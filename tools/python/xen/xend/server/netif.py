# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Support for virtual network interfaces.
"""

import random

from twisted.internet import defer
#defer.Deferred.debug = 1

from xen.xend import sxp
from xen.xend import Vifctl
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log
from xen.xend import XendVnet
from xen.xend.XendRoot import get_component

import channel
import controller
from messages import *

class NetifBackendController(controller.BackendController):
    """Handler for the 'back-end' channel to a device driver domain.
    """
    
    def __init__(self, factory, dom):
        controller.BackendController.__init__(self, factory, dom)
        self.addMethod(CMSG_NETIF_BE,
                       CMSG_NETIF_BE_DRIVER_STATUS_CHANGED,
                       self.recv_be_driver_status_changed)
        self.registerChannel()

    def recv_be_driver_status_changed(self, msg, req):
        val = unpackMsg('netif_be_driver_status_changed_t', msg)
        status = val['status']

class NetifControllerFactory(controller.SplitControllerFactory):
    """Factory for creating network interface controllers.
    """

    def __init__(self):
        controller.ControllerFactory.__init__(self)

    def createInstance(self, dom, recreate=0, backend=0):
        """Create or find the network interface controller for a domain.

        @param dom:      domain
        @param recreate: if true this is a recreate (xend restarted)
        @return: netif controller
        """
        netif = self.getInstanceByDom(dom)
        if netif is None:
            netif = NetifController(self, dom, backend=backend)
            self.addInstance(netif)
        return netif

    def getDomainDevices(self, dom):
        """Get the network device controllers for a domain.

        @param dom:  domain
        @return: netif controller list
        """
        netif = self.getInstanceByDom(dom)
        return (netif and netif.getDevices()) or []

    def getDomainDevice(self, dom, vif):
        """Get a virtual network interface device for a domain.

        @param dom: domain
        @param vif: virtual interface index
        @return: NetDev
        """
        netif = self.getInstanceByDom(dom)
        return (netif and netif.getDevice(vif)) or None
        
    def createBackendController(self, dom):
        return NetifBackendController(self, dom)

class NetDev(controller.Dev):
    """Info record for a network device.
    """

    def __init__(self, ctrl, vif, config):
        controller.Dev.__init__(self, vif, ctrl)
        self.vif = vif
        self.evtchn = None
        self.configure(config)

    def getBackendController(self):
        return self.controller.backendController

    def configure(self, config):
        self.config = config
        self.mac = None
        self.bridge = None
        self.script = None
        self.ipaddr = []
        
        vmac = sxp.child_value(config, 'mac')
        if not vmac: raise XendError("invalid mac")
        mac = [ int(x, 16) for x in vmac.split(':') ]
        if len(mac) != 6: raise XendError("invalid mac")
        self.mac = mac

        self.bridge = sxp.child_value(config, 'bridge')
        self.script = sxp.child_value(config, 'script')

        ipaddrs = sxp.children(config, elt='ip')
        for ipaddr in ipaddrs:
            self.ipaddr.append(sxp.child0(ipaddr))
        
    def sxpr(self):
        vif = str(self.vif)
        mac = self.get_mac()
        val = ['vif',
               ['idx', self.idx],
               ['vif', vif],
               ['mac', mac]]
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
        return ':'.join(map(lambda x: "%02x" % x, self.mac))

    def vifctl_params(self, vmname=None):
        """Get the parameters to pass to vifctl.
        """
        dom = self.controller.dom
        if vmname is None:
            xd = get_component('xen.xend.XendDomain')
            try:
                vm = xd.domain_lookup(dom)
                vmname = vm.name
            except:
                vmname = 'DOM%d' % dom
        return { 'domain': vmname,
                 'vif'   : self.get_vifname(), 
                 'mac'   : self.get_mac(),
                 'bridge': self.bridge,
                 'script': self.script,
                 'ipaddr': self.ipaddr, }

    def vifctl(self, op, vmname=None):
        """Bring the device up or down.
        The vmname is needed when bringing a device up for a new domain because
        the domain is not yet in the table so we can't look its name up.

        @param op: operation name (up, down)
        @param vmname: vmname
        """
        Vifctl.vifctl(op, **self.vifctl_params(vmname=vmname))
        vnet = XendVnet.instance().vnet_of_bridge(self.bridge)
        if vnet:
            vnet.vifctl(op, self.get_vifname(), self.get_mac())

    def attach(self, d):
        print 'attach>', d
        self.send_be_create(response=d)

    def send_be_create(self, response=None):
        msg = packMsg('netif_be_create_t',
                      { 'domid'        : self.controller.dom,
                        'netif_handle' : self.vif,
                        'mac'          : self.mac })
        self.getBackendController().writeRequest(msg, response=response)

    def destroy(self):
        """Destroy the device's resources and disconnect from the back-end
        device controller.
        """
        def cb_destroy(val):
            self.send_be_destroy()
        log.debug("Destroying vif domain=%d vif=%d", self.controller.dom, self.vif)
        self.vifctl('down')
        d = defer.Deferred()
        d.addCallback(cb_destroy)
        self.send_be_disconnect(response=d)

    def send_be_disconnect(self, response=None):
        msg = packMsg('netif_be_disconnect_t',
                      { 'domid'        : self.controller.dom,
                        'netif_handle' : self.vif })
        self.getBackendController().writeRequest(msg, response=response)

    def send_be_destroy(self, response=None):
        msg = packMsg('netif_be_destroy_t',
                      { 'domid'        : self.controller.dom,
                        'netif_handle' : self.vif })
        self.controller.delDevice(self.vif)
        self.getBackendController().writeRequest(msg, response=response)
    
    def recv_fe_interface_connect(self, val, req):
        if not req: return
        self.evtchn = channel.eventChannel(0, self.controller.dom)
        msg = packMsg('netif_be_connect_t',
                      { 'domid'          : self.controller.dom,
                        'netif_handle'   : self.vif,
                        'evtchn'         : self.evtchn['port1'],
                        'tx_shmem_frame' : val['tx_shmem_frame'],
                        'rx_shmem_frame' : val['rx_shmem_frame'] })
        d = defer.Deferred()
        d.addCallback(self.respond_be_connect)
        self.getBackendController().writeRequest(msg, response=d)
        
    def respond_be_connect(self, msg):
        val = unpackMsg('netif_be_connect_t', msg)
        dom = val['domid']
        vif = val['netif_handle']
        print 'respond_be_connect>', '     dom=', dom, '     vif=', vif
        print 'respond_be_connect>', 'self.dom=', self.controller.dom, 'self.vif=', self.vif
        msg = packMsg('netif_fe_interface_status_changed_t',
                      { 'handle' : self.vif,
                        'status' : NETIF_INTERFACE_STATUS_CONNECTED,
                        'evtchn' : self.evtchn['port2'],
                        'mac'    : self.mac })
        self.controller.writeRequest(msg)

    def attach_fe_device(self):
        msg = packMsg('netif_fe_interface_status_changed_t',
                      { 'handle' : self.vif,
                        'status' : NETIF_INTERFACE_STATUS_DISCONNECTED,
                        'evtchn' : 0,
                        'mac'    : self.mac })
        self.controller.writeRequest(msg)
        
class NetifController(controller.SplitController):
    """Network interface controller. Handles all network devices for a domain.
    """
    
    def __init__(self, factory, dom, backend):
        controller.SplitController.__init__(self, factory, dom, backend)
        self.devices = {}
        self.addMethod(CMSG_NETIF_FE,
                       CMSG_NETIF_FE_DRIVER_STATUS_CHANGED,
                       self.recv_fe_driver_status_changed)
        self.addMethod(CMSG_NETIF_FE,
                       CMSG_NETIF_FE_INTERFACE_CONNECT,
                       self.recv_fe_interface_connect)
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

        @param vif: device index
        @return: device (or None)
        """
        return self.devices.get(vif)

    def addDevice(self, vif, config):
        """Add a network interface.

        @param vif: device index
        @param config: device configuration 
        @return: device
        """
        dev = NetDev(self, vif, config)
        self.devices[vif] = dev
        return dev

    def delDevice(self, vif):
        if vif in self.devices:
            del self.devices[vif]

    def destroy(self):
        """Destroy the controller and all devices.
        """
        self.destroyDevices()
        
    def destroyDevices(self):
        """Destroy all devices.
        """
        for dev in self.getDevices():
            dev.destroy()

    def attachDevice(self, vif, config, recreate=0):
        """Attach a network device.

        @param vif: interface index
        @param config: device configuration
        @param recreate: recreate flag (true after xend restart)
        @return: deferred
        """
        dev = self.addDevice(vif, config)
        d = defer.Deferred()
        if recreate:
            d.callback(self)
        else:
            dev.attach(d)
        return d

    def recv_fe_driver_status_changed(self, msg, req):
        if not req: return
        msg = packMsg('netif_fe_driver_status_changed_t',
                      { 'status'        : NETIF_DRIVER_STATUS_UP,
                        'nr_interfaces' : len(self.devices) })
        self.writeRequest(msg)
        for dev in self.devices.values():
            dev.attach_fe_device()
    
    def recv_fe_interface_connect(self, msg, req):
        val = unpackMsg('netif_fe_interface_connect_t', msg)
        vif = val['handle']
        dev = self.devices.get(vif)
        if dev:
            dev.recv_fe_interface_connect(val, req)
        else:
            log.error('Received netif_fe_interface_connect for unknown vif: '+vif)

