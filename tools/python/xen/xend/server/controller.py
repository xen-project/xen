# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""General support for controllers, which handle devices
for a domain.
"""

from xen.xend.XendError import XendError
from messages import msgTypeName, printMsg, getMessageType

DEBUG = 0

class CtrlMsgRcvr:
    """Dispatcher class for messages on a control channel.
    Once I{registerChannel} has been called, our message types are registered
    with the channel. The channel will call I{requestReceived}
    when a request arrives if it has one of our message types.

    @ivar channel: channel to a domain
    @type channel: Channel
    @ivar majorTypes: major message types we are interested in
    @type majorTypes: {int:{int:method}}
    
    """

    def __init__(self, channel):
        self.majorTypes = {}
        self.channel = channel

    def getHandler(self, type, subtype):
        """Get the method for a type and subtype.

        @param type: major message type
        @param subtype: minor message type
        @return: method or None
        """
        method = None
        subtypes = self.majorTypes.get(type)
        if subtypes:
            method = subtypes.get(subtype)
        return method

    def addHandler(self, type, subtype, method):
        """Add a method to handle a message type and subtype.
        
        @param type: major message type
        @param subtype: minor message type
        @param method: method
        """
        subtypes = self.majorTypes.get(type)
        if not subtypes:
            subtypes = {}
            self.majorTypes[type] = subtypes
        subtypes[subtype] = method

    def getMajorTypes(self):
        """Get the list of major message types handled.
        """
        return self.majorTypes.keys()

    def requestReceived(self, msg, type, subtype):
        """Dispatch a request message to handlers.
        Called by the channel for requests with one of our types.

        @param msg:     message
        @type  msg:     xu message
        @param type:    major message type
        @type  type:    int
        @param subtype: minor message type
        @type  subtype: int
        """
        if DEBUG:
            print 'requestReceived>',
            printMsg(msg, all=True)
        responded = 0
        method = self.getHandler(type, subtype)
        if method:
            responded = method(msg)
        elif DEBUG:
            print ('requestReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self
        return responded
        

    def lostChannel(self):
        """Called when the channel to the domain is lost.
        """
        print 'CtrlMsgRcvr>lostChannel>',
        self.channel = None
    
    def registerChannel(self):
        """Register interest in our major message types with the
        channel to our domain. Once we have registered, the channel
        will call requestReceived for our messages.
        """
        if DEBUG:
            print 'CtrlMsgRcvr>registerChannel>', self.channel, self.getMajorTypes()
        if self.channel:
            self.channel.registerDevice(self.getMajorTypes(), self)
        
    def deregisterChannel(self):
        """Deregister interest in our major message types with the
        channel to our domain. After this the channel won't call
        us any more.
        """
        if self.channel:
            self.channel.deregisterDevice(self)

class DevControllerType:
    """Abstract class for device controller types.
    """

    def __init__(self, type):
        self.type = type

    def getType(self):
        """Get the device controller type name.
        """
        return self.type

    def createDevController(self, vm, recreate=False):
        """Create a device controller for a domain.
           Must be implemented in subclass.
        """
        raise NotImplementedError()

class SimpleDevControllerType(DevControllerType):
    """Device controller type that simply wraps a controller
    class and uses its constructor to create instances.
    """
    
    def __init__(self, type, devControllerClass):
        DevControllerType.__init__(self, type)
        self.devControllerClass = devControllerClass

    def createDevController(self, vm, recreate=False):
        """Create a device controller for a domain.
        """
        ctrl = self.devControllerClass(self, vm, recreate=recreate)
        ctrl.initController(recreate=recreate)
        return ctrl

class DevControllerTable:
    """Table of device controller types, indexed by type name.
    """

    def __init__(self):
        self.controllerTypes = {}

    def getDevControllerType(self, type):
        return self.controllerTypes.get(type)

    def addDevControllerType(self, dctype):
        self.controllerTypes[dctype.getType()] = dctype
        return dctype

    def delDevControllerType(self, type):
        if type in self.controllerTypes:
            del self.controllerTypes[type]

    def createDevController(self, type, vm, recreate=False):
        dctype = self.getDevControllerType(type)
        if not dctype:
            raise XendError("unknown device type: " + type)
        return dctype.createDevController(vm, recreate=recreate)

def getDevControllerTable():
    global devControllerTable
    try:
        devControllerTable
    except:
        devControllerTable = DevControllerTable()
    return devControllerTable

def addDevControllerType(dctype):
    return getDevControllerTable().addDevControllerType(dctype)
    
def addDevControllerClass(name, klass):
    ty = SimpleDevControllerType(name, klass)
    return addDevControllerType(ty)

def createDevController(name, vm, recreate=False):
    return getDevControllerTable().createDevController(name, vm, recreate=recreate)

class DevController:
    """Abstract class for a device controller attached to a domain.
    A device controller manages all the devices of a given type for a domain.
    There is exactly one device controller for each device type for
    a domain.

    """

    def __init__(self, dctype, vm, recreate=False):
        self.dctype = dctype
        self.destroyed = False
        self.vm = vm
        self.deviceId = 0
        self.devices = {}
        self.device_order = []

    def getType(self):
        return self.dctype.getType()

    def getDevControllerType(self):
        return self.dctype

    def getDomain(self):
        return self.vm.getDomain()

    def getDomainName(self):
        return self.vm.getName()

    def getChannel(self):
        chan = self.vm.getChannel()
        return chan
    
    def getDomainInfo(self):
        return self.vm

    #----------------------------------------------------------------------------
    # Subclass interface.
    # Subclasses should define the unimplemented methods..
    # Redefinitions must have the same arguments.

    def initController(self, recreate=False, reboot=False):
        self.destroyed = False
        if reboot:
            self.rebootDevices()

    def newDevice(self, id, config, recreate=False):
        """Create a device with the given config.
        Must be defined in subclass.

        @return device
        """
        raise NotImplementedError()

    def createDevice(self, config, recreate=False, change=False):
        print 'DevController>createDevice>', 'config=', config, 'recreate=', recreate, 'change=', change
        dev = self.newDevice(self.nextDeviceId(), config, recreate=recreate)
        dev.init(recreate=recreate)
        self.addDevice(dev)
        idx = self.getDeviceIndex(dev)
        recreate = self.vm.get_device_recreate(self.getType(), idx)
        dev.attach(recreate=recreate, change=change)
        print 'DevController>createDevice<'

    def configureDevice(self, id, config, change=False):
        """Reconfigure an existing device.
        May be defined in subclass."""
        dev = self.getDevice(id)
        if not dev:
            raise XendError("invalid device id: " + id)
        dev.configure(config, change=change)

    def destroyDevice(self, id, change=False, reboot=False):
        """Destroy a device.
        May be defined in subclass."""
        dev = self.getDevice(id)
        if not dev:
            raise XendError("invalid device id: " + id)
        dev.destroy(change=change, reboot=reboot)
        return dev

    def deleteDevice(self, id, change=True):
        dev = self.destroyDevice(id, change=change)
        self.removeDevice(dev)

    def destroyController(self, reboot=False):
        """Destroy all devices and clean up.
        May be defined in subclass."""
        self.destroyed = True
        self.destroyDevices(reboot=reboot)

    #----------------------------------------------------------------------------
    
    def isDestroyed(self):
        return self.destroyed

    def getDevice(self, id):
        return self.devices.get(id)

    def getDeviceByIndex(self, idx):
        if 0 <= idx < len(self.device_order):
            return self.device_order[idx]
        else:
            return None

    def getDeviceIndex(self, dev):
        return self.device_order.index(dev)

    def getDeviceIds(self):
        return [ dev.getId() for dev in self.device_order ]

    def getDevices(self):
        return self.device_order

    def getDeviceConfig(self, id):
        return self.getDevice(id).getConfig()

    def getDeviceConfigs(self):
        return [ dev.getConfig() for dev in self.device_order ]

    def getDeviceSxprs(self):
        return [ dev.sxpr() for dev in self.device_order ]

    def addDevice(self, dev):
        self.devices[dev.getId()] = dev
        self.device_order.append(dev)
        return dev

    def removeDevice(self, dev):
        if dev.getId() in self.devices:
            del self.devices[dev.getId()]
        if dev in self.device_order:
            self.device_order.remove(dev)

    def rebootDevices(self):
        print 'DevController>rebootDevices>', self
        for dev in self.getDevices():
            dev.reboot()

    def destroyDevices(self, reboot=False):
        """Destroy all devices.
        """
        for dev in self.getDevices():
            dev.destroy(reboot=reboot)

    def getMaxDeviceId(self):
        maxid = 0
        for id in self.devices:
            if id > maxid:
                maxid = id
        return maxid

    def nextDeviceId(self):
        id = self.deviceId
        self.deviceId += 1
        return id

    def getDeviceCount(self):
        return len(self.devices)

class Dev:
    """Abstract class for a device attached to a device controller.

    @ivar id:        identifier
    @type id:        int
    @ivar controller: device controller
    @type controller: DevController
    """
    
    def __init__(self, controller, id, config, recreate=False):
        self.controller = controller
        self.id = id
        self.config = config
        self.destroyed = False

    def getDomain(self):
        return self.controller.getDomain()

    def getDomainName(self):
        return self.controller.getDomainName()

    def getChannel(self):
        return self.controller.getChannel()
    
    def getDomainInfo(self):
        return self.controller.getDomainInfo()
    
    def getController(self):
        return self.controller

    def getType(self):
        return self.controller.getType()

    def getId(self):
        return self.id

    def getIndex(self):
        return self.controller.getDeviceIndex(self)

    def getConfig(self):
        return self.config

    def isDestroyed(self):
        return self.destroyed

    #----------------------------------------------------------------------------
    # Subclass interface.
    # Define methods in subclass as needed.
    # Redefinitions must have the same arguments.

    def init(self, recreate=False, reboot=False):
        """Initialization. Called on initial create (when reboot is False)
        and on reboot (when reboot is True). When xend is restarting is
        called with recreate True. Define in subclass if needed.
        """
        self.destroyed = False

    def attach(self, recreate=False, change=False):
        """Attach the device to its front and back ends.
        Define in subclass if needed.
        """
        pass

    def reboot(self):
        """Reconnect device when the domain is rebooted.
        """
        print 'Dev>reboot>', self
        self.init(reboot=True)
        self.attach()

    def sxpr(self):
        """Get the s-expression for the deivice.
        Implement in a subclass if needed.

        @return: sxpr
        """
        return self.getConfig()

    def configure(self, config, change=False):
        """Reconfigure the device.

        Implement in subclass.
        """
        raise NotImplementedError()

    def refresh(self):
        """Refresh the device..
        Default no-op. Define in subclass if needed.
        """
        pass

    def destroy(self, change=False, reboot=False):
        """Destroy the device.
        If change is True notify destruction (runtime change).
        If reboot is True the device is being destroyed for a reboot.
        Redefine in subclass if needed.
        """
        self.destroyed = True
        pass
    
    #----------------------------------------------------------------------------
