#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
#============================================================================

"""General support for controllers, which handle devices
for a domain.
"""

from xen.xend.XendError import XendError
from xen.xend.xenstore import DBVar

DEBUG = 0

class DevControllerTable:
    """Table of device controller classes, indexed by type name.
    """

    def __init__(self):
        self.controllerClasses = {}

    def getDevControllerClass(self, type):
        return self.controllerClasses.get(type)

    def addDevControllerClass(self, cls):
        self.controllerClasses[cls.getType()] = cls

    def delDevControllerClass(self, type):
        if type in self.controllerClasses:
            del self.controllerClasses[type]

    def createDevController(self, type, vm, recreate=False):
        cls = self.getDevControllerClass(type)
        if not cls:
            raise XendError("unknown device type: " + str(type))
        return cls.createDevController(vm, recreate=recreate)

def getDevControllerTable():
    """Singleton constructor for the controller table.
    """
    global devControllerTable
    try:
        devControllerTable
    except:
        devControllerTable = DevControllerTable()
    return devControllerTable

def addDevControllerClass(name, cls):
    """Add a device controller class to the controller table.
    """
    cls.type = name
    getDevControllerTable().addDevControllerClass(cls)


def isDevControllerClass(name):
    """@return True if a device controller class has been registered with
    the controller table under the given name."""
    return name in getDevControllerTable().controllerClasses


def createDevController(name, vm, recreate=False):
    return getDevControllerTable().createDevController(name, vm, recreate=recreate)

class DevController:
    """Abstract class for a device controller attached to a domain.
    A device controller manages all the devices of a given type for a domain.
    There is exactly one device controller for each device type for
    a domain.

    """

    # State:
    # controller/<type> : for controller
    # device/<type>/<id>   : for each device

    def createDevController(cls, vm, recreate=False):
        """Class method to create a dev controller.
        """
        ctrl = cls(vm, recreate=recreate)
        ctrl.initController(recreate=recreate)
        ctrl.exportToDB()
        return ctrl

    createDevController = classmethod(createDevController)

    def getType(cls):
        return cls.type

    getType = classmethod(getType)

    __exports__ = [
        DBVar('type',      'str'),
        DBVar('destroyed', 'bool'),
        ]

    # Set when registered.
    type = None

    def __init__(self, vm, recreate=False):
        self.destroyed = False
        self.vm = vm
        self.db = self.getDB()
        self.deviceId = 0
        self.devices = {}
        self.device_order = []

    def getDB(self):
        """Get the db node to use for a controller.
        """
        return self.vm.db.addChild("/controller/%s" % self.getType())

    def getDevDB(self, id):
        """Get the db node to use for a device.
        """
        return self.vm.db.addChild("/device/%s/%s" % (self.getType(), id))

    def exportToDB(self, save=False):
        self.db.exportToDB(self, fields=self.__exports__, save=save)

    def importFromDB(self):
        self.db.importFromDB(self, fields=self.__exports__)

    def getDevControllerType(self):
        return self.dctype

    def getDomain(self):
        return self.vm.getDomain()

    def getDomainName(self):
        return self.vm.getName()

    def getDomainInfo(self):
        return self.vm

    #----------------------------------------------------------------------------
    # Subclass interface.
    # Subclasses should define the unimplemented methods..
    # Redefinitions must have the same arguments.

    def initController(self, recreate=False, reboot=False):
        """Initialise the controller. Called when the controller is
        first created, and again after the domain is rebooted (with reboot True).
        If called with recreate True (and reboot False) the controller is being
        recreated after a xend restart.

        As this can be a re-init (after reboot) any controller state should
        be reset. For example the destroyed flag.
        """
        self.destroyed = False
        if reboot:
            self.rebootDevices()

    def newDevice(self, id, config, recreate=False):
        """Create a device with the given config.
        Must be defined in subclass.
        Called with recreate True when the device is being recreated after a
        xend restart.

        @return device
        """
        raise NotImplementedError()

    def createDevice(self, config, recreate=False, change=False):
        """Create a device and attach to its front- and back-ends.
        If recreate is true the device is being recreated after a xend restart.
        If change is true the device is a change to an existing domain,
        i.e. it is being added at runtime rather than when the domain is created.
        """
        dev = self.newDevice(self.nextDeviceId(), config, recreate=recreate)
        if self.vm.recreate:
            dev.importFromDB()
        dev.init(recreate=recreate)
        self.addDevice(dev)
        if not recreate:
            dev.exportToDB()
        dev.attach(recreate=recreate, change=change)
        dev.exportToDB()

        return dev

    def configureDevice(self, id, config, change=False):
        """Reconfigure an existing device.
        May be defined in subclass."""
        dev = self.getDevice(id, error=True)
        dev.configure(config, change=change)

    def destroyDevice(self, id, change=False, reboot=False):
        """Destroy a device.
        May be defined in subclass.

        If reboot is true the device is being destroyed for a domain reboot.

        The device is not deleted, since it may be recreated later.
        """
        dev = self.getDevice(id, error=True)
        dev.destroy(change=change, reboot=reboot)
        return dev

    def deleteDevice(self, id, change=True):
        """Destroy a device and delete it.
        Normally called to remove a device from a domain at runtime.
        """
        dev = self.destroyDevice(id, change=change)
        self.removeDevice(dev)

    def destroyController(self, reboot=False):
        """Destroy all devices and clean up.
        May be defined in subclass.
        If reboot is true the controller is being destroyed for a domain reboot.
        Called at domain shutdown.
        """
        self.destroyed = True
        self.destroyDevices(reboot=reboot)

    #----------------------------------------------------------------------------
    
    def isDestroyed(self):
        return self.destroyed

    def getDevice(self, id, error=False):
        dev = self.devices.get(int(id))
        if error and not dev:
            raise XendError("invalid device id: " + str(id))
        return dev

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
    
    # ./status       : need 2: actual and requested?
    # down-down: initial.
    # up-up: fully up.
    # down-up: down requested, still up. Watch front and back, when both
    # down go to down-down. But what if one (or both) is not connected?
    # Still have front/back trees with status? Watch front/status, back/status?
    # up-down: up requested, still down.
    # Back-end watches ./status, front/status
    # Front-end watches ./status, back/status
    # i.e. each watches the other 2.
    # Each is status/request status/actual?
    #
    # backend?
    # frontend?

    __exports__ = [
        DBVar('id',        ty='int'),
        DBVar('type',      ty='str'),
        DBVar('config',    ty='sxpr'),
        DBVar('destroyed', ty='bool'),
        ]

    def __init__(self, controller, id, config, recreate=False):
        self.controller = controller
        self.id = id
        self.config = config
        self.destroyed = False
        self.type = self.getType()

        self.db = controller.getDevDB(id)

    def exportToDB(self, save=False):
        self.db.exportToDB(self, fields=self.__exports__, save=save)

    def importFromDB(self):
        self.db.importFromDB(self, fields=self.__exports__)

    def getDomain(self):
        return self.controller.getDomain()

    def getDomainName(self):
        return self.controller.getDomainName()

    def getDomainInfo(self):
        return self.controller.getDomainInfo()
    
    def getController(self):
        return self.controller

    def getType(self):
        return self.controller.getType()

    def getId(self):
        return self.id

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

        Device instance variables must be defined in the class constructor,
        but given null or default values. The real values should be initialised
        in this method. This allows devices to be re-initialised.

        Since this can be called to re-initialise a device any state flags
        should be reset.
        """
        self.destroyed = False

    def attach(self, recreate=False, change=False):
        """Attach the device to its front and back ends.
        Define in subclass if needed.
        """
        pass

    def reboot(self):
        """Reconnect the device when the domain is rebooted.
        """
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

        Called at domain shutdown and when a device is deleted from
        a running domain (with change True).
        """
        self.destroyed = True
        pass
    
    #----------------------------------------------------------------------------
