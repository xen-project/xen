# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""General support for controllers, which handle devices
for a domain.
"""

from twisted.internet import defer
#defer.Deferred.debug = 1

import channel
from messages import msgTypeName, printMsg

DEBUG = 0

class Responder:
    """Handler for a response to a message with a specified id.
    """

    def __init__(self, mid, deferred):
        """Create a responder.

        @param mid: message id of response to handle
        @type  mid: int
        @param deferred: deferred object holding the callbacks
        @type  deferred: Deferred
        """
        self.mid = mid
        self.deferred = deferred

    def responseReceived(self, msg):
        """Entry point called when a response message with the right id arrives.
        Calls callback on I{self.deferred} with the message.

        @param msg: response message
        @type  msg: xu message
        """
        if self.deferred.called: return
        self.deferred.callback(msg)

    def error(self, err):
        """Entry point called when there has been an error.
        Calls errback on I{self.deferred} with the error.

        @param err: error
        @type  err: Exception
        """
        if self.deferred.called: return
        self.deferred.errback(err)

class CtrlMsgRcvr:
    """Abstract class for things that deal with a control interface to a domain.
    Once I{registerChannel} has been called, our message types are registered
    with the channel to the domain. The channel will call I{requestReceived}
    when a request arrives, or I{responseReceived} when a response arrives,
    if they have one of our message types.

    @ivar dom: the domain we are a control interface for
    @type dom: int
    @ivar majorTypes: major message types we are interested in
    @type majorTypes: {int:{int:method}}
    @ivar timeout: timeout (in seconds) for message handlers
    @type timeout: int
    
    @ivar channel: channel to the domain
    @type channel: Channel
    @ivar idx: channel index
    @ivar idx: string
    @ivar responders: table of message response handlers
    @type responders: {int:Responder}
    """

    def __init__(self, remote_port = 0):
        self.channelFactory = channel.channelFactory()
        self.majorTypes = {}
        self.dom = None
        self.channel = None
        self.idx = None
        self.responders = {}
        self.timeout = 10
        self.remote_port = remote_port

    def setTimeout(self, timeout):
        self.timeout = timeout

    def getMethod(self, type, subtype):
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

    def addMethod(self, type, subtype, method):
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
            printMsg(msg, all=1)
        responded = 0
        method = self.getMethod(type, subtype)
        if method:
            responded = method(msg, 1)
        elif DEBUG:
            print ('requestReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self
        return responded
        
    def responseReceived(self, msg, type, subtype):
        """Dispatch a response to handlers.
        Called by the channel for responses with one of our types.
        
        First looks for a message responder for the message's id.
        See L{callResponders}, L{addResponder}.
        If there is no responder, looks for a message handler for
        the message type/subtype.

        @param msg:     message
        @type  msg:     xu message
        @param type:    major message type
        @type  type:    int
        @param subtype: minor message type
        @type  subtype: int
        """
        if DEBUG:
            print 'responseReceived>',
            printMsg(msg, all=1)
        if self.callResponders(msg):
            return
        method = self.getMethod(type, subtype)
        if method:
            method(msg, 0)
        elif DEBUG:
            print ('responseReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self

    def addResponder(self, mid, deferred):
        """Add a responder for a message id.
        The I{deferred} is called with callback(msg) when a response
        with message id I{mid} arrives.

        Responders have a timeout set and I{deferred} will error
        on expiry.

        @param mid:      message id of response expected
        @type  mid:      int
        @param deferred: handler for the response
        @type  deferred: Deferred
        @return: responder
        @rtype:  Responder
        """
        resp = Responder(mid, deferred)
        self.responders[resp.mid] = resp
        if self.timeout > 0:
            deferred.setTimeout(self.timeout)
        return resp

    def callResponders(self, msg):
        """Call any waiting responders for a response message.
        Looks for a responder registered for the message's id.
        See L{addResponder}.

        @param msg: response message
        @type  msg: xu message
        @return: 1 if there was a responder for the message, 0 otherwise
        @rtype : bool
        """
        hdr = msg.get_header()
        mid = hdr['id']
        handled = 0
        resp = self.responders.get(mid)
        if resp:
            handled = 1
            resp.responseReceived(msg)
            del self.responders[mid]
        # Clean up called responders.
        for resp in self.responders.values():
            if resp.deferred.called:
                del self.responders[resp.mid]
        return handled

    def lostChannel(self):
        """Called when the channel to the domain is lost.
        """
        pass
    
    def registerChannel(self):
        """Register interest in our major message types with the
        channel to our domain. Once we have registered, the channel
        will call requestReceived or responseReceived for our messages.
        """
        self.channel = self.channelFactory.domChannel(self.dom,
                                                      self.remote_port)
        self.idx = self.channel.getIndex()
        if self.majorTypes:
            self.channel.registerDevice(self.getMajorTypes(), self)
        
    def deregisterChannel(self):
        """Deregister interest in our major message types with the
        channel to our domain. After this the channel won't call
        us any more.
        """
        if self.channel:
            self.channel.deregisterDevice(self)
            self.channel = None

    def produceRequests(self):
        """Produce any queued requests.

        @return: number produced
        @rtype:  int
        """
        return 0

    def writeRequest(self, msg, response=None):
        """Write a request to the channel.

        @param msg:      request message
        @type  msg:      xu message
        @param response: response handler
        @type  response: Deferred
        """
        if self.channel:
            if DEBUG:
                print 'CtrlMsgRcvr>writeRequest>',
                printMsg(msg, all=1)
            if response:
                self.addResponder(msg.get_header()['id'], response)
            self.channel.writeRequest(msg)
        else:
            print 'CtrlMsgRcvr>writeRequest>', 'no channel!', self

    def writeResponse(self, msg):
        """Write a response to the channel. This acknowledges
        a request message.

        @param msg:      message
        @type  msg:      xu message
        """
        if self.channel:
            if DEBUG:
                print 'CtrlMsgRcvr>writeResponse>',
                printMsg(msg, all=0)
            self.channel.writeResponse(msg)
        else:
            print 'CtrlMsgRcvr>writeResponse>', 'no channel!', self
            
class ControllerFactory:
    """Abstract class for factories creating controllers for a domain.
    Maintains a table of controllers.

    @ivar controllers: mapping of index to controller instance
    @type controllers: {String: Controller}
    @ivar dom: domain
    @type dom: int
    """

    def __init__(self):
        self.controllers = {}
        
    def addController(self, controller):
        """Add a controller instance (under its index).
        """
        self.controllers[controller.idx] = controller

    def getControllers(self):
        """Get a list of all controllers.
        """
        return self.controllers.values()

    def getControllerByIndex(self, idx):
        """Get a controller from its index.
        """
        return self.controllers.get(idx)

    def getControllerByDom(self, dom):
        """Get the controller for the given domain.

        @param dom: domain id
        @type  dom: int
        @return: controller or None
        """
        for inst in self.controllers.values():
            if inst.dom == dom:
                return inst
        return None

    def getController(self, dom):
        """Create or find the controller for a domain.

        @param dom:      domain
        @return: controller
        """
        ctrl = self.getControllerByDom(dom)
        if ctrl is None:
            ctrl = self.createController(dom)
            self.addController(ctrl)
        return ctrl
    
    def createController(self, dom):
        """Create a controller. Define in a subclass.

        @param dom: domain
        @type  dom: int
        @return: controller instance
        @rtype:  Controller (or subclass)
        """
        raise NotImplementedError()

    def delController(self, controller):
        """Delete a controller instance from the table.

        @param controller: controller instance
        """
        if controller.idx in self.controllers:
            del self.controllers[controller.idx]

    def controllerClosed(self, controller):
        """Callback called when a controller is closed (usually by the controller).
        
        @param controller: controller instance
        """
        self.delController(controller)

class Controller(CtrlMsgRcvr):
    """Abstract class for a device controller attached to a domain.

    @ivar factory: controller factory
    @type factory: ControllerFactory
    @ivar dom:     domain
    @type dom:     int
    @ivar channel: channel to the domain
    @type channel: Channel
    @ivar idx:     channel index
    @type idx:     String
    """

    def __init__(self, factory, dom, remote_port=0):
        CtrlMsgRcvr.__init__(self, remote_port=remote_port)
        self.factory = factory
        self.dom = int(dom)
        self.channel = None
        self.idx = None

    def close(self):
        """Close the controller.
        """
        self.lostChannel()

    def lostChannel(self):
        """The controller channel has been lost.
        """
        self.deregisterChannel()
        self.factory.controllerClosed(self)

class SplitControllerFactory(ControllerFactory):
    """Abstract class for factories creating split controllers for a domain.
    Maintains a table of backend controllers.
    """

    def __init__(self):
        ControllerFactory.__init__(self)
        self.backendControllers = {}

    def getBackendControllers(self):
        return self.backendControllers.values()

    def getBackendControllerByDomain(self, dom):
        """Get the backend controller for a domain if there is one.

        @param dom: backend domain
        @return: backend controller
        """
        return self.backendControllers.get(dom)

    def getBackendController(self, dom):
        """Get the backend controller for a domain, creating
        if necessary.

        @param dom: backend domain
        @return: backend controller
        """
        b = self.getBackendControllerByDomain(dom)
        if b is None:
            b = self.createBackendController(dom)
            self.backendControllers[b.dom] = b
        return b

    def createBackendController(self, dom):
        """Create a backend controller. Define in a subclass.

        @param dom: backend domain
        @return: backend controller
        """
        raise NotImplementedError()

    def delBackendController(self, ctrlr):
        """Remove a backend controller.

        @param ctrlr: backend controller
        """
        if ctrlr.dom in self.backendControllers:
            del self.backendControllers[ctrlr.dom]

    def backendControllerClosed(self, ctrlr):
        """Callback called when a backend is closed.
        """
        self.delBackendController(ctrlr)
        
    def createBackendInterface(self, ctrl, dom, handle):
        """Create a backend interface. Define in a subclass.

        @param ctrl: frontend controller
        @param dom: backend domain
        @return: backend interface
        """
        raise NotImplementedError()

class BackendController(Controller):
    """Abstract class for a backend device controller attached to a domain.

    @ivar factory: backend controller factory
    @type factory: BackendControllerFactory
    @ivar dom:     backend domain
    @type dom:     int
    @ivar channel: channel to the domain
    @type channel: Channel
    """

    
    def __init__(self, factory, dom):
        CtrlMsgRcvr.__init__(self)
        self.factory = factory
        self.dom = int(dom)
        self.channel = None
        self.backendInterfaces = {}
        
    def close(self):
        self.lostChannel()

    def lostChannel(self):
        self.deregisterChannel()
        self.backend.backendClosed(self)

    def registerInterface(self, intf):
        key = intf.getInterfaceKey()
        self.backendInterfaces[key] = intf

    def deregisterInterface(self, intf):
        key = intf.getInterfaceKey()
        if key in self.backendInterfaces:
            del self.backendInterfaces[key]

    def getInterface(self, dom, handle):
        key = (dom, handle)
        return self.backendInterfaces.get(key)

        
    def createBackendInterface(self, ctrl, dom, handle):
        """Create a backend interface. Define in a subclass.

        @param ctrl: controller
        @param dom: backend domain
        @param handle: backend handle
        """
        raise NotImplementedError()

    
class BackendInterface:
    """Abstract class for a domain's interface onto a backend controller.
    """

    def __init__(self, controller, dom, handle):
        """

        @param controller: front-end controller
        @param dom:        back-end domain
        @param handle:     back-end interface handle
        """
        self.factory = controller.factory
        self.controller = controller
        self.dom = int(dom)
        self.handle = handle
        self.backend = self.getBackendController()

    def registerInterface(self):
        self.backend.registerInterface(self)

    def getInterfaceKey(self):
        return (self.controller.dom, self.handle)

    def getBackendController(self):
        return self.factory.getBackendController(self.dom)

    def writeRequest(self, msg, response=None):
        return self.backend.writeRequest(msg, response=response)

    def writeResponse(self, msg):
        return self.backend.writeResponse(msg)
    
    def close(self):
        self.backend.deregisterInterface(self)
        self.controller.backendInterfaceClosed(self)
        
class SplitController(Controller):
    """Abstract class for a device controller attached to a domain.
    A SplitController manages a BackendInterface for each backend domain
    it has at least one device for.
    """

    def __init__(self, factory, dom):
        Controller.__init__(self, factory, dom)
        self.backendInterfaces = {}
        self.backendHandle = 0
        self.devices = {}

    def getDevices(self):
        """Get a list of the devices..
        """
        return self.devices.values()

    def delDevice(self, idx):
        """Remove the device with the given index from the device table.

        @param idx device index
        """
        if idx in self.devices:
            del self.devices[idx]

    def getDevice(self, idx):
        """Get the device with a given index.

        @param idx device index
        @return device (or None)
        """
        return self.devices.get(idx)

    def findDevice(self, idx):
        """Find a device. If idx is non-negative,
        get the device with the given index. If idx is negative,
        look for the device with least index greater than -idx - 2.
        For example, if idx is -2, look for devices with index
        greater than 0, i.e. 1 or above.

        @param idx device index
        @return device (or None)
        """
        if idx < 0:
            idx = -idx - 2
            val = None
            for dev in self.devices.values():
                if dev.idx <= idx: continue
                if (val is None) or (dev.idx < val.idx):
                    val = dev
        else:
            val = getDevice(idx)
        return val

    def getMaxDeviceIdx(self):
        """Get the maximum id used by devices.

        @return maximum idx
        """
        maxIdx = 0
        for dev in self.devices:
            if dev.idx > maxIdx:
                maxIdx = dev.idx
        return maxIdx
        
    def getBackendInterfaces(self):
        return self.backendInterfaces.values()

    def getBackendInterfaceByHandle(self, handle):
        for b in self.getBackendInterfaces():
            if b.handle == handle:
                return b
        return None

    def getBackendInterfaceByDomain(self, dom):
        return self.backendInterfaces.get(dom)

    def getBackendInterface(self, dom):
        """Get the backend interface for a domain.

        @param dom: domain
        @return: backend controller
        """
        b = self.getBackendInterfaceByDomain(dom)
        if b is None:
            handle = self.backendHandle
            self.backendHandle += 1
            b = self.factory.createBackendInterface(self, dom, handle)
            b.registerInterface()
            self.backendInterfaces[b.dom] = b
        return b

    def delBackendInterface(self, ctrlr):
        """Remove a backend controller.

        @param ctrlr: backend controller
        """
        if ctrlr.dom in self.backendInterfaces:
            del self.backendInterfaces[ctrlr.dom]

    def backendInterfaceClosed(self, ctrlr):
        """Callback called when a backend is closed.
        """
        self.delBackendInterface(ctrlr)
        
class Dev:
    """Abstract class for a device attached to a device controller.

    @ivar idx:        identifier
    @type idx:        String
    @ivar controller: device controller
    @type controller: DeviceController
    @ivar props:      property table
    @type props:      { String: value }
    """
    
    def __init__(self, idx, controller):
        self.idx = str(idx)
        self.controller = controller
        self.props = {}

    def getidx(self):
        return self.idx

    def setprop(self, k, v):
        self.props[k] = v

    def getprop(self, k, v=None):
        return self.props.get(k, v)

    def hasprop(self, k):
        return k in self.props

    def delprop(self, k):
        if k in self.props:
            del self.props[k]

    def sxpr(self):
        """Get the s-expression for the deivice.
        Implement in a subclass.

        @return: sxpr
        """
        raise NotImplementedError()

    def configure(self, config, change=0):
        raise NotImplementedError()

class SplitDev(Dev):

    def __init__(self, idx, controller):
        Dev.__init__(self, idx, controller)
        self.backendDomain = 0
        self.index = None

    def getBackendInterface(self):
        return self.controller.getBackendInterface(self.backendDomain)

    def getIndex(self):
        return self.index

    def setIndex(self, index):
        self.index = index



    
