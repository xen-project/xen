# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""General support for controllers, which handle devices
for a domain.
"""

from twisted.internet import defer
#defer.Deferred.debug = 1

import channel
from messages import msgTypeName, printMsg

DEBUG = 1

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

    def __init__(self):
        self.channelFactory = channel.channelFactory()
        self.majorTypes = {}
        self.dom = None
        self.channel = None
        self.idx = None
        self.responders = {}
        self.timeout = 10

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
        self.channel = self.channelFactory.domChannel(self.dom)
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
    Maintains a table of instances.

    @ivar instances: mapping of index to controller instance
    @type instances: {String: Controller}
    @ivar dom: domain
    @type dom: int
    """

    def __init__(self):
        self.instances = {}
        self.backends = {}
        self.dom = 0
        
    def addInstance(self, instance):
        """Add a controller instance (under its index).
        """
        self.instances[instance.idx] = instance

    def getInstance(self, idx):
        """Get a controller instance from its index.
        """
        return self.instances.get(idx)

    def getInstances(self):
        """Get a list of all controller instances.
        """
        return self.instances.values()

    def getInstanceByDom(self, dom):
        """Get the controller instance for the given domain.

        @param dom: domain id
        @type  dom: int
        @return: controller or None
        """
        for inst in self.instances.values():
            if inst.dom == dom:
                return inst
        return None

    def delInstance(self, instance):
        """Delete a controller instance from the table.

        @param instance: controller instance
        """
        if instance.idx in self.instances:
            del self.instances[instance.idx]

    def createInstance(self, dom, recreate=0):
        """Create an instance. Define in a subclass.

        @param dom: domain
        @type  dom: int
        @param recreate: true if the instance is being recreated (after xend restart)
        @type  recreate: int
        @return: controller instance
        @rtype:  Controller (or subclass)
        """
        raise NotImplementedError()

    def instanceClosed(self, instance):
        """Callback called when an instance is closed (usually by the instance).
        
        @param instance: controller instance
        """
        self.delInstance(instance)

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

    def __init__(self, factory, dom):
        CtrlMsgRcvr.__init__(self)
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
        self.factory.instanceClosed(self)

class SplitControllerFactory(ControllerFactory):
    """Factory for SplitControllers.
    
    @ivar backends:  mapping of domain id to backend
    @type backends:  {int: BackendController}
    """
    
    def __init__(self):
        ControllerFactory.__init__(self)
        self.backends = {}

    def createInstance(self, dom, recreate=0, backend=0):
        """Create an instance. Define in a subclass.

        @param dom: domain
        @type  dom: int
        @param recreate: true if the instance is being recreated (after xend restart)
        @type  recreate: int
        @param backend: backend domain
        @type  backend: int
        @return: controller instance
        @rtype:  SplitController (or subclass)
        """
        raise NotImplementedError()
        
    def getBackendController(self, dom):
        """Get the backend controller for a domain.

        @param dom: domain
        @return: backend controller
        """
        ctrlr = self.backends.get(dom)
        if ctrlr is None:
            ctrlr = self.createBackendController(dom)
            self.backends[dom] = ctrlr
        return ctrlr

    def createBackendController(self, dom):
        """Create a backend controller. Define in a subclass.

        @param dom: domain
        """
        raise NotImplementedError()

    def delBackendController(self, ctrlr):
        """Remove a backend controller.

        @param ctrlr: backend controller
        """
        if ctrlr.dom in self.backends:
            del self.backends[ctrlr.dom]

    def backendControllerClosed(self, ctrlr):
        """Callback called when a backend is closed.
        """
        self.delBackendController(ctrlr)

class BackendController(CtrlMsgRcvr):
    """Abstract class for a backend device controller attached to a domain.

    @ivar factory: controller factory
    @type factory: ControllerFactory
    @ivar dom:     domain
    @type dom:     int
    @ivar channel: channel to the domain
    @type channel: Channel
    """

    
    def __init__(self, factory, dom):
        CtrlMsgRcvr.__init__(self)
        self.factory = factory
        self.dom = int(dom)
        self.channel = None
        
    def close(self):
        self.lostChannel()

    def lostChannel(self):
        self.deregisterChannel()
        self.factory.instanceClosed(self)


class SplitController(Controller):
    """Abstract class for a device controller attached to a domain.
    A SplitController has a BackendContoller.
    """

    def __init__(self, factory, dom, backend):
        Controller.__init__(self, factory, dom)
        self.backendDomain = None
        self.backendController = None
        self.setBackendDomain(backend)
        
    def setBackendDomain(self, dom):
        ctrlr = self.factory.getBackendController(dom)
        self.backendDomain = ctrlr.dom
        self.backendController = ctrlr

    def getBackendDomain(self):
        return self.backendDomain

    def getBackendController(self):
        return self.backendController

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

    
