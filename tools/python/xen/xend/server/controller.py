# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""General support for controllers, which handle devices
for a domain.
"""

from twisted.internet import defer
#defer.Deferred.debug = 1

import channel
from messages import msgTypeName, printMsg

DEBUG = 0

class OutOfOrderError(RuntimeError):
    """Error reported when a response message arrives out of order.
    """
    pass

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
    @type majorTypes: [int]
    @ivar subTypes: mapping of message subtypes to methods
    @ivar subTypes: {int:method}
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
        self.majorTypes = [ ]
        self.subTypes = {}
        self.dom = None
        self.channel = None
        self.idx = None
        self.responders = []
        self.timeout = 10

    def setTimeout(self, timeout):
        self.timeout = timeout

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
        method = self.subTypes.get(subtype)
        if method:
            method(msg, 1)
        elif DEBUG:
            print ('requestReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self
        
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
        method = self.subTypes.get(subtype)
        if method:
            method(msg, 0)
        elif DEBUG:
            print ('responseReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self

    def addResponder(self, mid, deferred):
        """Add a responder for a message id.
        The I{deferred} is called with callback(msg) when a response
        with message id I{mid} arrives. Responses are expected
        to arrive in order of message id. When a response arrives,
        waiting responders for messages with lower id have errback
        called with an OutOfOrder error.

        Responders have a timeout set and I{deferred} will error
        on expiry.

        @param mid:      message id of response expected
        @type  mid:      int
        @param deferred: handler for the response
        @type  deferred: Deferred
        @return: responder
        @rtype:  Responder
        """
        if self.timeout > 0:
            deferred.setTimeout(self.timeout)
        resp = Responder(mid, deferred)
        self.responders.append(resp)
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
        while self.responders:
            resp = self.responders[0]
            if resp.mid > mid:
                break
            self.responders.pop()
            if resp.mid < mid:
                print 'callResponders> Out of order:', resp.mid, mid
                resp.error(OutOfOrderError())
            else:
                handled = 1
                resp.responseReceived(msg)
                break
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
            self.channel.registerDevice(self.majorTypes, self)
        
    def deregisterChannel(self):
        """Deregister interest in our major message types with the
        channel to our domain. After this the channel won't call
        us any more.
        """
        if self.channel:
            self.channel.deregisterDevice(self)
            del self.channel

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
            
class ControllerFactory(CtrlMsgRcvr):
    """Abstract class for factories creating controllers for a domain.
    Maintains a table of instances.

    @ivar instances: mapping of index to controller instance
    @type instances: {int: Controller}
    @ivar dom: domain
    @type dom: int
    """

    def __init__(self):
        CtrlMsgRcvr.__init__(self)
        self.instances = {}
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
        """
        for inst in self.instances.values():
            if inst.dom == dom:
                return inst
        return None

    def delInstance(self, instance):
        """Delete an instance from the table.
        """
        if instance.idx in self.instances:
            del self.instances[instance.idx]

    def createInstance(self, dom, recreate=0):
        """Create an instance. Define in a subclass.

        @param dom: domain
        @type  dom: int
        @param recreate: true if the instance is being recreated (after xend restart)
        @type  recreate: int
        """
        raise NotImplementedError()

    def instanceClosed(self, instance):
        """Callback called when an instance is closed (usually by the instance).
        """
        self.delInstance(instance)

class Controller(CtrlMsgRcvr):
    """Abstract class for a device controller attached to a domain.
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

class Dev:
    """Abstract class for a device attached to a device controller.
    """
    
    def __init__(self, controller):
        self.controller = controller
        self.props = {}

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
        raise NotImplementedError()

    
