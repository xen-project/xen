# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from twisted.internet import defer
defer.Deferred.debug = 1

import channel
from messages import msgTypeName

DEBUG=0

class OutOfOrderError(RuntimeError):
    """Error reported when a response arrives out of order.
    """
    pass

class Responder:
    """Handler for a response to a message.
    """

    def __init__(self, mid, deferred):
        """Create a responder.

        mid      message id of response to handle
        deferred deferred object holding the callbacks
        """
        self.mid = mid
        self.deferred = deferred

    def responseReceived(self, msg):
        if self.deferred.called: return
        self.deferred.callback(msg)

    def error(self, err):
        if self.deferred.called: return
        self.deferred.errback(err)

class CtrlMsgRcvr:
    """Abstract class for things that deal with a control interface to a domain.

    Instance variables:

    dom       : the domain we are a control interface for
    majorTypes: list of major message types we are interested in
    subTypes  : mapping of message subtypes to methods
    
    channel   : channel to the domain
    idx       : channel index
    """


    def __init__(self):
        self.channelFactory = channel.channelFactory()
        self.majorTypes = [ ]
        self.subTypes = {}
        self.dom = None
        self.channel = None
        self.idx = None
        self.responders = []
        # Timeout (in seconds) for deferreds.
        self.timeout = 10

    def setTimeout(self, timeout):
        self.timeout = timeout

    def requestReceived(self, msg, type, subtype):
        """Dispatch a request to handlers.

        msg     message
        type    major message type
        subtype minor message type
        """
        msgid = msg.get_header()['id']
        if DEBUG:
            print 'requestReceived>', self, msgid, msgTypeName(type, subtype)
        method = self.subTypes.get(subtype)
        if method:
            method(msg, 1)
        elif DEBUG:
            print ('requestReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self
        
    def responseReceived(self, msg, type, subtype):
        """Dispatch a response to handlers.

        msg     message
        type    major message type
        subtype minor message type
        """
        msgid = msg.get_header()['id']
        if DEBUG:
            print 'responseReceived>', self, msgid, msgTypeName(type, subtype)
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
        The deferred is called with callback(msg) when a response
        with the given message id arrives. Responses are expected
        to arrive in order of message id. When a response arrives,
        waiting responders for messages with lower id have errback
        called with an OutOfOrder error.

        mid      message id of response expected
        deferred a Deferred to handle the response

        returns Responder
        """
        if self.timeout > 0:
            deferred.setTimeout(self.timeout)
        resp = Responder(mid, deferred)
        self.responders.append(resp)
        return resp

    def callResponders(self, msg):
        """Call any waiting responders for a response message.

        msg     response message
        
        returns 1 if there was a responder for the message, 0 otherwise
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
                print 'handleResponse> Out of order:', resp.mid, mid
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
        channel to our domain.
        """
        self.channel = self.channelFactory.domChannel(self.dom)
        self.idx = self.channel.getIndex()
        if self.majorTypes:
            self.channel.registerDevice(self.majorTypes, self)
        
    def deregisterChannel(self):
        """Deregister interest in our major message types with the
        channel to our domain.
        """
        if self.channel:
            self.channel.deregisterDevice(self)
            del self.channel

    def produceRequests(self):
        """Produce any queued requests.

        return number produced
        """
        return 0

    def writeRequest(self, msg, response=None):
        """Write a request to the channel.

        msg      message
        response Deferred to handle the response (optional)
        """
        if self.channel:
            if DEBUG: print 'CtrlMsgRcvr>writeRequest>', self, msg
            if response:
                self.addResponder(msg.get_header()['id'], response)
            self.channel.writeRequest(msg)
        else:
            print 'CtrlMsgRcvr>writeRequest>', 'no channel!', self

    def writeResponse(self, msg):
        """Write a response to the channel.
        """
        if self.channel:
            if DEBUG: print 'CtrlMsgRcvr>writeResponse>', self, msg
            self.channel.writeResponse(msg)
        else:
            print 'CtrlMsgRcvr>writeResponse>', 'no channel!', self
            
class ControllerFactory(CtrlMsgRcvr):
    """Abstract class for factories creating controllers.
    Maintains a table of instances.

    Instance variables:

    instances : mapping of index to controller instance
    dlist     : list of deferreds
    dom       : domain
    """

    def __init__(self):
        CtrlMsgRcvr.__init__(self)
        self.instances = {}
        self.dlist = []
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

    
