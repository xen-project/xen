# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from twisted.internet import defer

import channel
from messages import msgTypeName

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

    def requestReceived(self, msg, type, subtype):
        """Dispatch a request to handlers.

        msg     message
        type    major message type
        subtype minor message type
        """
        method = self.subTypes.get(subtype)
        if method:
            method(msg, 1)
        else:
            print ('requestReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self
        
    def responseReceived(self, msg, type, subtype):
        """Dispatch a response to handlers.

        msg     message
        type    major message type
        subtype minor message type
        """
        method = self.subTypes.get(subtype)
        if method:
            method(msg, 0)
        else:
            print ('responseReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self

    def lostChannel(self):
        """Called when the channel to the domain is lost.
        """
        pass
    
    def registerChannel(self):
        """Register interest in our major message types with the
        channel to our domain.
        """
        #print 'CtrlMsgRcvr>registerChannel>', self
        self.channel = self.channelFactory.domChannel(self.dom)
        self.idx = self.channel.getIndex()
        if self.majorTypes:
            self.channel.registerDevice(self.majorTypes, self)
        
    def deregisterChannel(self):
        """Deregister interest in our major message types with the
        channel to our domain.
        """
        #print 'CtrlMsgRcvr>deregisterChannel>', self
        if self.channel:
            self.channel.deregisterDevice(self)
            del self.channel

    def produceRequests(self):
        """Produce any queued requests.

        return number produced
        """
        return 0

    def writeRequest(self, msg):
        """Write a request to the channel.
        """
        if self.channel:
            self.channel.writeRequest(msg)
        else:
            print 'CtrlMsgRcvr>writeRequest>', 'no channel!', self

    def writeResponse(self, msg):
        """Write a response to the channel.
        """
        if self.channel:
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
    timeout   : deferred timeout
    """

    def __init__(self):
        CtrlMsgRcvr.__init__(self)
        self.instances = {}
        self.dlist = []
        self.dom = 0
        # Timeout (in seconds) for deferreds.
        self.timeout = 10
        
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

    def addDeferred(self):
        """Add a deferred object.

        returns deferred
        """
        d = defer.Deferred()
        if self.timeout > 0:
            # The deferred will error if not called before timeout.
            d.setTimeout(self.timeout)
        self.dlist.append(d)
        return d

    def callDeferred(self, *args):
        """Call the top deferred object

        args arguments
        """
        if self.dlist:
            d = self.dlist.pop(0)
            if not d.called:
                d.callback(*args)

    def errDeferred(self, *args):
        """Signal an error to the top deferred object.

        args arguments
        """
        if self.dlist:
            d = self.dlist.pop(0)
            if not d.called:
                d.errback(*args)

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

    
