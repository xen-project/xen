from twisted.internet import defer

import channel
from messages import msgTypeName

class CtrlMsgRcvr:
    """Abstract class for things that deal with a control interface to a domain.
    """


    def __init__(self):
        self.channelFactory = channel.channelFactory()
        self.majorTypes = [ ]
        self.subTypes = {}
        self.dom = None
        self.channel = None
        self.idx = None

    def requestReceived(self, msg, type, subtype):
        method = self.subTypes.get(subtype)
        if method:
            method(msg, 1)
        else:
            print ('requestReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self
        
    def responseReceived(self, msg, type, subtype):
        method = self.subTypes.get(subtype)
        if method:
            method(msg, 0)
        else:
            print ('responseReceived> No handler: Message type %s %d:%d'
                   % (msgTypeName(type, subtype), type, subtype)), self

    def lostChannel(self):
        pass
    
    def registerChannel(self):
        self.channel = self.channelFactory.domChannel(self.dom)
        self.idx = self.channel.getIndex()
        if self.majorTypes:
            self.channel.registerDevice(self.majorTypes, self)
        
    def deregisterChannel(self):
        if self.channel:
            self.channel.deregisterDevice(self)
            del self.channel

    def produceRequests(self):
        return 0

    def writeRequest(self, msg):
        if self.channel:
            self.channel.writeRequest(msg)
        else:
            print 'CtrlMsgRcvr>writeRequest>', 'no channel!', self

    def writeResponse(self, msg):
        if self.channel:
            self.channel.writeResponse(msg)
        else:
            print 'CtrlMsgRcvr>writeResponse>', 'no channel!', self
            
class ControllerFactory(CtrlMsgRcvr):
    """Abstract class for factories creating controllers.
    Maintains a table of instances.
    """

    def __init__(self):
        CtrlMsgRcvr.__init__(self)
        self.instances = {}
        self.dlist = []
        self.dom = 0
        
    def addInstance(self, instance):
        self.instances[instance.idx] = instance

    def getInstance(self, idx):
        return self.instances.get(idx)

    def getInstances(self):
        return self.instances.values()

    def getInstanceByDom(self, dom):
        for inst in self.instances.values():
            if inst.dom == dom:
                return inst
        return None

    def delInstance(self, instance):
        if instance.idx in self.instances:
            del self.instances[instance.idx]

    def createInstance(self, dom):
        raise NotImplementedError()

    def instanceClosed(self, instance):
        self.delInstance(instance)

    def addDeferred(self):
        d = defer.Deferred()
        self.dlist.append(d)
        return d

    def callDeferred(self, *args):
        if self.dlist:
            d = self.dlist.pop(0)
            d.callback(*args)

    def errDeferred(self, *args):
        if self.dlist:
            d = self.dlist.pop(0)
            d.errback(*args)

class Controller(CtrlMsgRcvr):
    """Abstract class for a device controller attached to a domain.
    """

    def __init__(self, factory, dom):
        CtrlMsgRcvr.__init__(self)
        self.factory = factory
        self.dom = dom
        self.channel = None
        self.idx = None

    def close(self):
        self.deregisterChannel()
        self.lostChannel(self)

    def lostChannel(self):
        self.factory.instanceClosed(self)
