# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()
from xen.lowlevel import xu
from messages import msgTypeName, printMsg

VIRQ_MISDIRECT  = 0  # Catch-all interrupt for unbound VIRQs.
VIRQ_TIMER      = 1  # Timebase update, and/or requested timeout.
VIRQ_DEBUG      = 2  # Request guest to dump debug info.
VIRQ_CONSOLE    = 3  # (DOM0) bytes received on emergency console.
VIRQ_DOM_EXC    = 4  # (DOM0) Exceptional event for some domain.

def eventChannel(dom1, dom2):
    return xc.evtchn_bind_interdomain(dom1=dom1, dom2=dom2)

class ChannelFactory:
    """Factory for creating channels.
    Maintains a table of channels.
    """

    """ Channels indexed by index. """
    channels = {}

    def __init__(self):
        """Constructor - do not use. Use the channelFactory function."""
        self.notifier = xu.notifier()
    
    def addChannel(self, channel):
        """Add a channel. Registers with the notifier.
        """
        idx = channel.idx
        self.channels[idx] = channel
        self.notifier.bind(idx)

    def getChannel(self, idx):
        """Get the channel with the given index (if any).
        """
        return self.channels.get(idx)

    def delChannel(self, idx):
        """Remove the channel with the given index (if any).
        Deregisters with the notifier.
        """
        if idx in self.channels:
            del self.channels[idx]
            self.notifier.unbind(idx)

    def domChannel(self, dom, remote_port=0):
        """Get the channel for the given domain.
        Construct if necessary.

        dom domain

        returns channel
        """
        chan = self.getDomChannel(dom)
        if not chan:
            chan = Channel(self, dom, remote_port=remote_port)
            self.addChannel(chan)
        return chan

    def getDomChannel(self, dom):
        """Get the channel for the given domain.

        dom domain

        returns channel (or None)
        """
        dom = int(dom)
        for chan in self.channels.values():
            if not isinstance(chan, Channel): continue
            if chan.dom == dom:
                return chan
        return None
        

    def virqChannel(self, virq):
        """Get the channel for the given virq.
        Construct if necessary.
        """
        for chan in self.channels.values():
            if not isinstance(chan, VirqChannel): continue
            if chan.virq == virq:
                return chan
        chan = VirqChannel(self, virq)
        self.addChannel(chan)
        return chan

    def channelClosed(self, channel):
        """The given channel has been closed - remove it.
        """
        self.delChannel(channel.idx)

    def createPort(self, dom, remote_port=0):
        """Create a port for a channel to the given domain.
        """
        return xu.port(dom, 0, remote_port)

def channelFactory():
    """Singleton constructor for the channel factory.
    Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = ChannelFactory()
    return inst

class BaseChannel:
    """Abstract superclass for channels.

    The subclass constructor must set idx to the port to use.
    """

    def __init__(self, factory):
        self.factory = factory
        self.idx = -1
        self.closed = 0

    def getIndex(self):
        """Get the channel index.
        """
        return self.idx

    def notificationReceived(self):
        """Called when a notification is received.
        Calls handleNotification(), which should be defined
        in a subclass.
        """
        if self.closed: return
        self.handleNotification()

    def close(self):
        """Close the channel. Calls channelClosed() on the factory.
        Override in subclass.
        """
        self.factory.channelClosed(self)

    def handleNotification(self):
        """Handle notification.
        Define in subclass.
        """
        pass
        

class VirqChannel(BaseChannel):
    """A channel for handling a virq.
    """
    
    def __init__(self, factory, virq):
        """Create a channel for the given virq using the given factory.

        Do not call directly, use virqChannel on the factory.
        """
        BaseChannel.__init__(self, factory)
        self.virq = virq
        # Notification port (int).
        self.port = xc.evtchn_bind_virq(virq)
        self.idx = self.port
        # Clients to call when a virq arrives.
        self.clients = []

    def __repr__(self):
        return ('<VirqChannel virq=%d port=%d>'
                % (self.virq, self.port))

    def getVirq(self):
        """Get the channel's virq.
        """
        return self.virq

    def close(self):
        """Close the channel. Calls lostChannel(self) on all its clients and
        channelClosed() on the factory.
        """
        for c in self.clients[:]:
            c.lostChannel(self)
        self.clients = []
        BaseChannel.close(self)

    def registerClient(self, client):
        """Register a client. The client will be called with
        client.virqReceived(virq) when a virq is received.
        The client will be called with client.lostChannel(self) if the
        channel is closed.
        """
        self.clients.append(client)

    def handleNotification(self):
        for c in self.clients:
            c.virqReceived(self.virq)

    def notify(self):
        xc.evtchn_send(self.port)


class Channel(BaseChannel):
    """A control channel to a domain. Messages for the domain device controllers
    are multiplexed over the channel (console, block devs, net devs).
    """

    def __init__(self, factory, dom, remote_port=0):
        """Create a channel to the given domain using the given factory.

        Do not call directly, use domChannel on the factory.
        """
        BaseChannel.__init__(self, factory)
        # Domain.
        self.dom = int(dom)
        # Domain port (object).
        self.port = self.factory.createPort(dom, remote_port=remote_port)
        # Channel port (int).
        self.idx = self.port.local_port
        # Registered devices.
        self.devs = []
        # Devices indexed by the message types they handle.
        self.devs_by_type = {}
        # Output queue.
        self.queue = []
        self.closed = 0

    def getLocalPort(self):
        """Get the local port.

        @return: local port
        @rtype:  int
        """
        if self.closed: return -1
        return self.port.local_port

    def getRemotePort(self):
        """Get the remote port.

        @return: remote port
        @rtype:  int
        """
        if self.closed: return -1
        return self.port.remote_port

    def close(self):
        """Close the channel. Calls lostChannel() on all its devices and
        channelClosed() on the factory.
        """
        if self.closed: return
        self.closed = 1
        for d in self.devs[:]:
            d.lostChannel()
        self.factory.channelClosed(self)
        self.devs = []
        self.devs_by_type = {}
        self.port.disconnect()

    def registerDevice(self, types, dev):
        """Register a device controller.

        @param types: message types the controller handles
        @type  types: array of ints
        @param dev:   device controller
        """
        if self.closed: return
        self.devs.append(dev)
        for ty in types:
            self.devs_by_type[ty] = dev

    def deregisterDevice(self, dev):
        """Remove the registration for a device controller.

        @param dev: device controller
        """
        if dev in self.devs:
            self.devs.remove(dev)
        types = [ ty for (ty, d) in self.devs_by_type.items() if d == dev ]
        for ty in types:
            del self.devs_by_type[ty]

    def getDevice(self, type):
        """Get the device controller handling a message type.

        @param type: message type
        @type  type: int
        @return: controller or None
        @rtype:  device controller
        """
        return self.devs_by_type.get(type)

    def getMessageType(self, msg):
        """Get a 2-tuple of the message type and subtype.

        @param msg: message
        @type  msg: xu message
        @return: type info
        @rtype:  (int, int)
        """
        hdr = msg.get_header()
        return (hdr['type'], hdr.get('subtype'))

    def __repr__(self):
        return ('<Channel dom=%d ports=%d:%d>'
                % (self.dom,
                   self.getLocalPort(),
                   self.getRemotePort()))

    def handleNotification(self):
        """Process outstanding messages in repsonse to notification on the port.
        """
        if self.closed:
            print 'handleNotification> Notification on closed channel', self
            return
        work = 0
        work += self.handleRequests()
        work += self.handleResponses()
        work += self.handleWrites()
        if work:
            self.notify()

    def notify(self):
        """Notify the other end of the port that messages have been processed.
        """
        if self.closed: return
        self.port.notify()

    def handleRequests(self):
        work = 0
        while 1:
            msg = self.readRequest()
            if not msg: break
            self.requestReceived(msg)
            work += 1
        return work

    def requestReceived(self, msg):
        (ty, subty) = self.getMessageType(msg)
        #todo:  Must respond before writing any more messages.
        #todo:  Should automate this (respond on write)
        responded = 0
        dev = self.getDevice(ty)
        if dev:
            responded = dev.requestReceived(msg, ty, subty)
        else:
            print ("requestReceived> No device: Message type %s %d:%d"
                   % (msgTypeName(ty, subty), ty, subty)), self
        if not responded:
            self.port.write_response(msg)

    def handleResponses(self):
        work = 0
        while 1:
            msg = self.readResponse()
            if not msg: break
            self.responseReceived(msg)
            work += 1
        return work

    def responseReceived(self, msg):
        (ty, subty) = self.getMessageType(msg)
        dev = self.getDevice(ty)
        if dev:
            dev.responseReceived(msg, ty, subty)
        else:
            print ("responseReceived> No device: Message type %d:%d"
                   % (msgTypeName(ty, subty), ty, subty)), self

    def handleWrites(self):
        work = 0
        # Pull data from producers.
        for dev in self.devs:
            work += dev.produceRequests()
        # Flush the queue.
        while self.queue and self.port.space_to_write_request():
            msg = self.queue.pop(0)
            self.port.write_request(msg)
            work += 1
        return work

    def writeRequest(self, msg, notify=1):
        if self.closed:
            val = -1
        elif self.writeReady():
            self.port.write_request(msg)
            if notify: self.notify()
            val = 1
        else:
            self.queue.append(msg)
            val = 0
        return val

    def writeResponse(self, msg):
        if self.closed: return -1
        self.port.write_response(msg)
        return 1

    def writeReady(self):
        if self.closed or self.queue: return 0
        return self.port.space_to_write_request()

    def readRequest(self):
        if self.closed:
            return None
        if self.port.request_to_read():
            val = self.port.read_request()
        else:
            val = None
        return val
        
    def readResponse(self):
        if self.closed:
            return None
        if self.port.response_to_read():
            val = self.port.read_response()
        else:
            val = None
        return val
