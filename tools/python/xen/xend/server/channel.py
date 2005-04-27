# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import threading
import select

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()
from xen.lowlevel import xu

from xen.xend.XendLogging import log

from messages import *

VIRQ_MISDIRECT  = 0  # Catch-all interrupt for unbound VIRQs.
VIRQ_TIMER      = 1  # Timebase update, and/or requested timeout.
VIRQ_DEBUG      = 2  # Request guest to dump debug info.
VIRQ_CONSOLE    = 3  # (DOM0) bytes received on emergency console.
VIRQ_DOM_EXC    = 4  # (DOM0) Exceptional event for some domain.

DEBUG = 0

RESPONSE_TIMEOUT = 20.0

def eventChannel(dom1, dom2):
    """Create an event channel between domains.
    The returned dict contains dom1, dom2, port1 and port2 on success.

    @return dict (empty on error)
    """
    evtchn = xc.evtchn_bind_interdomain(dom1=dom1, dom2=dom2)
    if evtchn:
        evtchn['dom1'] = dom1
        evtchn['dom2'] = dom2
    return evtchn

def eventChannelClose(evtchn):
    """Close an event channel that was opened by eventChannel().
    """
    def evtchn_close(dom, port):
        if (dom is None) or (port is None): return
        try:
            xc.evtchn_close(dom=dom, port=port)
        except Exception, ex:
            pass
        
    if not evtchn: return
    print 'eventChannelClose>', evtchn
    evtchn_close(evtchn.get('dom1'), evtchn.get('port1'))
    evtchn_close(evtchn.get('dom2'), evtchn.get('port2'))
    

class ChannelFactory:
    """Factory for creating channels.
    Maintains a table of channels.
    """

    """ Channels indexed by index. """
    channels = {}

    thread = None

    notifier = None

    """Map of ports to the virq they signal."""
    virqPorts = {}

    def __init__(self):
        """Constructor - do not use. Use the channelFactory function."""
        self.notifier = xu.notifier()
        # Register interest in all virqs.
        # Unfortunately virqs do not seem to be delivered.
        self.bind_virq(VIRQ_MISDIRECT)
        self.bind_virq(VIRQ_TIMER)
        self.bind_virq(VIRQ_DEBUG)
        self.bind_virq(VIRQ_CONSOLE)
        self.bind_virq(VIRQ_DOM_EXC)
        self.virqHandler = None

    def bind_virq(self, virq):
        port = self.notifier.bind_virq(virq)
        self.virqPorts[port] = virq
        log.info("Virq %s on port %s", virq, port)

    def virq(self):
        self.notifier.virq_send(self.virqPort)

    def start(self):
        """Fork a thread to read messages.
        """
        if self.thread: return
        self.thread = threading.Thread(name="ChannelFactory",
                                       target=self.main)
        self.thread.setDaemon(True)
        self.thread.start()

    def stop(self):
        """Signal the thread to stop.
        """
        self.thread = None

    def main(self):
        """Main routine for the thread.
        Reads the notifier and dispatches to channels.
        """
        while True:
            if self.thread == None: return
            port = self.notifier.read()
            if port:
                virq = self.virqPorts.get(port)
                if virq is not None:
                    self.virqReceived(virq)
                else:
                    self.msgReceived(port)
            else:
                select.select([self.notifier], [], [], 1.0)

    def msgReceived(self, port):
        # We run the message handlers in their own threads.
        # Note we use keyword args to lambda to save the values -
        # otherwise lambda will use the variables, which will get
        # assigned by the loop and the lambda will get the changed values.
        received = 0
        for chan in self.channels.values():
            if self.thread == None: return
            msg = chan.readResponse()
            if msg:
                received += 1
                chan.responseReceived(msg)
        for chan in self.channels.values():
            if self.thread == None: return
            msg = chan.readRequest()
            if msg:
                received += 1
                self.runInThread(lambda chan=chan, msg=msg: chan.requestReceived(msg))
        if port and received == 0:
            log.warning("Port %s notified, but no messages found", port)

    def runInThread(self, thunk):
        thread = threading.Thread(target = thunk)
        thread.setDaemon(True)
        thread.start()

    def setVirqHandler(self, virqHandler):
        self.virqHandler = virqHandler

    def virqReceived(self, virq):
        if 1 or DEBUG:
            print 'virqReceived>', virq
        if not self.virqHandler: return
        self.runInThread(lambda virq=virq: self.virqHandler(virq))

    def newChannel(self, dom, local_port, remote_port):
        """Create a new channel.
        """
        return self.addChannel(Channel(self, dom, local_port, remote_port))
    
    def addChannel(self, channel):
        """Add a channel.
        """
        self.channels[channel.getKey()] = channel
        return channel

    def delChannel(self, channel):
        """Remove the channel.
        """
        key = channel.getKey()
        if key in self.channels:
            del self.channels[key]

    def getChannel(self, dom, local_port, remote_port):
        """Get the channel with the given domain and ports (if any).
        """
        key = (dom, local_port, remote_port)
        return self.channels.get(key)

    def findChannel(self, dom, local_port=0, remote_port=0):
        """Find a channel. Ports given as zero are wildcards.

        dom domain

        returns channel
        """
        chan = self.getChannel(dom, local_port, remote_port)
        if chan: return chan
        if local_port and remote_port:
            return None
        for c in self.channels.values():
            if c.dom != dom: continue
            if local_port and local_port != c.getLocalPort(): continue
            if remote_port and remote_port != c.getRemotePort(): continue
            return c
        return None

    def openChannel(self, dom, local_port=0, remote_port=0):
        return (self.findChannel(dom, local_port=local_port, remote_port=remote_port)
                or
                self.newChannel(dom, local_port, remote_port))

    def createPort(self, dom, local_port=0, remote_port=0):
        """Create a port for a channel to the given domain.
        If only the domain is specified, a new channel with new port ids is
        created.  If one port id is specified and the given port id is in use,
        the other port id is filled.  If one port id is specified and the
        given port id is not in use, a new channel is created with one port
        id equal to the given id and a new id for the other end.  If both
        port ids are specified, a port is reconnected using the given port
        ids.

        @param dom: domain
        @param local: local port id to use
        @type  local: int
        @param remote: remote port id to use
        @type  remote: int
        @return: port object
        """
        return xu.port(dom, local_port=int(local_port),
                       remote_port=int(remote_port))

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

class Channel:
    """Chanel to a domain.
    Maintains a list of device handlers to dispatch requests to, based
    on the request type.
    """

    def __init__(self, factory, dom, local_port, remote_port):
        self.factory = factory
        self.dom = int(dom)
        # Registered device handlers.
        self.devs = []
        # Handlers indexed by the message types they handle.
        self.devs_by_type = {}
        self.port = self.factory.createPort(self.dom,
                                            local_port=local_port,
                                            remote_port=remote_port)
        self.closed = False
        # Queue of waiters for responses to requests.
        self.queue = ResponseQueue(self)
        # Make sure the port will deliver all the messages.
        self.port.register(TYPE_WILDCARD)

    def getKey(self):
        """Get the channel key.
        """
        return (self.dom, self.getLocalPort(), self.getRemotePort())

    def sxpr(self):
        val = ['channel']
        val.append(['domain', self.dom])
        if self.port:
            val.append(['local_port', self.port.local_port])
            val.append(['remote_port', self.port.remote_port])
        return val

    def close(self):
        """Close the channel.
        """
        if DEBUG:
            print 'Channel>close>', self
        if self.closed: return
        self.closed = True
        self.factory.delChannel(self)
        for d in self.devs[:]:
            d.lostChannel(self)
        self.devs = []
        self.devs_by_type = {}
        if self.port:
            self.port.close()
            #self.port = None

    def getDomain(self):
        return self.dom

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

    def __repr__(self):
        return ('<Channel dom=%d ports=%d:%d>'
                % (self.dom,
                   self.getLocalPort(),
                   self.getRemotePort()))


    def registerDevice(self, types, dev):
        """Register a device message handler.

        @param types: message types handled
        @type  types: array of ints
        @param dev:   device handler
        """
        if self.closed: return
        self.devs.append(dev)
        for ty in types:
            self.devs_by_type[ty] = dev

    def deregisterDevice(self, dev):
        """Remove the registration for a device handler.

        @param dev: device handler
        """
        if dev in self.devs:
            self.devs.remove(dev)
        types = [ ty for (ty, d) in self.devs_by_type.items() if d == dev ]
        for ty in types:
            del self.devs_by_type[ty]

    def getDevice(self, type):
        """Get the handler for a message type.

        @param type: message type
        @type  type: int
        @return: controller or None
        @rtype:  device handler
        """
        return self.devs_by_type.get(type)

    def requestReceived(self, msg):
        """A request has been received on the channel.
        Disptach it to the device handlers.
        Called from the channel factory thread.
        """
        if DEBUG:
            print 'Channel>requestReceived>', self,
            printMsg(msg)
        (ty, subty) = getMessageType(msg)
        responded = False
        dev = self.getDevice(ty)
        if dev:
            responded = dev.requestReceived(msg, ty, subty)
        elif DEBUG:
            print "Channel>requestReceived> No device handler", self,
            printMsg(msg)
        else:
            pass
        if not responded:
            self.writeResponse(msg)

    def writeRequest(self, msg):
        """Write a request to the channel.
        """
        if DEBUG:
            print 'Channel>writeRequest>', self,
            printMsg(msg, all=True)
        if self.closed: return -1
        self.port.write_request(msg)
        return 1

    def writeResponse(self, msg):
        """Write a response to the channel.
        """
        if DEBUG:
            print 'Channel>writeResponse>', self,
            printMsg(msg, all=True)
        if self.port:
            self.port.write_response(msg)
        return 1

    def readRequest(self):
        """Read a request from the channel.
        Called internally.
        """
        if self.closed:
            val =  None
        else:
            val = self.port.read_request()
        return val
        
    def readResponse(self):
        """Read a response from the channel.
        Called internally.
        """
        if self.closed:
            val = None
        else:
            val = self.port.read_response()
        if DEBUG and val:
            print 'Channel>readResponse>', self,
            printMsg(val, all=True)
        return val

    def requestResponse(self, msg, timeout=None):
        """Write a request and wait for a response.
        Raises IOError on timeout.

        @param msg request message
        @param timeout timeout (0 is forever)
        @return response message
        """
        if self.closed:
            raise IOError("closed")
        if self.closed:
            return None
        if timeout is None:
            timeout = RESPONSE_TIMEOUT
        elif timeout <= 0:
            timeout = None
        return self.queue.call(msg, timeout)

    def responseReceived(self, msg):
        """A response has been received, look for a waiter to
        give it to.
        Called internally.
        """
        if DEBUG:
            print 'Channel>responseReceived>', self,
            printMsg(msg)
        self.queue.response(getMessageId(msg), msg)

    def virq(self):
        self.factory.virq()

class Response:
    """Entry in the response queue.
    Used to signal a response to a message.
    """

    def __init__(self, mid):
        self.mid = mid
        self.msg = None
        self.ready = threading.Event()

    def response(self, msg):
        """Signal arrival of a response to a waiting thread.
        Passing msg None cancels the wait with an IOError.
        """
        if msg:
            self.msg = msg
        else:
            self.mid = -1
        self.ready.set()

    def wait(self, timeout):
        """Wait up to 'timeout' seconds for a response.
        Returns the response or raises an IOError.
        """
        self.ready.wait(timeout)
        if self.mid < 0:
            raise IOError("wait canceled")
        if self.msg is None:
            raise IOError("response timeout")
        return self.msg

class ResponseQueue:
    """Response queue. Manages waiters for responses to messages.
    """

    def __init__(self, channel):
        self.channel = channel
        self.lock = threading.Lock()
        self.responses = {}

    def add(self, mid):
        r = Response(mid)
        self.responses[mid] = r
        return r

    def get(self, mid):
        return self.responses.get(mid)

    def remove(self, mid):
        r = self.responses.get(mid)
        if r:
            del self.responses[mid]
        return r

    def response(self, mid, msg):
        """Process a response - signals any waiter that a response
        has arrived.
        """
        try:
            self.lock.acquire()
            r = self.remove(mid)
        finally:
            self.lock.release()
        if r:
            r.response(msg)

    def call(self, msg, timeout):
        """Send the message and wait for 'timeout' seconds for a response.
        Returns the response.
        Raises IOError on timeout.
        """
        mid = getMessageId(msg)
        try:
            self.lock.acquire()
            r = self.add(mid)
        finally:
            self.lock.release()
        self.channel.writeRequest(msg)
        return r.wait(timeout)
                
