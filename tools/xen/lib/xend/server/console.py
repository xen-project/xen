
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.protocols import telnet

from xen.ext import xu

from xen.xend import EventServer
eserver = EventServer.instance()

import controller
from messages import *
from params import *

"""Telnet binary option."""
TRANSMIT_BINARY = '0'
WILL = chr(251)
IAC = chr(255)

class ConsoleProtocol(protocol.Protocol):
    """Asynchronous handler for a console TCP socket.
    """

    def __init__(self, controller, idx):
        self.controller = controller
        self.idx = idx
        self.addr = None
        self.binary = 0

    def connectionMade(self):
        peer = self.transport.getPeer()
        self.addr = (peer.host, peer.port)
        if self.controller.connect(self.addr, self):
            self.transport.write("Cannot connect to console %d on domain %d\n"
                                 % (self.idx, self.controller.dom))
            self.loseConnection()
            return
        else:
            self.transport.write("Connected to console %d on domain %d\n"
                                 % (self.idx, self.controller.dom))
            self.setTelnetTransmitBinary()
            eserver.inject('xend.console.connect',
                           [self.idx, self.addr[0], self.addr[1]])

    def setTelnetTransmitBinary(self):
        """Send the sequence to set the telnet TRANSMIT-BINARY option.
        """
        self.write(IAC + WILL + TRANSMIT_BINARY)

    def dataReceived(self, data):
        if self.controller.handleInput(self, data):
            self.loseConnection()

    def write(self, data):
        #if not self.connected: return -1
        self.transport.write(data)
        return len(data)

    def connectionLost(self, reason=None):
        eserver.inject('xend.console.disconnect',
                       [self.idx, self.addr[0], self.addr[1]])
        self.controller.disconnect()

    def loseConnection(self):
        self.transport.loseConnection()

class ConsoleFactory(protocol.ServerFactory):
    """Asynchronous handler for a console server socket.
    """
    protocol = ConsoleProtocol
    
    def __init__(self, controller, idx):
        #protocol.ServerFactory.__init__(self)
        self.controller = controller
        self.idx = idx

    def buildProtocol(self, addr):
        proto = self.protocol(self.controller, self.idx)
        proto.factory = self
        return proto

class ConsoleControllerFactory(controller.ControllerFactory):
    """Factory for creating console controllers.
    """

    def createInstance(self, dom, console_port=None):
        if console_port is None:
            console_port = CONSOLE_PORT_BASE + dom
        console = ConsoleController(self, dom, console_port)
        self.addInstance(console)
        eserver.inject('xend.console.create',
                       [console.idx, console.dom, console.console_port])
        return console
        
    def consoleClosed(self, console):
        eserver.inject('xend.console.close', console.idx)
        self.delInstance(console)

class ConsoleController(controller.Controller):
    """Console controller for a domain.
    Does not poll for i/o itself, but relies on the notifier to post console
    output and the connected TCP sockets to post console input.
    """

    def __init__(self, factory, dom, console_port):
        #print 'ConsoleController> dom=', dom, type(dom)
        controller.Controller.__init__(self, factory, dom)
        self.majorTypes = [ CMSG_CONSOLE ]
        self.status = "new"
        self.addr = None
        self.conn = None
        self.rbuf = xu.buffer()
        self.wbuf = xu.buffer()
        self.console_port = console_port

        self.registerChannel()
        self.listener = None
        self.listen()
        #print 'ConsoleController<', 'dom=', self.dom, 'idx=', self.idx

    def sxpr(self):
        val =['console',
              ['status',       self.status ],
              ['id',           self.idx ],
              ['domain',       self.dom ],
              ['local_port',   self.channel.getLocalPort() ],
              ['remote_port',  self.channel.getRemotePort() ],
              ['console_port', self.console_port ] ]
        if self.addr:
            val.append(['connected', self.addr[0], self.addr[1]])
        return val

    def ready(self):
        return not (self.closed() or self.rbuf.empty())

    def closed(self):
        return self.status == 'closed'

    def connected(self):
        return self.status == 'connected'

    def close(self):
        try:
            #print 'ConsoleController> close dom=', self.dom
            self.status = "closed"
            if self.conn:
                self.conn.loseConnection()
            self.listener.stopListening()
            self.deregisterChannel()
            self.lostChannel()
        except Exception, ex:
            print 'ConsoleController>close>', ex
            raise

    def listen(self):
        """Listen for TCP connections to the console port..
        """
        if self.closed(): return
        self.status = "listening"
        if self.listener:
            #self.listener.startListening()
            pass
        else:
            f = ConsoleFactory(self, self.idx)
            self.listener = reactor.listenTCP(self.console_port, f)

    def connect(self, addr, conn):
        if self.closed(): return -1
        if self.connected(): return -1
        self.addr = addr
        self.conn = conn
        self.status = "connected"
        self.handleOutput()
        return 0

    def disconnect(self):
        if self.conn:
            self.conn.loseConnection()
        self.addr = None
        self.conn = None
        self.listen()

    def requestReceived(self, msg, type, subtype):
        #print '***Console', self.dom, msg.get_payload()
        self.rbuf.write(msg.get_payload())
        self.handleOutput()
        
    def responseReceived(self, msg, type, subtype):
        pass

    def produceRequests(self):
        # Send as much pending console data as there is room for.
        work = 0
        while not self.wbuf.empty() and self.channel.writeReady():
            msg = xu.message(CMSG_CONSOLE, 0, 0)
            msg.append_payload(self.wbuf.read(msg.MAX_PAYLOAD))
            work += self.channel.writeRequest(msg, notify=0)
        return work

    def handleInput(self, conn, data):
        """Handle some external input aimed at the console.
        Called from a TCP connection (conn).
        """
        if self.closed(): return -1
        if conn != self.conn: return 0
        self.wbuf.write(data)
        if self.produceRequests():
            self.channel.notify()
        return 0

    def handleOutput(self):
        """Handle buffered output from the console.
        Sends it to the connected console (if any).
        """
        if self.closed():
            #print 'Console>handleOutput> closed'
            return -1
        if not self.conn:
            #print 'Console>handleOutput> not connected'
            return 0
        while not self.rbuf.empty():
            try:
                #print 'Console>handleOutput> writing...'
                bytes = self.conn.write(self.rbuf.peek())
                if bytes > 0:
                    self.rbuf.discard(bytes)
            except socket.error, error:
                pass
        #print 'Console>handleOutput<'
        return 0
