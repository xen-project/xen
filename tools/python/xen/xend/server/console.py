# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import socket

from twisted.internet import reactor
from twisted.internet import protocol

from xen.lowlevel import xu

from xen.xend.XendError import XendError
from xen.xend import EventServer
eserver = EventServer.instance()
from xen.xend.XendLogging import log

import controller
from messages import *
from params import *

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
            # KAF: A nice quiet successful connect.
            #self.transport.write("Connected to console %d on domain %d\n"
            #                     % (self.idx, self.controller.dom))
            log.info("Console connected %s %s %s",
                     self.idx, str(self.addr[0]), str(self.addr[1]))
            eserver.inject('xend.console.connect',
                           [self.idx, self.addr[0], self.addr[1]])

    def dataReceived(self, data):
        if self.controller.handleInput(self, data):
            self.loseConnection()

    def write(self, data):
        #if not self.connected: return -1
        self.transport.write(data)
        return len(data)

    def connectionLost(self, reason=None):
        log.info("Console disconnected %s %s %s",
                 self.idx, str(self.addr[0]), str(self.addr[1]))
        eserver.inject('xend.console.disconnect',
                       [self.idx, self.addr[0], self.addr[1]])
        self.controller.disconnect(conn=self)

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

    def createController(self, dom, console_port=None, remote_port=0):
        if console_port is None:
            console_port = CONSOLE_PORT_BASE + dom
        for c in self.getControllers():
            if c.console_port == console_port:
                raise XendError('console port in use: ' + str(console_port))
        console = ConsoleController(self, dom, console_port,
                                    remote_port=remote_port)
        self.addController(console)
        log.info("Created console id=%s domain=%d port=%d",
                 console.idx, console.dom, console.console_port)
        eserver.inject('xend.console.create',
                       [console.idx, console.dom, console.console_port])
        return console
        
    def consoleClosed(self, console):
        log.info("Closed console id=%s", console.idx)
        eserver.inject('xend.console.close', console.idx)
        self.delController(console)

class ConsoleController(controller.Controller):
    """Console controller for a domain.
    Does not poll for i/o itself, but relies on the notifier to post console
    output and the connected TCP sockets to post console input.
    """

    STATUS_NEW       = 'new'
    STATUS_CLOSED    = 'closed'
    STATUS_CONNECTED = 'connected'
    STATUS_LISTENING = 'listening'

    def __init__(self, factory, dom, console_port, remote_port=0):
        controller.Controller.__init__(self, factory, dom,
                                       remote_port=remote_port)
        self.addMethod(CMSG_CONSOLE, 0, None)
        self.status = self.STATUS_NEW
        self.addr = None
        self.conn = None
        self.rbuf = xu.buffer()
        self.wbuf = xu.buffer()
        self.console_port = console_port

        self.registerChannel()
        self.listener = None
        self.listen()

    def sxpr(self):
        val = ['console',
               ['status', self.status ],
               ['id',     self.idx    ],
               ['domain', self.dom    ] ]
        val.append(['local_port',   self.getLocalPort()  ])
        val.append(['remote_port',  self.getRemotePort() ])
        val.append(['console_port', self.console_port    ])
        if self.addr:
            val.append(['connected', self.addr[0], self.addr[1]])
        return val

    def getLocalPort(self):
        if self.channel:
            return self.channel.getLocalPort()
        else:
            return 0

    def getRemotePort(self):
        if self.channel:
            return self.channel.getRemotePort()
        else:
            return 0

    def uri(self):
        """Get the uri to use to connect to the console.
        This will be a telnet: uri.

        return uri
        """
        host = socket.gethostname()
        return "telnet://%s:%d" % (host, self.console_port)

    def ready(self):
        return not (self.closed() or self.rbuf.empty())

    def closed(self):
        return self.status == self.STATUS_CLOSED

    def connected(self):
        return self.status == self.STATUS_CONNECTED

    def close(self):
        """Close the console controller.
        """
        self.lostChannel()

    def lostChannel(self):
        """The channel to the domain has been lost.
        Cleanup: disconnect TCP connections and listeners, notify the controller.
        """
        self.status = self.STATUS_CLOSED
        if self.conn:
            self.conn.loseConnection()
        self.listener.stopListening()
        controller.Controller.lostChannel(self)

    def listen(self):
        """Listen for TCP connections to the console port..
        """
        if self.closed(): return
        self.status = self.STATUS_LISTENING
        if self.listener:
            #self.listener.startListening()
            pass
        else:
            f = ConsoleFactory(self, self.idx)
            self.listener = reactor.listenTCP(self.console_port, f)

    def connect(self, addr, conn):
        """Connect a TCP connection to the console.
        Fails if closed or already connected.

        addr peer address
        conn connection

        returns 0 if ok, negative otherwise
        """
        if self.closed(): return -1
        if self.connected(): return -1
        self.addr = addr
        self.conn = conn
        self.status = self.STATUS_CONNECTED
        self.handleOutput()
        return 0

    def disconnect(self, conn=None):
        """Disconnect the TCP connection to the console.
        """
        if conn and conn != self.conn: return
        if self.conn:
            self.conn.loseConnection()
        self.addr = None
        self.conn = None
        self.listen()

    def requestReceived(self, msg, type, subtype):
        """Receive console data from the console channel.

        msg     console message
        type    major message type
        subtype minor message typ
        """
        self.rbuf.write(msg.get_payload())
        self.handleOutput()
        
    def responseReceived(self, msg, type, subtype):
        """Handle a response to a request written to the console channel.
        Just ignore it because the return values are not interesting.

        msg     console message
        type    major message type
        subtype minor message typ
        """
        pass

    def produceRequests(self):
        """Write pending console data to the console channel.
        Writes as much to the channel as it can.
        """
        work = 0
        while self.channel and not self.wbuf.empty() and self.channel.writeReady():
            msg = xu.message(CMSG_CONSOLE, 0, 0)
            msg.append_payload(self.wbuf.read(msg.MAX_PAYLOAD))
            work += self.channel.writeRequest(msg, notify=0)
        return work

    def handleInput(self, conn, data):
        """Handle some external input aimed at the console.
        Called from a TCP connection (conn). Ignores the input
        if the calling connection (conn) is not the one connected
        to the console (self.conn).

        conn connection
        data input data
        """
        if self.closed(): return -1
        if conn != self.conn: return 0
        self.wbuf.write(data)
        if self.channel and self.produceRequests():
            self.channel.notify()
        return 0

    def handleOutput(self):
        """Handle buffered output from the console.
        Sends it to the connected console (if any).
        """
        if self.closed():
            return -1
        if not self.conn:
            return 0
        while not self.rbuf.empty():
            try:
                bytes = self.conn.write(self.rbuf.peek())
                if bytes > 0:
                    self.rbuf.discard(bytes)
            except socket.error, error:
                pass
        return 0
