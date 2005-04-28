# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import socket
import threading
from errno import EAGAIN, EINTR, EWOULDBLOCK
    
from xen.web import reactor, protocol

from xen.lowlevel import xu

from xen.xend.XendError import XendError
from xen.xend import EventServer; eserver = EventServer.instance()
from xen.xend.XendLogging import log
from xen.xend import XendRoot; xroot = XendRoot.instance()
from xen.xend import sxp

from controller import CtrlMsgRcvr, Dev, DevController
from messages import *
from params import *

class ConsoleProtocol(protocol.Protocol):
    """Asynchronous handler for a console socket.
    """

    def __init__(self, console, id):
        self.console = console
        self.id = id
        self.addr = None

    def connectionMade(self, addr=None):
        peer = self.transport.getPeer()
        self.addr = addr
        if self.console.connect(self.addr, self):
            self.transport.write("Cannot connect to console %d on domain %d\n"
                                 % (self.id, self.console.getDomain()))
            self.loseConnection()
            return
        else:
            if len(self.addr) == 2:
                host = str(self.addr[0])
                port = str(self.addr[1])
            else:
                host = 'localhost'
                port = str(addr)
            log.info("Console connected %s %s %s",
                     self.id, host, port)
            eserver.inject('xend.console.connect',
                           [self.id, host, port])

    def dataReceived(self, data):
        if self.console.receiveInput(self, data):
            self.loseConnection()

    def write(self, data):
        self.transport.write(data)
        return len(data)

    def connectionLost(self, reason=None):
        log.info("Console disconnected %s %s %s",
                 str(self.id), str(self.addr[0]), str(self.addr[1]))
        eserver.inject('xend.console.disconnect',
                       [self.id, self.addr[0], self.addr[1]])
        self.console.disconnect(conn=self)

    def loseConnection(self):
        self.transport.loseConnection()

class ConsoleDev(Dev, protocol.ServerFactory):
    """Console device for a domain.
    Does not poll for i/o itself, but relies on the domain to post console
    output and the connected TCP sockets to post console input.
    """

    STATUS_NEW       = 'new'
    STATUS_CLOSED    = 'closed'
    STATUS_CONNECTED = 'connected'
    STATUS_LISTENING = 'listening'

    def __init__(self, controller, id, config, recreate=False):
        Dev.__init__(self, controller, id, config)
        self.lock = threading.RLock()
        self.status = self.STATUS_NEW
        self.addr = None
        self.conn = None
        self.console_port = None
        self.obuf = xu.buffer()
        self.ibuf = xu.buffer()
        self.channel = None
        self.listening = False
        self.unix_listener = None
        self.tcp_listener = None
        
        console_port = sxp.child_value(self.config, "console_port")
        if console_port is None:
            console_port = xroot.get_console_port_base() + self.getDomain()
        self.checkConsolePort(console_port)
        self.console_port = console_port
        
        log.info("Created console id=%d domain=%d port=%d",
                 self.id, self.getDomain(), self.console_port)
        eserver.inject('xend.console.create',
                       [self.id, self.getDomain(), self.console_port])

    def init(self, recreate=False, reboot=False):
        try:
            self.lock.acquire()
            self.destroyed = False
            self.channel = self.getChannel()
            self.listen()
        finally:
            self.lock.release()

    def checkConsolePort(self, console_port):
        """Check that a console port is not in use by another console.
        """
        xd = XendRoot.get_component('xen.xend.XendDomain')
        for vm in xd.domains():
            ctrl = vm.getDeviceController(self.getType(), error=False)
            if (not ctrl): continue
            ctrl.checkConsolePort(console_port)
    
    def sxpr(self):
        try:
            self.lock.acquire()
            val = ['console',
                   ['status', self.status ],
                   ['id',     self.id    ],
                   ['domain', self.getDomain() ] ]
            val.append(['local_port',   self.getLocalPort()  ])
            val.append(['remote_port',  self.getRemotePort() ])
            val.append(['console_port', self.console_port    ])
            val.append(['index', self.getIndex()])
            if self.addr:
                val.append(['connected', self.addr[0], self.addr[1]])
        finally:
            self.lock.release()
        return val

    def getLocalPort(self):
        try:
            self.lock.acquire()
            if self.channel:
                return self.channel.getLocalPort()
            else:
                return 0
        finally:
            self.lock.release()

    def getRemotePort(self):
        try:
            self.lock.acquire()
            if self.channel:
                return self.channel.getRemotePort()
            else:
                return 0
        finally:
            self.lock.release()

    def uri(self):
        """Get the uri to use to connect to the console.
        This will be a telnet: uri.

        return uri
        """
        host = socket.gethostname()
        return "telnet://%s:%d" % (host, self.console_port)

    def closed(self):
        return self.status == self.STATUS_CLOSED

    def connected(self):
        return self.status == self.STATUS_CONNECTED

    def destroy(self, change=False, reboot=False):
        """Close the console.
        """
        print 'ConsoleDev>destroy>', self, reboot
        if reboot:
            return
        try:
            self.lock.acquire()
            self.status = self.STATUS_CLOSED
            self.listening = False
            if self.conn:
                self.conn.loseConnection()
            if self.tcp_listener:
                self.tcp_listener.stopListening()
                self.tcp_listener = None
            if self.unix_listener:
                self.unix_listener.stopListening()
                self.unix_listener = None
        finally:
            self.lock.release()

    def listen(self):
        """Listen for TCP connections to the console port..
        """
        try:
            self.lock.acquire()
            if self.closed():
                return
            if self.listening:
                pass
            else:
                self.listening = True
                self.status = self.STATUS_LISTENING
                if xroot.get_xend_unix_server():
                    path = '/var/lib/xend/console-%s' % self.console_port
                    self.unix_listener = reactor.listenUNIX(path, self)
                if xroot.get_xend_http_server():
                    interface = xroot.get_console_address()
                    self.tcp_listener = reactor.listenTCP(self.console_port, self, interface=interface)
        finally:
            self.lock.release()

    def buildProtocol(self, addr):
        """Factory function called to create the protocol when a connection is accepted
        by listenTCP.
        """
        proto = ConsoleProtocol(self, self.id)
        proto.factory = self
        return proto

    def connect(self, addr, conn):
        """Connect a TCP connection to the console.
        Fails if closed or already connected.

        addr peer address
        conn connection

        returns 0 if ok, negative otherwise
        """
        try:
            self.lock.acquire()
            if self.closed():
                return -1
            if self.connected():
                return -1
            self.addr = addr
            self.conn = conn
            self.status = self.STATUS_CONNECTED
            self.writeOutput()
        finally:
            self.lock.release()
        return 0

    def disconnect(self, conn=None):
        """Disconnect the TCP connection to the console.
        """
        print 'ConsoleDev>disconnect>', conn
        try:
            self.lock.acquire()
            if conn and conn != self.conn: return
            if self.conn:
                self.conn.loseConnection()
            self.addr = None
            self.conn = None
            self.status = self.STATUS_LISTENING
            self.listen()
        finally:
            self.lock.release()

    def receiveOutput(self, msg):
        """Receive output console data from the console channel.

        msg     console message
        type    major message type
        subtype minor message typ
        """
        # Treat the obuf as a ring buffer.
        try:
            self.lock.acquire()
            data = msg.get_payload()
            data_n = len(data)
            if self.obuf.space() < data_n:
                self.obuf.discard(data_n)
            if self.obuf.space() < data_n:
                data = data[-self.obuf.space():]
            self.obuf.write(data)
            self.writeOutput()
        finally:
            self.lock.release()
        
    def writeOutput(self):
        """Handle buffered output from the console device.
        Sends it to the connected TCP connection (if any).
        """
        try:
            self.lock.acquire()
            if self.closed():
                return -1
            writes = 0
            while self.conn and (writes < 100) and (not self.obuf.empty()):
                try:
                    writes += 1
                    bytes = self.conn.write(self.obuf.peek())
                    if bytes > 0:
                        self.obuf.discard(bytes)
                except socket.error, err:
                    if err.args[0] in (EWOULDBLOCK, EAGAIN, EINTR):
                        pass
                    else:
                        self.disconnect()
                        break
                        
        finally:
            self.lock.release()
        return 0
    
    def receiveInput(self, conn, data):
        """Receive console input from a TCP connection.  Ignores the
        input if the calling connection (conn) is not the one
        connected to the console (self.conn).

        conn connection
        data input data
        """
        try:
            self.lock.acquire()
            if self.closed(): return -1
            if conn != self.conn: return 0
            self.ibuf.write(data)
            self.writeInput()
        finally:
            self.lock.release()
        return 0

    def writeInput(self):
        """Write pending console input to the console channel.
        Writes as much to the channel as it can.
        """
        try:
            self.lock.acquire()
            while self.channel and not self.ibuf.empty():
                msg = xu.message(CMSG_CONSOLE, 0, 0)
                msg.append_payload(self.ibuf.read(msg.MAX_PAYLOAD))
                self.channel.writeRequest(msg)
        finally:
            self.lock.release()

class ConsoleController(DevController):
    """Device controller for all the consoles for a domain.
    """

    def __init__(self, vm, recreate=False):
        DevController.__init__(self, vm, recreate=recreate)
        self.rcvr = None

    def initController(self, recreate=False, reboot=False):
        self.destroyed = False
        self.rcvr = CtrlMsgRcvr(self.getChannel())
        self.rcvr.addHandler(CMSG_CONSOLE,
                             0,
                             self.receiveOutput)
        self.rcvr.registerChannel()
        if reboot:
            self.rebootDevices()

    def destroyController(self, reboot=False):
        print 'ConsoleController>destroyController>', self, reboot
        self.destroyed = True
        self.destroyDevices(reboot=reboot)
        self.rcvr.deregisterChannel()

    def newDevice(self, id, config, recreate=False):
        return ConsoleDev(self, id, config, recreate=recreate)

    def checkConsolePort(self, console_port):
        """Check that a console port is not in use by a console.
        """
        for c in self.getDevices():
            if c.console_port == console_port:
                raise XendError('console port in use: ' + str(console_port))

    def receiveOutput(self, msg):
        """Handle a control request.
        The CMSG_CONSOLE messages just contain data, and no console id,
        so just send to console 0 (if there is one).

        todo: extend CMSG_CONSOLE to support more than one console?
        """
        console = self.getDevice(0)
        if console:
            console.receiveOutput(msg)
        else:
            log.warning('no console: domain %d', self.getDomain())

