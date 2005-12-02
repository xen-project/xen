#============================================================================
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd.
#============================================================================

import sys
import threading
import select
import socket
import fcntl

from errno import EAGAIN, EINTR, EWOULDBLOCK

"""General classes to support server and client sockets, without
specifying what kind of socket they are. There are subclasses
for TCP and unix-domain sockets (see tcp.py and unix.py).
"""

"""We make sockets non-blocking so that operations like accept()
don't block. We also select on a timeout. Otherwise we have no way
of getting the threads to shutdown.
"""
SELECT_TIMEOUT = 2.0

class SocketServerConnection:
    """An accepted connection to a server.
    """

    def __init__(self, sock, protocol, addr, server):
        self.sock = sock
        self.protocol = protocol
        self.addr = addr
        self.server = server
        self.buffer_n = 1024
        self.thread = None
        self.protocol.setTransport(self)

    def run(self):
        self.thread = threading.Thread(target=self.main)
        self.thread.start()

    def main(self):
        while True:
            if not self.thread: break
            if self.select(): break
            if not self.thread: break
            data = self.read()
            if data is None: continue
            if data is True: break
            if self.dataReceived(data): break

    def select(self):
        try:
            select.select([self.sock], [], [], SELECT_TIMEOUT)
            return False
        except socket.error, ex:
            if ex.args[0] in (EWOULDBLOCK, EAGAIN, EINTR):
                return False
            else:
                self.loseConnection(ex)
                return True

    def read(self):
        try:
            data = self.sock.recv(self.buffer_n)
            if data == '':
                self.loseConnection()
                return True
            return data
        except socket.error, ex:
            if ex.args[0] in (EWOULDBLOCK, EAGAIN, EINTR):
                return None
            else:
                self.loseConnection(ex)
                return True

    def dataReceived(self, data):
        try:
            self.protocol.dataReceived(data)
        except SystemExit:
            raise
        except Exception, ex:
            self.loseConnection(ex)
            return True
        return False

    def write(self, data):
        self.sock.send(data)

    def loseConnection(self, reason=None):
        self.thread = None
        self.closeSocket(reason)

    def closeSocket(self, reason):
        try:
            self.sock.close()
        except SystemExit:
            raise
        except:
            pass

class SocketListener:
    """A server socket, running listen in a thread.
    Accepts connections and runs a thread for each one.
    """

    def __init__(self, protocol_class, backlog=None):
        if backlog is None:
            backlog = 5
        self.protocol_class = protocol_class
        self.sock = None
        self.backlog = backlog
        self.thread = None

    def createSocket(self):
        raise NotImplementedError()

    def setCloExec(self):
        fcntl.fcntl(self.sock.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)

    def acceptConnection(self, sock, protocol, addr):
        return SocketServerConnection(sock, protocol, addr, self)

    def startListening(self):
        if self.sock or self.thread:
            raise IOError("already listening")
        self.sock = self.createSocket()
        self.sock.setblocking(0)
        self.sock.listen(self.backlog)
        self.run()

    def stopListening(self, reason=None):
        self.loseConnection(reason)

    def run(self):
        self.thread = threading.Thread(target=self.main)
        self.thread.start()

    def main(self):
        while True:
            if not self.thread: break
            if self.select(): break
            if self.accept(): break

    def select(self):
        try:
            select.select([self.sock], [], [], SELECT_TIMEOUT)
            return False
        except socket.error, ex:
            if ex.args[0] in (EWOULDBLOCK, EAGAIN, EINTR):
                return False
            else:
                self.loseConnection(ex)
                return True

    def accept(self):
        try:
            (sock, addr) = self.sock.accept()
            sock.setblocking(0)
            return self.accepted(sock, addr)
        except socket.error, ex:
            if ex.args[0] in (EWOULDBLOCK, EAGAIN, EINTR):
                return False
            else:
                self.loseConnection(ex)
                return True

    def accepted(self, sock, addr):
        self.acceptConnection(sock, self.protocol_class(), addr).run()
        return False

    def loseConnection(self, reason=None):
        self.thread = None
        self.closeSocket(reason)

    def closeSocket(self, reason):
        try:
            self.sock.close()
        except SystemExit:
            raise
        except Exception, ex:
            pass


class SocketClientConnection:
    """A connection to a server from a client.

    Call connectionMade() on the protocol in a thread when connected.
    It is completely up to the protocol what to do.
    """

    def __init__(self, connector):
        self.addr = None
        self.connector = connector
        self.buffer_n = 1024

    def createSocket (self):
        raise NotImplementedError()

    def write(self, data):
        if self.sock:
            return self.sock.send(data)
        else:
            return 0

    def connect(self, timeout):
        #todo: run a timer to cancel on timeout?
        try:
            sock = self.createSocket()
            sock.connect(self.addr)
            self.sock = sock
            self.protocol = self.connector.protocol_class()
            self.protocol.setTransport(self)
        except SystemExit:
            raise
        except Exception, ex:
            self.connector.connectionFailed(ex)
            return False

        self.thread = threading.Thread(target=self.main)
        #self.thread.setDaemon(True)
        self.thread.start()
        return True

    def main(self):
        try:
            # Call the protocol in a thread.
            # Up to it what to do.
            self.protocol.connectionMade(self.addr)
        except SystemExit:
            raise
        except Exception, ex:
            self.loseConnection(ex)

    def mainLoop(self):
        # Something a protocol could call.
        while True:
            if not self.thread: break
            if self.select(): break
            if not self.thread: break
            data = self.read()
            if data is None: continue
            if data is True: break
            if self.dataReceived(data): break

    def select(self):
        try:
            select.select([self.sock], [], [], SELECT_TIMEOUT)
            return False
        except socket.error, ex:
            if ex.args[0] in (EWOULDBLOCK, EAGAIN, EINTR):
                return False
            else:
                self.loseConnection(ex)
                return True

    def read(self):
        try:
            data = self.sock.recv(self.buffer_n)
            return data
        except socket.error, ex:
            if ex.args[0] in (EWOULDBLOCK, EAGAIN, EINTR):
                return None
            else:
                self.loseConnection(ex)
                return True
        
    def dataReceived(self, data):
        if not self.protocol:
            return True
        try:
            self.protocol.dataReceived(data)
        except SystemExit:
            raise
        except Exception, ex:
            self.loseConnection(ex)
            return True
        return False

    def loseConnection(self, reason=None):
        self.thread = None
        self.closeSocket(reason)

    def closeSocket(self, reason):
        try:
            if self.sock:
                self.sock.close()
        except SystemExit:
            raise
        except:
            pass

class SocketConnector:
    """A client socket. Connects to a server and runs the client protocol
    in a thread.
    """

    def __init__(self, protocol_class):
        self.protocol_class = protocol_class
        self.transport = None

    def connect(self):
        pass
