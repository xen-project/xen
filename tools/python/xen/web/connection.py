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

BUFFER_SIZE = 1024


class SocketServerConnection:
    """An accepted connection to a server.
    """

    def __init__(self, sock, protocol, addr, server):
        self.sock = sock
        self.protocol = protocol
        self.addr = addr
        self.server = server
        self.protocol.setTransport(self)


    def run(self):
        threading.Thread(target=self.main).start()


    def main(self):
        try:
            while True:
                try:
                    data = self.sock.recv(BUFFER_SIZE)
                    if data == '':
                        break
                    if self.protocol.dataReceived(data):
                        break
                except socket.error, ex:
                    if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                        break
        finally:
            try:
                self.sock.close()
            except:
                pass


    def write(self, data):
        self.sock.send(data)


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


    def listen(self):
        if self.sock or self.thread:
            raise IOError("already listening")
        self.sock = self.createSocket()
        self.sock.listen(self.backlog)
        self.run()


    def run(self):
        self.thread = threading.Thread(target=self.main)
        self.thread.start()


    def main(self):
        try:
            while True:
                try:
                    (sock, addr) = self.sock.accept()
                    self.acceptConnection(sock, self.protocol_class(),
                                          addr).run()
                except socket.error, ex:
                    if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                        break
        finally:
            try:
                self.sock.close()
            except:
                pass
