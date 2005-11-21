#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd.
#============================================================================

import sys
import socket
import os
import os.path

from connection import *
from protocol import *

class UnixListener(SocketListener):

    def __init__(self, path, protocol, backlog=None):
        SocketListener.__init__(self, protocol, backlog=backlog)
        self.path = path
        
    def createSocket(self):
        pathdir = os.path.dirname(self.path)
        if not os.path.exists(pathdir):
            os.makedirs(pathdir)
        else:
            try:
                os.unlink(self.path)
            except SystemExit:
                raise
            except Exception, ex:
                pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.path)
        return sock

    def acceptConnection(self, sock, protocol, addr):
        return SocketServerConnection(sock, protocol, self.path, self)

class UnixClientConnection(SocketClientConnection):

    def __init__(self, addr, connector):
        SocketClientConnection.__init__(self, connector)
        self.addr = addr
        
    def createSocket(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        return sock
    
class UnixConnector(SocketConnector):

    def __init__(self, path, protocol, timeout=None):
        SocketConnector.__init__(self, protocol)
        self.addr = path
        self.timeout = timeout

    def connect(self):
        self.transport = UnixClientConnection(self.addr, self)
        self.transport.connect(self.timeout)

def listenUNIX(path, protocol, backlog=None):
    l = UnixListener(path, protocol, backlog=backlog)
    l.startListening()
    return l

def connectUNIX(path, protocol, timeout=None):
    c = UnixConnector(path, protocol, timeout=timeout)
    c.connect()
    return c
