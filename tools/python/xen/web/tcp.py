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


import socket
import time
import errno

from connection import *


class TCPListener(SocketListener):

    def __init__(self, port, protocol, backlog=None, interface=''):
        SocketListener.__init__(self, protocol, backlog=backlog)
        self.port = port
        self.interface = interface
        
    def createSocket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # SO_REUSEADDR does not always ensure that we do not get an address
        # in use error when restarted quickly
        # we implement a timeout to try and avoid failing unnecessarily
        timeout = time.time() + 30
        while True:
            try:
                sock.bind((self.interface, self.port))
                return sock
            except socket.error, (_errno, strerrno):
                if _errno == errno.EADDRINUSE and time.time() < timeout:
                    time.sleep(0.5)
                else:
                    raise

    def acceptConnection(self, sock, protocol, addr):
        return SocketServerConnection(sock, protocol, addr, self)


def listenTCP(port, protocol, interface='', backlog=None):
    l = TCPListener(port, protocol, interface=interface, backlog=backlog)
    l.listen()
    l.setCloExec()
