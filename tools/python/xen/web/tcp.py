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


import errno
import re
import socket
import time

import connection

from xen.xend.XendLogging import log


class TCPListener(connection.SocketListener):

    def __init__(self, protocol_class, port, interface, hosts_allow):
        self.port = port
        self.interface = interface
        self.hosts_allow = hosts_allow
        connection.SocketListener.__init__(self, protocol_class)


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


    def acceptConnection(self, sock, addrport):
        addr = addrport[0]
        if self.hosts_allow is None:
                connection.SocketServerConnection(sock, self.protocol_class)
        else:
            fqdn = socket.getfqdn(addr)
            for h in self.hosts_allow:
                if h.match(fqdn) or h.match(addr):
                    log.debug("Match %s %s", fqdn, h.pattern)
                    connection.SocketServerConnection(sock,
                                                      self.protocol_class)
                    return

            try:
                log.warn("Rejected connection from %s:%d (%s) for port %d.",
                         addr, addrport[1], fqdn, self.port)
                sock.close()
            except:
                pass
