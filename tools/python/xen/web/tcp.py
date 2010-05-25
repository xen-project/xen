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
import fcntl     # For get_interface_addr
import struct    # For get_interface_addr

import connection

from xen.xend.XendLogging import log


class TCPListener(connection.SocketListener):

    def __init__(self, protocol_class, port, interface, hosts_allow):
        self.port = port
        self.interface = interface
        self.hosts_allow = hosts_allow
        connection.SocketListener.__init__(self, protocol_class)

    def isValidHex(self, word):
        # If we have empty word we treat it as valid
        if len(word) == 0:
            return True
        try:
            int(word, 16)
            return True
        except ValueError:
            return False

    def isValidIP(self, ipaddr):
        # Check for IPv4 address
        numValid = 0
        tmp = ipaddr.split('.')
        for byte in tmp:
            if byte.isdigit():
                numValid += 1

        if numValid == len(tmp):
            return True

        # Check for IPv6 address
        numValid = 0
        tmp = ipaddr.split(':')
        for word in tmp:
            if self.isValidHex(word):
                numValid += 1

        return numValid == len(tmp)

    def getIfAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            x = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15])
            )[20:24])
            s.close()
        except Exception, e:
            x = ifname

        return x

    def createSocket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # SO_REUSEADDR does not always ensure that we do not get an address
        # in use error when restarted quickly
        # we implement a timeout to try and avoid failing unnecessarily
        timeout = time.time() + 30
        while True:
            try:
                if not self.isValidIP(self.interface):
                    self.interface = self.getIfAddr(self.interface)
                log.debug("Listening on %s:%s" % (self.interface, self.port))
                sock.bind((self.interface, self.port))
                return sock
            except socket.error, (_errno, strerrno):
                if _errno == errno.EADDRINUSE and time.time() < timeout:
                    time.sleep(0.5)
                else:
                    raise


    def acceptConnection(self, sock, addrport):
        addr = addrport[0]
        if connection.hostAllowed(addrport, self.hosts_allow):
            connection.SocketServerConnection(sock, self.protocol_class)
        else:
            try:
                sock.close()
            except:
                pass

class SSLTCPListener(TCPListener):

    def __init__(self, protocol_class, port, interface, hosts_allow,
                 ssl_key_file = None, ssl_cert_file = None):
        if not ssl_key_file or not ssl_cert_file:
            raise ValueError("SSLXMLRPCServer requires ssl_key_file "
                             "and ssl_cert_file to be set.")

        self.ssl_key_file = ssl_key_file
        self.ssl_cert_file = ssl_cert_file

        TCPListener.__init__(self, protocol_class, port, interface, hosts_allow)

    def isValidHex(self, word):
        # If we have empty word we treat it as valid
        if len(word) == 0:
            return True
        try:
            int(word, 16)
            return True
        except ValueError:
            return False

    def isValidIP(self, ipaddr):
        # Check for IPv4 address
        numValid = 0
        tmp = ipaddr.split('.')
        for byte in tmp:
            if byte.isdigit():
                numValid += 1

        if numValid == len(tmp):
            return True

        # Check for IPv6 address
        numValid = 0
        tmp = ipaddr.split(':')
        for word in tmp:
            if self.isValidHex(word):
                numValid += 1

        return numValid == len(tmp)

    def getIfAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            x = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15])
            )[20:24])
            s.close()
        except Exception, e:
            x = ifname

        return x

    def createSocket(self):
        from OpenSSL import SSL
        # make a SSL socket
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.use_privatekey_file (self.ssl_key_file)
        ctx.use_certificate_file(self.ssl_cert_file)
        sock = SSL.Connection(ctx,
                              socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.set_accept_state()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # SO_REUSEADDR does not always ensure that we do not get an address
        # in use error when restarted quickly
        # we implement a timeout to try and avoid failing unnecessarily
        timeout = time.time() + 30
        while True:
            try:
                if not self.isValidIP(self.interface):
                    self.interface = self.getIfAddr(self.interface)
                log.debug("Listening on %s:%s" % (self.interface, self.port))
                sock.bind((self.interface, self.port))
                return sock
            except socket.error, (_errno, strerrno):
                if _errno == errno.EADDRINUSE and time.time() < timeout:
                    time.sleep(0.5)
                else:
                    raise


    def acceptConnection(self, sock, addrport):
        addr = addrport[0]
        if connection.hostAllowed(addrport, self.hosts_allow):
            connection.SSLSocketServerConnection(sock, self.protocol_class)
        else:
            try:
                sock.close()
            except:
                pass

