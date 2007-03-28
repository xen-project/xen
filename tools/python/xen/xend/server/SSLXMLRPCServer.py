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
# Copyright (C) 2007 XenSource Inc.
#============================================================================


"""
HTTPS wrapper for an XML-RPC server interface.  Requires PyOpenSSL (Debian
package python-pyopenssl).
"""

import socket

from OpenSSL import SSL

from xen.util.xmlrpclib2 import XMLRPCRequestHandler, TCPXMLRPCServer


class SSLXMLRPCRequestHandler(XMLRPCRequestHandler):
    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

#
# Taken from pyOpenSSL-0.6 examples (public-domain)
#

class SSLWrapper:
    """
    """
    def __init__(self, conn):
        """
        Connection is not yet a new-style class,
        so I'm making a proxy instead of subclassing.
        """
        self.__dict__["conn"] = conn
    def __getattr__(self, name):
        return getattr(self.__dict__["conn"], name)
    def __setattr__(self, name, value):
        setattr(self.__dict__["conn"], name, value)

    def close(self):
        self.shutdown()
        return self.__dict__["conn"].close()

    def shutdown(self, how=1):
        """
        SimpleXMLRpcServer.doPOST calls shutdown(1),
        and Connection.shutdown() doesn't take
        an argument. So we just discard the argument.
        """
        # Block until the shutdown is complete
        self.__dict__["conn"].shutdown()
        self.__dict__["conn"].shutdown()

    def accept(self):
        """
        This is the other part of the shutdown() workaround.
        Since servers create new sockets, we have to infect
        them with our magic. :)
        """
        c, a = self.__dict__["conn"].accept()
        return (SSLWrapper(c), a)

#
# End of pyOpenSSL-0.6 example code.
#

class SSLXMLRPCServer(TCPXMLRPCServer):
    def __init__(self, addr, allowed, xenapi, logRequests = 1,
                 ssl_key_file = None, ssl_cert_file = None):

        TCPXMLRPCServer.__init__(self, addr, allowed, xenapi,
                                 SSLXMLRPCRequestHandler, logRequests)

        if not ssl_key_file or not ssl_cert_file:
            raise ValueError("SSLXMLRPCServer requires ssl_key_file "
                             "and ssl_cert_file to be set.")

        # make a SSL socket
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.use_privatekey_file (ssl_key_file)
        ctx.use_certificate_file(ssl_cert_file)
        self.socket = SSLWrapper(SSL.Connection(ctx,
                                 socket.socket(self.address_family,
                                               self.socket_type)))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_bind()
        self.server_activate()
