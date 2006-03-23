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
# Copyright (C) 2006 Anthony Liguori <aliguori@us.ibm.com>
#============================================================================

"""
An enhanced XML-RPC client/server interface for Python.
"""

from httplib import HTTPConnection, HTTP
from xmlrpclib import Transport
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import xmlrpclib, socket, os, traceback

# A new ServerProxy that also supports httpu urls.  An http URL comes in the
# form:
#
# httpu:///absolute/path/to/socket.sock
#
# It assumes that the RPC handler is /RPC2.  This probably needs to be improved

class HTTPUnixConnection(HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.host)

class HTTPUnix(HTTP):
    _connection_class = HTTPUnixConnection

class UnixTransport(Transport):
    def request(self, host, handler, request_body, verbose=0):
        self.__handler = handler
        return Transport.request(self, host, '/RPC2', request_body, verbose)
    def make_connection(self, host):
        return HTTPUnix(self.__handler)

class ServerProxy(xmlrpclib.ServerProxy):
    def __init__(self, uri, transport=None, encoding=None, verbose=0,
                 allow_none=1):
        if transport == None:
            (protocol, rest) = uri.split(':', 1)
            if protocol == 'httpu':
                uri = 'http:' + rest
                transport = UnixTransport()
        xmlrpclib.ServerProxy.__init__(self, uri, transport, encoding,
                                       verbose, allow_none)

# This is a base XML-RPC server for TCP.  It sets allow_reuse_address to
# true, and has an improved marshaller that serializes unknown exceptions
# with full traceback information.

class TCPXMLRPCServer(SimpleXMLRPCServer):
    allow_reuse_address = True

    def _marshaled_dispatch(self, data, dispatch_method = None):
        params, method = xmlrpclib.loads(data)
        try:
            if dispatch_method is not None:
                response = dispatch_method(method, params)
            else:
                response = self._dispatch(method, params)

            response = (response,)
            response = xmlrpclib.dumps(response,
                                       methodresponse=1,
                                       allow_none=1)
        except xmlrpclib.Fault, fault:
            response = xmlrpclib.dumps(fault)
        except:
            response = xmlrpclib.dumps(
                xmlrpclib.Fault(1, traceback.format_exc())
                )

        return response

# This is a XML-RPC server that sits on a Unix domain socket.
# It implements proper support for allow_reuse_address by
# unlink()'ing an existing socket.

class UnixXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    def address_string(self):
        try:
            return SimpleXMLRPCRequestHandler.address_string(self)
        except ValueError, e:
            return self.client_address[:2]

class UnixXMLRPCServer(TCPXMLRPCServer):
    address_family = socket.AF_UNIX

    def __init__(self, addr, logRequests):
        if self.allow_reuse_address:
            try:
                os.unlink(addr)
            except OSError, exc:
                pass
        TCPXMLRPCServer.__init__(self, addr, UnixXMLRPCRequestHandler,
                                 logRequests)
