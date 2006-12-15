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
# Copyright (C) 2006 XenSource Inc.
#============================================================================
#
# Parts of this file are based upon xmlrpclib.py, the XML-RPC client
# interface included in the Python distribution.
#
# Copyright (c) 1999-2002 by Secret Labs AB
# Copyright (c) 1999-2002 by Fredrik Lundh
#
# By obtaining, using, and/or copying this software and/or its
# associated documentation, you agree that you have read, understood,
# and will comply with the following terms and conditions:
#
# Permission to use, copy, modify, and distribute this software and
# its associated documentation for any purpose and without fee is
# hereby granted, provided that the above copyright notice appears in
# all copies, and that both that copyright notice and this permission
# notice appear in supporting documentation, and that the name of
# Secret Labs AB or the author not be used in advertising or publicity
# pertaining to distribution of the software without specific, written
# prior permission.
#
# SECRET LABS AB AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD
# TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANT-
# ABILITY AND FITNESS.  IN NO EVENT SHALL SECRET LABS AB OR THE AUTHOR
# BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
# --------------------------------------------------------------------

import xmlrpclib

import xen.util.xmlrpclib2


class Failure(Exception):
    def __init__(self, details):
        self.details = details

    def __str__(self):
        return "Xen-API failure: %s" % str(self.details)


class Session(xen.util.xmlrpclib2.ServerProxy):
    """A server proxy and session manager for communicating with Xend using
    the Xen-API.

    Example:

    session = Session('http://localhost:9363/')
    session.login_with_password('me', 'mypassword')
    session.xenapi.VM.start(vm_uuid)
    session.xenapi.session.logout()

    For now, this class also supports the legacy XML-RPC API, using
    session.xend.domain('Domain-0') and similar.  This support will disappear
    once there is a working Xen-API replacement for every call in the legacy
    API.
    """

    def __init__(self, uri, transport=None, encoding=None, verbose=0,
                 allow_none=1):
        xen.util.xmlrpclib2.ServerProxy.__init__(self, uri, transport,
                                                 encoding, verbose,
                                                 allow_none)
        self._session = None


    def xenapi_request(self, methodname, params):
        if methodname.startswith('login'):
            self._login(methodname, *params)
            return None
        else:
            full_params = (self._session,) + params
            return _parse_result(getattr(self, methodname)(*full_params))


    def _login(self, method, username, password):
        self._session = _parse_result(
            getattr(self, 'session.%s' % method)(username, password))


    def __getattr__(self, name):
        if name == 'xenapi':
            return _Dispatcher(self.xenapi_request, None)
        elif name.startswith('login'):
            return lambda u, p: self._login(name, u, p)
        else:
            return xen.util.xmlrpclib2.ServerProxy.__getattr__(self, name)


def _parse_result(result):
    if 'Status' not in result:
        raise xmlrpclib.Fault(500, 'Missing Status in response from server')
    if result['Status'] == 'Success':
        if 'Value' in result:
            return result['Value']
        else:
            raise xmlrpclib.Fault(500,
                                  'Missing Value in response from server')
    else:
        if 'ErrorDescription' in result:
            raise Failure(result['ErrorDescription'])
        else:
            raise xmlrpclib.Fault(
                500, 'Missing ErrorDescription in response from server')


# Based upon _Method from xmlrpclib.
class _Dispatcher:
    def __init__(self, send, name):
        self.__send = send
        self.__name = name
    def __getattr__(self, name):
        if self.__name is None:
            return _Dispatcher(self.__send, name)
        else:
            return _Dispatcher(self.__send, "%s.%s" % (self.__name, name))
    def __call__(self, *args):
        return self.__send(self.__name, args)
