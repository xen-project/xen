#!/usr/bin/python
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
# Copyright (C) 2006 XenSource Ltd.
# Copyright (C) 2006 IBM Corporation
#============================================================================

import os
import sys
from XmTestLib import *
from xen.util.xmlrpclib2 import ServerProxy
from types import DictType


XAPI_DEFAULT_LOGIN = " "
XAPI_DEFAULT_PASSWORD = " "

class XenAPIError(Exception):
    pass


#A list of VMs' UUIDs that were created using vm_create
_VMuuids = []

#Terminate previously created managed(!) VMs and destroy their configs
def vm_destroy_all():
    server, session = _connect()
    for uuid in _VMuuids:
        execute(server.VM.hard_shutdown, session, uuid)
        execute(server.VM.destroy      , session, uuid)


def execute(fn, *args):
    result = fn(*args)
    if type(result) != DictType:
        raise TypeError("Function returned object of type: %s" %
                        str(type(result)))
    if 'Value' not in result:
        raise XenAPIError(*result['ErrorDescription'])
    return result['Value']

_initialised = False
_server = None
_session = None
def _connect(*args):
    global _server, _session, _initialised
    if not _initialised:
        _server = ServerProxy('httpu:///var/run/xend/xmlrpc.sock')
        login = XAPI_DEFAULT_LOGIN
        password = XAPI_DEFAULT_PASSWORD
        creds = (login, password)
        _session = execute(_server.session.login_with_password, *creds)
        _initialised = True
    return (_server, _session)
