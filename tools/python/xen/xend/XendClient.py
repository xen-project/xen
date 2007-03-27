#!/usr/bin/env python
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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2006 Anthony Liguori <aliguori@us.ibm.com>
#============================================================================

from xen.util.xmlrpcclient import ServerProxy
import os
import sys

XML_RPC_SOCKET = "/var/run/xend/xmlrpc.sock"
XEN_API_SOCKET = "/var/run/xend/xen-api.sock"

ERROR_INTERNAL = 1
ERROR_GENERIC = 2
ERROR_INVALID_DOMAIN = 3

uri = 'httpu:///var/run/xend/xmlrpc.sock'
if os.environ.has_key('XM_SERVER'):
    uri = os.environ['XM_SERVER']

try:
    server = ServerProxy(uri)
except ValueError, exn:
    print >>sys.stderr, exn
    sys.exit(1)

