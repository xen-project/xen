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
# Copyright (C) 2009 flonatel GmbH & Co. KG
#============================================================================

import atexit
import os
import sys
from XmTestLib import *
from xen.xm import main as xmmain
from xen.xm import XenAPI
from xen.xm.opts import OptionError
from types import DictType
import xml.dom.minidom

sessions=[]

def connect(*args):
    creds = ("", "")
    uri = "http://localhost:9363"

    try:
        session = XenAPI.Session(uri)
    except:
        raise OptionError("Could not create XenAPI session with Xend." \
                          "URI=%s" % uri)
    try:
        session.login_with_password(*creds)
    except:
        raise OptionError("Could not login to Xend. URI=%s" % uri)
    def logout():
        try:
            for s in sessions:
                s.xenapi.session.logout()
        except:
            pass
    sessions.append(session)
    atexit.register(logout)
    return session
