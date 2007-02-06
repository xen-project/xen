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

import atexit
import os
import sys
from XmTestLib import *
from xen.xm import main as xmmain
from xen.xm import XenAPI
from xen.xm.opts import OptionError
from types import DictType
import xml.dom.minidom

def get_login_pwd():
    if xmmain.serverType == xmmain.SERVER_XEN_API:
        try:
            login, password = xmmain.parseAuthentication()
            return (login, password)
        except:
            raise OptionError("Configuration for login/pwd not found. "
                              "Need to run xapi-setup.py?")
    raise OptionError("Xm configuration file not using Xen-API for "
                      "communication with xend.")

sessions=[]

def connect(*args):
    try:
        creds = get_login_pwd()
    except Exception, e:
        FAIL("%s" % str(e))
    try:
        session = XenAPI.Session(xmmain.serverURI)
    except:
        raise OptionError("Could not create XenAPI session with Xend." \
                          "URI=%s" % xmmain.serverURI)
    try:
        session.login_with_password(*creds)
    except:
        raise OptionError("Could not login to Xend. URI=%s" % xmmain.serverURI)
    def logout():
        try:
            for s in sessions:
                s.xenapi.session.logout()
        except:
            pass
    sessions.append(session)
    atexit.register(logout)
    return session
