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
#============================================================================

import time

from xen.xend import uuid
from xen.xend.XendError import *
from xen.xend.XendLogging import log

class XendAuthSessions:
    """Keeps track of Xen API Login Sessions. (Example only)"""

    def __init__(self):
        self.sessions = {}
        self.users = {'atse': 'passwd'}

    def init(self):
        pass

    def login_with_password(self, username, password):
        if self.is_authorized(username, password):
            new_session = uuid.createString()
            self.sessions[new_session] = (username, time.time())
            return new_session

        raise XendError("Login failed")

    def logout(self, session):
        if self.is_session_valid(session):
            del self.sessions[session]

    def is_session_valid(self, session):
        if type(session) == type(str()):
            return (session in self.sessions)
        return False
    
    def is_authorized(self, username, password):
        if username in self.users and self.users[username] == password:
            return True
        return False

    def get_user(self, session):
        try:
            return self.sessions[session][0]
        except (KeyError, IndexError):
            return None


def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendAuthSessions()
        inst.init()
    return inst

# Handy Authentication Decorators
# -------------------------------
def session_required(func):
    def check_session(self, session, *args, **kwargs):
        if instance().is_session_valid(session):
            return func(self, session, *args, **kwargs)
        else:
            return {'Status': 'Failure',
                    'ErrorDescription': XEND_ERROR_SESSION_INVALID}
    return check_session


