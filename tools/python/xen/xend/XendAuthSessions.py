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
import PAM

from xen.xend import uuid
from xen.xend.XendError import *
from xen.xend.XendLogging import log

class XendAuthSessions:
    """Keeps track of Xen API Login Sessions. (Example only)"""

    def __init__(self):
        self.sessions = {}

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
        pam_auth = PAM.pam()
        pam_auth.start("login")
        pam_auth.set_item(PAM.PAM_USER, username)

        def _pam_conv(auth, query_list, user_data):
            resp = []
            for i in range(len(query_list)):
                query, qtype = query_list[i]
                if qtype == PAM.PAM_PROMPT_ECHO_ON:
                    resp.append((username, 0))
                elif qtype == PAM.PAM_PROMPT_ECHO_OFF:
                    resp.append((password, 0))
                else:
                    return None
            return resp

        pam_auth.set_item(PAM.PAM_CONV, _pam_conv)
        
        try:
            pam_auth.authenticate()
            pam_auth.acct_mgmt()
        except PAM.error, resp:
            return False
        except Exception, e:
            log.warn("Error with PAM: %s" % str(e))
            return False
        else:
            return True

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


