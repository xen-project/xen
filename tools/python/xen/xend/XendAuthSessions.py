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
    """Keeps track of Xen API Login Sessions using PAM.

    Note: Login sessions are not valid across instances of Xend.
    """
    def __init__(self):
        self.sessions = {}

    def init(self):
        pass

    def login_unconditionally(self, username):
        """Returns a session UUID if valid.

        @rtype: string
        @return: Session UUID
        """
        new_session = uuid.createString()
        self.sessions[new_session] = (username, time.time())
        return new_session

    def login_with_password(self, username, password):
        """Returns a session UUID if valid, otherwise raises an error.

        @raises XendError: If login fails.
        @rtype: string
        @return: Session UUID
        """
        if self.is_authorized(username, password):
            return self.login_unconditionally(username)

        raise XendError("Login failed")

    def logout(self, session):
        """Delete session of it exists."""
        if self.is_session_valid(session):
            del self.sessions[session]

    def is_session_valid(self, session):
        """Returns true is session is valid."""
        if type(session) == type(str()):
            return (session in self.sessions)
        return False

    def is_authorized(self, username, password):
        """Returns true is a user is authorised via PAM.

        Note: We use the 'login' PAM stack rather than inventing
              our own.

        @rtype: boolean
        """
        pam_auth = None
        try:
            import PAM
            pam_auth = PAM.pam()
        except ImportError:
            log.warn("python-pam is required for XenAPI support.")
            return False
        except NameError:
            # if PAM doesn't exist, let's ignore it
            return False
        
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
