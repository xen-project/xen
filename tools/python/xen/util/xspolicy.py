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
# Copyright (C) 2006,2007 International Business Machines Corp.
# Author: Stefan Berger <stefanb@us.ibm.com>
#============================================================================

import threading
import xsconstants

class XSPolicy:
    """
       The base policy class for all policies administered through
       XSPolicyAdmin.
    """

    def __init__(self, name=None, ref=None):
        self.lock = threading.Lock()
        self.ref = ref
        self.name = name
        if ref:
            from xen.xend.XendXSPolicy import XendXSPolicy
            self.xendxspolicy = XendXSPolicy(self, {}, ref)
        else:
            self.xendxspolicy = None

    def grab_lock(self):
        self.lock.acquire()

    def unlock(self):
        self.lock.release()

    def get_ref(self):
        return self.ref

    def destroy(self):
        if self.xendxspolicy:
            self.xendxspolicy.destroy()

    # All methods below should be overwritten by the inheriting class

    def isloaded(self):
        return False

    def loadintohv(self):
        return xsconstants.XSERR_POLICY_LOAD_FAILED

    def get_type(self):
        return xsconstants.XS_POLICY_NONE

    def get_type_name(self):
        return ""

    def update(self, repr_new):
        return -xsconstants.XSERR_GENERAL_FAILURE, ""
