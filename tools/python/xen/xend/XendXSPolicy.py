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
# Copyright (c) 2007 IBM Corporation
# Copyright (c) 2006 Xensource
#============================================================================

import base64
import logging
from xen.xend import XendDomain
from xen.xend.XendBase import XendBase
from xen.xend.XendError import *
from xen.xend.XendAPIConstants import *
from xen.xend.XendXSPolicyAdmin import XSPolicyAdminInstance
from xen.util import xsconstants
import xen.util.xsm.xsm as security

log = logging.getLogger("xend.XendXSPolicy")
log.setLevel(logging.TRACE)


class XendXSPolicy(XendBase):
    """ Administration class for an XSPolicy. """

    def getClass(self):
        return "XSPolicy"

    def getMethods(self):
        methods = ['activate_xspolicy']
        return XendBase.getMethods() + methods

    def getFuncs(self):
        funcs = [ 'get_xstype',
                  'set_xspolicy',
                  'reset_xspolicy',
                  'get_xspolicy',
                  'rm_xsbootpolicy',
                  'get_resource_label',
                  'set_resource_label',
                  'get_labeled_resources',
                  'can_run' ]
        return XendBase.getFuncs() + funcs

    getClass    = classmethod(getClass)
    getMethods  = classmethod(getMethods)
    getFuncs    = classmethod(getFuncs)

    def __init__(self, xspol, record, uuid):
        """ xspol = actual XSPolicy  object """
        self.xspol = xspol
        XendBase.__init__(self, uuid, record)

    def get_record(self):
        xspol_record = {
          'uuid'   : self.get_uuid(),
          'flags'  : XSPolicyAdminInstance().get_policy_flags(self.xspol),
          'repr'   : self.xspol.toxml(),
          'type'   : self.xspol.get_type(),
        }
        return xspol_record

    def get_xstype(self):
        return XSPolicyAdminInstance().isXSEnabled()

    def set_xspolicy(self, xstype, policy, flags, overwrite):
        ref = ""
        xstype = int(xstype)
        flags  = int(flags)

        polstate = { 'xs_ref': "", 'repr'   : "", 'type'   : 0,
                     'flags' : 0 , 'version': 0 , 'errors' : "", 'xserr' : 0 }
        if xstype == xsconstants.XS_POLICY_ACM:
            poladmin = XSPolicyAdminInstance()
            try:
                (xspol, rc, errors) = poladmin.add_acmpolicy_to_system(
                                                                   policy, flags,
                                                                   overwrite)
                if rc != 0:
                    polstate.update( { 'xserr' : rc,
                                       'errors': base64.b64encode(errors) } )
                else:
                    ref = xspol.get_ref()
                    polstate = {
                      'xs_ref' : ref,
                      'flags'  : poladmin.get_policy_flags(xspol),
                      'type'   : xstype,
                      'repr'   : "",
                      'version': xspol.get_version(),
                      'errors' : base64.b64encode(errors),
                      'xserr'  : rc,
                    }
            except Exception, e:
                raise
        elif xstype == xsconstants.XS_POLICY_FLASK:
            rc, errors = security.set_policy(xstype, policy);
            if rc != 0:
                polstate.update( { 'xserr' : -xsconstants.XSERR_POLICY_LOAD_FAILED,
                                   'errors': errors } )
            else:
                polstate.update( { 'xserr' : xsconstants.XSERR_SUCCESS,
                                   'errors': errors } )
        else:
            raise SecurityError(-xsconstants.XSERR_POLICY_TYPE_UNSUPPORTED)
        return polstate


    def reset_xspolicy(self, xstype):
        xstype = int(xstype)
        polstate = { 'xs_ref': "", 'repr'   : "", 'type'   : 0,
                     'flags' : 0 , 'version': 0 , 'errors' : "", 'xserr' : 0 }
        if xstype == xsconstants.XS_POLICY_ACM:
            poladmin = XSPolicyAdminInstance()
            try:
                (xspol, rc, errors) = poladmin.reset_acmpolicy()
                if rc != 0:
                    polstate.update( { 'xserr' : rc,
                                       'errors': base64.b64encode(errors) } )
                else:
                    ref = xspol.get_ref()
                    polstate = {
                      'xs_ref' : ref,
                      'flags'  : poladmin.get_policy_flags(xspol),
                      'type'   : xstype,
                      'repr'   : "",
                      'version': xspol.get_version(),
                      'errors' : base64.b64encode(errors),
                      'xserr'  : rc,
                    }
            except Exception, e:
                raise
        else:
            raise SecurityError(-xsconstants.XSERR_POLICY_TYPE_UNSUPPORTED)
        return polstate


    def activate_xspolicy(self, flags):
        flags = int(flags)
        rc = -xsconstants.XSERR_GENERAL_FAILURE
        poladmin = XSPolicyAdminInstance()
        try:
            rc = poladmin.activate_xspolicy(self.xspol, flags)
        except Exception, e:
            log.info("Activate_policy: %s" % str(e))
        if rc != flags:
            raise SecurityError(rc)
        return flags

    def get_xspolicy(self):
        polstate = { 'xs_ref' : "",
                     'repr'   : "",
                     'type'   : 0,
                     'flags'  : 0,
                     'version': "",
                     'errors' : "",
                     'xserr'  : 0 }
        poladmin = XSPolicyAdminInstance()
        refs = poladmin.get_policies_refs()
        # Will return one or no policy
        if refs and len(refs) > 0:
            ref = refs[0]
            xspol = XSPolicyAdminInstance().policy_from_ref(ref)
            if xspol:
                polstate = {
                  'xs_ref' : ref,
                  'repr'   : xspol.toxml(),
                  'type'   : xspol.get_type(),
                  'flags'  : poladmin.get_policy_flags(xspol),
                  'version': xspol.get_version(),
                  'errors' : "",
                  'xserr'  : 0,
                }
        return polstate

    def rm_xsbootpolicy(self):
        rc = XSPolicyAdminInstance().rm_bootpolicy()
        if rc != xsconstants.XSERR_SUCCESS:
            raise SecurityError(rc)

    def get_labeled_resources(self):
        return security.get_labeled_resources_xapi()

    def set_resource_label(self, resource, sec_lab, old_lab):
        rc = security.set_resource_label_xapi(resource, sec_lab, old_lab)
        if rc != xsconstants.XSERR_SUCCESS:
            raise SecurityError(rc)

    def get_resource_label(self, resource):
        res = security.get_resource_label_xapi(resource)
        return res

    def can_run(self, sec_label):
        irc = security.validate_label_xapi(sec_label, 'dom')
        if irc != xsconstants.XSERR_SUCCESS:
            raise SecurityError(irc)
        return security.check_can_run(sec_label)

    get_xstype      = classmethod(get_xstype)
    get_xspolicy    = classmethod(get_xspolicy)
    set_xspolicy    = classmethod(set_xspolicy)
    reset_xspolicy  = classmethod(reset_xspolicy)
    rm_xsbootpolicy = classmethod(rm_xsbootpolicy)
    set_resource_label = classmethod(set_resource_label)
    get_resource_label = classmethod(get_resource_label)
    get_labeled_resources = classmethod(get_labeled_resources)
    can_run = classmethod(can_run)


class XendACMPolicy(XendXSPolicy):
    """ Administration class of an ACMPolicy """

    def getClass(self):
        return "ACMPolicy"

    def getAttrRO(self):
        attrRO = [ 'xml',
                   'map',
                   'binary',
                   'header' ]
        return XendXSPolicy.getAttrRO() + attrRO

    def getFuncs(self):
        funcs = [ 'get_enforced_binary', 'get_VM_ssidref' ]
        return XendBase.getFuncs() + funcs

    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getFuncs    = classmethod(getFuncs)

    def __init__(self, acmpol, record, uuid):
        """ acmpol = actual ACMPolicy object """
        self.acmpol = acmpol
        XendXSPolicy.__init__(self, acmpol, record, uuid)

    def get_record(self):
        polstate = {
          'uuid'   : self.get_uuid(),
          'flags'  : XSPolicyAdminInstance().get_policy_flags(self.acmpol),
          'repr'   : self.acmpol.toxml(),
          'type'   : self.acmpol.get_type(),
        }
        return polstate

    def get_header(self):
        header = {
          'policyname'   : "", 'policyurl'    : "", 'reference'    : "",
          'date'         : "", 'namespaceurl' : "", 'version'      : "",
        }
        try:
            header = self.acmpol.get_header_fields_map()
        except:
            pass
        return header

    def get_xml(self):
        return self.acmpol.toxml()

    def get_map(self):
        return self.acmpol.get_map()

    def get_binary(self):
        polbin = self.acmpol.get_bin()
        return base64.b64encode(polbin)

    def get_VM_ssidref(self, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if not dom:
            raise InvalidHandleError("VM", vm_ref)
        if dom._stateGet() not in [ XEN_API_VM_POWER_STATE_RUNNING, \
                                    XEN_API_VM_POWER_STATE_PAUSED ]:
            raise VMBadState("Domain is not running or paused.")
        ssid = security.get_ssid(dom.getDomid())
        if not ssid:
            raise SecurityError(-xsconstants.XSERR_GENERAL_FAILURE)
        return ssid[3]

    def get_enforced_binary(self):
        polbin = XSPolicyAdminInstance(). \
                   get_enforced_binary(xsconstants.XS_POLICY_ACM)
        if polbin:
            return base64.b64encode(polbin)
        return None

    get_enforced_binary = classmethod(get_enforced_binary)
    get_VM_ssidref = classmethod(get_VM_ssidref)
