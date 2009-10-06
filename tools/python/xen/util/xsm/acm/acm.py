#===========================================================================
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
# Copyright (C) 2006 International Business Machines Corp.
# Author: Reiner Sailer
# Author: Bryan D. Payne <bdpayne@us.ibm.com>
# Author: Stefan Berger <stefanb@us.ibm.com>
#============================================================================

import commands
import logging
import os, string, re
import threading
import struct
import stat
import base64
from xen.lowlevel import acm
from xen.xend import sxp
from xen.xend import XendConstants
from xen.xend import XendOptions
from xen.xend.XendLogging import log
from xen.xend.XendError import VmError
from xen.util import dictio, xsconstants, auxbin, xpopen
from xen.xend.XendConstants import *

#global directories and tools for security management
install_policy_dir_prefix = auxbin.xen_configdir() + "/acm-security/policies"
security_dir_prefix = XendOptions.instance().get_xend_security_path()
policy_dir_prefix = security_dir_prefix + "/policies"
res_label_filename = policy_dir_prefix + "/resource_labels"
boot_filename = "/boot/grub/menu.lst"
altboot_filename = "/boot/grub/grub.conf"
xensec_tool = "/usr/sbin/xensec_tool"

#global patterns for map file
#police_reference_tagname = "POLICYREFERENCENAME"
primary_entry_re = re.compile("\s*PRIMARY\s+.*", re.IGNORECASE)
secondary_entry_re = re.compile("\s*SECONDARY\s+.*", re.IGNORECASE)
label_template_re =  re.compile(".*security_label_template.xml", re.IGNORECASE)
mapping_filename_re = re.compile(".*\.map", re.IGNORECASE)
policy_reference_entry_re = re.compile("\s*POLICYREFERENCENAME\s+.*", re.IGNORECASE)
vm_label_re = re.compile("\s*LABEL->SSID\s.+[VM|ANY]\s+.*", re.IGNORECASE)
res_label_re = re.compile("\s*LABEL->SSID\s+RES\s+.*", re.IGNORECASE)
all_label_re = re.compile("\s*LABEL->SSID\s+.*", re.IGNORECASE)
access_control_re = re.compile("\s*access_control\s*=", re.IGNORECASE)

#global patterns for boot configuration file
xen_title_re = re.compile("\s*title\s+XEN", re.IGNORECASE)
any_title_re = re.compile("\s*title\s", re.IGNORECASE)
xen_kernel_re = re.compile("\s*kernel.*xen.*\.gz", re.IGNORECASE)
kernel_ver_re = re.compile("\s*module.*vmlinuz", re.IGNORECASE)
any_module_re = re.compile("\s*module\s", re.IGNORECASE)
empty_line_re = re.compile("^\s*$")
binary_name_re = re.compile(".*[chwall|ste|chwall_ste].*\.bin", re.IGNORECASE)
policy_name_re = re.compile(".*[chwall|ste|chwall_ste].*", re.IGNORECASE)

#decision hooks known to the hypervisor
ACMHOOK_sharing = 1
ACMHOOK_authorization = 2
ACMHOOK_conflictset = 3

#other global variables
NULL_SSIDREF = 0

#general Rlock for map files; only one lock for all mapfiles
__mapfile_lock = threading.RLock()
__resfile_lock = threading.RLock()

log = logging.getLogger("xend.util.security")


#Functions exported through XML-RPC
xmlrpc_exports = [
  'on',
  'set_resource_label',
  'get_resource_label',
  'list_labels',
  'get_labeled_resources',
  'set_policy',
  'reset_policy',
  'get_policy',
  'activate_policy',
  'rm_bootpolicy',
  'get_xstype',
  'get_domain_label',
  'set_domain_label'
]

# Our own exception definition. It is masked (pass) if raised and
# whoever raises this exception must provide error information.
class XSMError(Exception):
    def __init__(self,value):
        self.value = value
    def __str__(self):
        return repr(self.value)



def err(msg):
    """Raise ACM exception.
    """
    raise XSMError(msg)



active_policy = None


def mapfile_lock():
    __mapfile_lock.acquire()

def mapfile_unlock():
    __mapfile_lock.release()


def resfile_lock():
    __resfile_lock.acquire()

def resfile_unlock():
    __resfile_lock.release()


def refresh_security_policy():
    """
    retrieves security policy
    """
    global active_policy

    active_policy = 'INACCESSIBLE'

    if os.access("/proc/xen/privcmd", os.R_OK|os.W_OK):
        try:
            active_policy = acm.policy()
        except:
            active_policy = "INACTIVE"

def get_active_policy_name():
    refresh_security_policy()
    return active_policy

# now set active_policy
refresh_security_policy()

def on():
    """
    returns none if security policy is off (not compiled),
    any string otherwise, use it: if not security.on() ...
    """
    if get_active_policy_name() not in ['INACTIVE', 'NULL', '']:
        return xsconstants.XS_POLICY_ACM
    return 0


def calc_dom_ssidref_from_info(info):
    """
       Calculate a domain's ssidref from the security_label in its
       info.
       This function is called before the domain is started and
       makes sure that:
        - the type of the policy is the same as indicated in the label
        - the name of the policy is the same as indicated in the label
        - calculates an up-to-date ssidref for the domain
       The latter is necessary since the domain's ssidref could have
       changed due to changes to the policy.
    """
    import xen.xend.XendConfig
    if isinstance(info, xen.xend.XendConfig.XendConfig):
        if info.has_key('security_label'):
            seclab = info['security_label']
            tmp = seclab.split(":")
            if len(tmp) != 3:
                raise VmError("VM label '%s' in wrong format." % seclab)
            typ, policyname, vmlabel = seclab.split(":")
            if typ != xsconstants.ACM_POLICY_ID:
                raise VmError("Policy type '%s' must be changed." % typ)
            if get_active_policy_name() != policyname:
                raise VmError("Active policy '%s' different than "
                              "what in VM's label ('%s')." %
                              (get_active_policy_name(), policyname))
            ssidref = label2ssidref(vmlabel, policyname, "dom")
            return ssidref
        else:
            return 0x0
    raise VmError("security.calc_dom_ssidref_from_info: info of type '%s'"
                  "not supported." % type(info))


def getmapfile(policyname):
    """
    in: if policyname is None then the currently
    active hypervisor policy is used
    out: 1. primary policy, 2. secondary policy,
    3. open file descriptor for mapping file, and
    4. True if policy file is available, False otherwise
    """
    if not policyname:
        policyname = get_active_policy_name()
    map_file_ok = False
    primary = None
    secondary = None
    #strip last part of policy as file name part
    policy_dir_list = string.split(policyname, ".")
    policy_file = policy_dir_list.pop()
    if len(policy_dir_list) > 0:
        policy_dir = string.join(policy_dir_list, "/") + "/"
    else:
        policy_dir = ""

    map_filename = policy_dir_prefix + "/" + policy_dir + policy_file + ".map"
    # check if it is there, if not check if policy file is there
    if not os.path.isfile(map_filename):
        policy_filename =  policy_dir_prefix + "/" + policy_dir + policy_file + "-security_policy.xml"
        if not os.path.isfile(policy_filename):
            err("Policy file \'" + policy_filename + "\' not found.")
        else:
            err("Mapping file \'" + map_filename + "\' not found.")

    f = open(map_filename)
    for line in f:
        if policy_reference_entry_re.match(line):
            l = line.split()
            if (len(l) == 2) and (l[1] == policyname):
                map_file_ok = True
        elif primary_entry_re.match(line):
            l = line.split()
            if len(l) == 2:
                primary = l[1]
        elif secondary_entry_re.match(line):
            l = line.split()
            if len(l) == 2:
                secondary = l[1]
    f.close()
    f = open(map_filename)
    if map_file_ok and primary and secondary:
        return (primary, secondary, f, True)
    else:
        err("Mapping file inconsistencies found.")



def ssidref2label(ssidref_var):
    """
    returns labelname corresponding to ssidref;
    maps current policy to default directory
    to find mapping file
    """
    #1. translated permitted input formats
    if isinstance(ssidref_var, str):
        ssidref_var.strip()
        if ssidref_var[0:2] == "0x":
            ssidref = int(ssidref_var[2:], 16)
        else:
            ssidref = int(ssidref_var)
    elif isinstance(ssidref_var, int):
        ssidref = ssidref_var
    else:
        err("Instance type of ssidref not supported (must be of type 'str' or 'int')")

    if ssidref == 0:
        from xen.util.acmpolicy import ACM_LABEL_UNLABELED
        return ACM_LABEL_UNLABELED

    try:
        mapfile_lock()

        (primary, secondary, f, pol_exists) = getmapfile(None)
        if not f:
            if (pol_exists):
                err("Mapping file for policy not found.")
            else:
                err("Policy file for \'" + get_active_policy_name() +
                    "\' not found.")

        #2. get labelnames for both ssidref parts
        pri_ssid = ssidref & 0xffff
        sec_ssid = ssidref >> 16
        pri_null_ssid = NULL_SSIDREF & 0xffff
        sec_null_ssid = NULL_SSIDREF >> 16
        pri_labels = []
        sec_labels = []
        labels = []

        for line in f:
            l = line.split()
            if (len(l) < 5) or (l[0] != "LABEL->SSID"):
                continue
            if primary and (l[2] == primary) and (int(l[4], 16) == pri_ssid):
                pri_labels.append(l[3])
            if secondary and (l[2] == secondary) and (int(l[4], 16) == sec_ssid):
                sec_labels.append(l[3])
        f.close()
    finally:
        mapfile_unlock()

    #3. get the label that is in both lists (combination must be a single label)
    if (primary == "CHWALL") and (pri_ssid == pri_null_ssid) and (sec_ssid != sec_null_ssid):
        labels = sec_labels
    elif (secondary == "CHWALL") and (pri_ssid != pri_null_ssid) and (sec_ssid == sec_null_ssid):
        labels = pri_labels
    elif secondary == "NULL":
        labels = pri_labels
    else:
        for i in pri_labels:
            for j in sec_labels:
                if (i==j):
                    labels.append(i)
    if len(labels) != 1:
        err("Label for ssidref \'" +  str(ssidref) +
            "\' unknown or not unique in policy \'" + active_policy + "\'")

    return labels[0]



def label2ssidref(labelname, policyname, typ):
    """
    returns ssidref corresponding to labelname;
    maps current policy to default directory
    to find mapping file    """

    if policyname in ['NULL', 'INACTIVE', 'INACCESSIBLE' ]:
        err("Cannot translate labels for \'" + policyname + "\' policy.")

    allowed_types = ['ANY']
    if typ == 'dom':
        allowed_types.append('VM')
    elif typ == 'res':
        allowed_types.append('RES')
    else:
        err("Invalid type.  Must specify 'dom' or 'res'.")

    try:
        mapfile_lock()
        (primary, secondary, f, pol_exists) = getmapfile(policyname)

        #2. get labelnames for ssidref parts and find a common label
        pri_ssid = []
        sec_ssid = []
        for line in f:
            l = line.split()
            if (len(l) < 5) or (l[0] != "LABEL->SSID"):
                continue
            if primary and (l[1] in allowed_types) and \
                           (l[2] == primary) and \
                           (l[3] == labelname):
                pri_ssid.append(int(l[4], 16))
            if secondary and (l[1] in allowed_types) and \
                             (l[2] == secondary) and \
                             (l[3] == labelname):
                sec_ssid.append(int(l[4], 16))
        f.close()
        if (typ == 'res') and (primary == "CHWALL") and (len(pri_ssid) == 0):
            pri_ssid.append(NULL_SSIDREF)
        elif (typ == 'res') and (secondary == "CHWALL") and \
             (len(sec_ssid) == 0):
            sec_ssid.append(NULL_SSIDREF)

        #3. sanity check and composition of ssidref
        if (len(pri_ssid) == 0) or ((len(sec_ssid) == 0) and \
            (secondary != "NULL")):
            err("Label \'" + labelname + "\' not found.")
        elif (len(pri_ssid) > 1) or (len(sec_ssid) > 1):
            err("Label \'" + labelname + "\' not unique in policy (policy error)")
        if secondary == "NULL":
            return pri_ssid[0]
        else:
            return (sec_ssid[0] << 16) | pri_ssid[0]
    finally:
        mapfile_unlock()


def refresh_ssidref(config):
    """
    looks up ssidref from security field
    and refreshes the value if label exists
    """
    #called by dom0, policy could have changed after xen.utils.security was initialized
    refresh_security_policy()

    security = None
    if isinstance(config, dict):
        security = config['security']
    elif isinstance(config, list):
        security = sxp.child_value(config, 'security')
    else:
        err("Instance type of config parameter not supported.")
    if not security:
        #nothing to do (no security label attached)
        return config

    policyname = None
    labelname = None
    # compose new security field
    for idx in range(0, len(security)):
        if security[idx][0] == 'ssidref':
            security.pop(idx)
            break
        elif security[idx][0] == 'access_control':
            for jdx in [1, 2]:
                if security[idx][jdx][0] == 'label':
                    labelname = security[idx][jdx][1]
                elif security[idx][jdx][0] == 'policy':
                    policyname = security[idx][jdx][1]
                else:
                    err("Illegal field in access_control")
    #verify policy is correct
    if active_policy != policyname:
        err("Policy \'" + str(policyname) +
            "\' in label does not match active policy \'"
            + str(active_policy) +"\'!")

    new_ssidref = label2ssidref(labelname, policyname, 'dom')
    if not new_ssidref:
        err("SSIDREF refresh failed!")

    security.append([ 'ssidref',str(new_ssidref)])
    security = ['security', security ]

    for idx in range(0,len(config)):
        if config[idx][0] == 'security':
            config.pop(idx)
            break
        config.append(security)



def get_ssid(domain):
    """
    enables domains to retrieve the label / ssidref of a running domain
    """
    if not on():
        err("No policy active.")

    if isinstance(domain, str):
        domain_int = int(domain)
    elif isinstance(domain, int):
        domain_int = domain
    else:
        err("Illegal parameter type.")
    try:
        ssid_info = acm.getssid(int(domain_int))
    except:
        err("Cannot determine security information.")

    label = ssidref2label(ssid_info["ssidref"])

    return(ssid_info["policyreference"],
           label,
           ssid_info["policytype"],
           ssid_info["ssidref"])



def get_decision(arg1, arg2):
    """
    enables domains to retrieve access control decisions from
    the hypervisor Access Control Module.
    IN: args format = ['domid', id] or ['ssidref', ssidref]
    or ['access_control', ['policy', policy], ['label', label], ['type', type]]
    """

    if not on():
        err("No policy active.")

    #translate labels before calling low-level function
    if arg1[0] == 'access_control':
        if (arg1[1][0] != 'policy') or (arg1[2][0] != 'label') or (arg1[3][0] != 'type'):
            err("Argument type not supported.")
        ssidref = label2ssidref(arg1[2][1], arg1[1][1], arg1[3][1])
        arg1 = ['ssidref', str(ssidref)]
    if arg2[0] == 'access_control':
        if (arg2[1][0] != 'policy') or (arg2[2][0] != 'label') or (arg2[3][0] != 'type'):
            err("Argument type not supported.")
        ssidref = label2ssidref(arg2[2][1], arg2[1][1], arg2[3][1])
        arg2 = ['ssidref', str(ssidref)]

    # accept only int or string types for domid and ssidref
    if isinstance(arg1[1], int):
        arg1[1] = str(arg1[1])
    if isinstance(arg2[1], int):
        arg2[1] = str(arg2[1])
    if not isinstance(arg1[1], str) or not isinstance(arg2[1], str):
        err("Invalid id or ssidref type, string or int required")

    try:
        decision = acm.getdecision(arg1[0], arg1[1], arg2[0], arg2[1],
                                   ACMHOOK_sharing)
    except:
        err("Cannot determine decision.")

    if decision:
        return decision
    else:
        err("Cannot determine decision (Invalid parameter).")


def has_authorization(ssidref):
    """ Check if the domain with the given ssidref has authorization to
        run on this system. To have authoriztion dom0's STE types must
        be a superset of that of the domain's given through its ssidref.
    """
    rc = True
    dom0_ssidref = int(acm.getssid(0)['ssidref'])
    decision = acm.getdecision('ssidref', str(dom0_ssidref),
                               'ssidref', str(ssidref),
                               ACMHOOK_authorization)
    if decision == "DENIED":
        rc = False
    return rc


def hv_chg_policy(bin_pol, del_array, chg_array):
    """
        Change the binary policy in the hypervisor
        The 'del_array' and 'chg_array' give hints about deleted ssidrefs
        and changed ssidrefs which can be due to deleted VM labels
        or reordered VM labels
    """
    rc = -xsconstants.XSERR_GENERAL_FAILURE
    errors = ""
    if not on():
        err("No policy active.")
    try:
        rc, errors = acm.chgpolicy(bin_pol, del_array, chg_array)
    except Exception, e:
        pass
    if len(errors) > 0:
        rc = -xsconstants.XSERR_HV_OP_FAILED
    return rc, errors

def hv_get_policy():
    """
        Gte the binary policy enforced in the hypervisor
    """
    rc = -xsconstants.XSERR_GENERAL_FAILURE
    bin_pol = ""
    if not on():
        err("No policy active.")
    try:
        rc, bin_pol = acm.getpolicy()
    except Exception, e:
        pass
    if len(bin_pol) == 0:
        bin_pol = None
    return rc, bin_pol


def is_in_conflict(ssidref):
    """ Check whether the given ssidref is in conflict with any running
        domain.
    """
    decision = acm.getdecision('ssidref', str(ssidref),
                               'ssidref', str(ssidref),
                               ACMHOOK_conflictset)
    if decision == "DENIED":
        return True
    return False


def set_policy(xs_type, xml, flags, overwrite):
    """
        Xend exports this function via XML-RPC
    """
    from xen.xend import XendXSPolicyAdmin
    xspoladmin = XendXSPolicyAdmin.XSPolicyAdminInstance()
    try:
        acmpol, rc, errors = \
             xspoladmin.add_acmpolicy_to_system(xml,
                                                int(flags),
                                                True)
        return rc, base64.b64encode(errors)
    except Exception, e:
        err(str(e))


def reset_policy():
    """
       Xend exports this function via XML-RPC
    """
    from xen.xend import XendXSPolicyAdmin
    xspoladmin = XendXSPolicyAdmin.XSPolicyAdminInstance()
    try:
        acmpol, rc, errors = \
             xspoladmin.reset_acmpolicy()
        return rc, base64.b64encode(errors)
    except Exception, e:
        err(str(e))


def get_policy():
    """
        Xend exports this function via XML-RPC
    """
    from xen.xend import XendXSPolicyAdmin
    poladmin = XendXSPolicyAdmin.XSPolicyAdminInstance()
    try:
        policy = poladmin.get_loaded_policy()
        if policy != None:
            return policy.toxml(), poladmin.get_policy_flags(policy)
    except Exception, e:
        err(str(e))
    return "", 0

def activate_policy(flags):
    """
        Xend exports this function via XML-RPC
    """
    from xen.xend import XendXSPolicyAdmin
    poladmin = XendXSPolicyAdmin.XSPolicyAdminInstance()
    try:
        policies = poladmin.get_policies()
        if len(policies) > 0:
           flags = int(flags)
           irc = poladmin.activate_xspolicy(policies[0], flags)
           return irc
    except Exception, e:
        err("Error while activating the policy: " % str(e))
    return 0


def rm_bootpolicy():
    """
        Xend exports this function via XML-RPC
    """
    from xen.xend import XendXSPolicyAdmin
    rc = XendXSPolicyAdmin.XSPolicyAdminInstance().rm_bootpolicy()
    if rc != xsconstants.XSERR_SUCCESS:
        err("Error while removing boot policy: %s" % \
            str(xsconstants.xserr2string(-rc)))
    return rc


def get_xstype():
    """
        Xend exports this function via XML-RPC
    """
    from xen.xend import XendXSPolicyAdmin
    return XendXSPolicyAdmin.XSPolicyAdminInstance().isXSEnabled()


def get_domain_label(domain):
    """
        Xend exports this function via XML-RPC
    """
    from xen.xend import XendDomain
    dom = XendDomain.instance().domain_lookup_nr(domain)
    if dom:
        seclab = dom.get_security_label()
        return seclab
    else:
        err("Domain not found.")


def set_domain_label(domain, seclab, old_seclab):
    """
        Xend exports this function via XML-RPC
    """
    from xen.xend import XendDomain
    dom = XendDomain.instance().domain_lookup_nr(domain)
    if dom:
        results = dom.set_security_label(seclab, old_seclab)
        rc, errors, old_label, new_ssidref = results
        return rc, new_ssidref
    else:
        err("Domain not found.")


def dump_policy():
    if active_policy in ['NULL', 'INACTIVE', 'INACCESSIBLE' ]:
        err("\'" + active_policy + "\' policy. Nothing to dump.")

    (ret, output) = commands.getstatusoutput(xensec_tool + " getpolicy")
    if ret:
        err("Dumping hypervisor policy failed:\n" + output)

    print output


def dump_policy_file(filename, ssidref=None):
    ssid = ""
    if ssidref:
        ssid = " " + str(ssidref)
    (ret, output) = commands.getstatusoutput(xensec_tool + " dumppolicy " +
                                             filename + ssid)
    if ret:
        err("Dumping policy failed:\n" + output)

    print output


def list_labels(policy_name, ltype):
    """
        Xend exports this function via XML-RPC

        List the VM,resource or any kind of labels contained in the
        given policy. If no policy name is given, the currently
        active policy's label will be returned if they exist.
    """
    if not policy_name:
        if active_policy in [ 'NULL', 'INACTIVE', "" ]:
            err("Current policy \'" + active_policy + "\' "
                "has no labels defined.\n")

    if not ltype or ltype == 'dom':
        condition = vm_label_re
    elif ltype == 'res':
        condition = res_label_re
    elif ltype == 'any':
        condition = all_label_re
    else:
        err("Unknown label type \'" + ltype + "\'")

    try:
        mapfile_lock()

        (primary, secondary, f, pol_exists) = getmapfile(policy_name)
        if not f:
            if pol_exists:
                err("Cannot find mapfile for policy \'" + policy_name + "\'.\n")
            else:
                err("Unknown policy \'" + policy_name + "\'")

        labels = []
        for line in f:
            if condition.match(line):
                label = line.split()[3]
                if label not in labels:
                    labels.append(label)
    finally:
        mapfile_unlock()

    if '__NULL_LABEL__' in labels:
        labels.remove('__NULL_LABEL__')

    return labels


def get_res_label(resource):
    """Returns resource label information (policytype, label, policy) if
       it exists. Otherwise returns null label and policy.
    """
    def default_res_label():
        ssidref = NULL_SSIDREF
        if on():
            label = ssidref2label(ssidref)
        else:
            label = None
        return (xsconstants.ACM_POLICY_ID, 'NULL', label)


    tmp = get_resource_label(resource)
    if len(tmp) == 2:
        policytype = xsconstants.ACM_POLICY_ID
        policy, label = tmp
    elif len(tmp) == 3:
        policytype, policy, label = tmp
    else:
        policytype, policy, label = default_res_label()

    return (policytype, label, policy)


def get_res_security_details(resource):
    """Returns the (label, ssidref, policy) associated with a given
       resource from the global resource label file.
    """
    def default_security_details():
        ssidref = NULL_SSIDREF
        if on():
            label = ssidref2label(ssidref)
        else:
            label = None
        policy = active_policy
        return (label, ssidref, policy)

    # find the entry associated with this resource
    (policytype, label, policy) = get_res_label(resource)
    if policy == 'NULL':
        log.info("Resource label for "+resource+" not in file, using DEFAULT.")
        return default_security_details()

    if policytype != xsconstants.ACM_POLICY_ID:
        raise VmError("Unknown policy type '%s in label for resource '%s'" %
                      (policytype, resource))

    # is this resource label for the running policy?
    if policy == active_policy:
        ssidref = label2ssidref(label, policy, 'res')
    elif label == xsconstants.XS_INACCESSIBLE_LABEL:
        ssidref = NULL_SSIDREF
    else:
        log.info("Resource label not for active policy, using DEFAULT.")
        return default_security_details()

    return (label, ssidref, policy)

def security_label_to_details(seclab):
    """ Convert a Xen-API type of security label into details """
    def default_security_details():
        ssidref = NULL_SSIDREF
        if on():
            label = ssidref2label(ssidref)
        else:
            label = None
        policy = active_policy
        return (label, ssidref, policy)

    (policytype, policy, label) = seclab.split(":")

    # is this resource label for the running policy?
    if policy == active_policy:
        ssidref = label2ssidref(label, policy, 'res')
    else:
        log.info("Resource label not for active policy, using DEFAULT.")
        return default_security_details()

    return (label, ssidref, policy)

def unify_resname(resource, mustexist=True):
    """Makes all resource locations absolute. In case of physical
    resources, '/dev/' is added to local file names"""

    if not resource:
        return resource

    # sanity check on resource name
    try:
        (typ, resfile) = resource.split(":", 1)
    except:
        err("Resource spec '%s' contains no ':' delimiter" % resource)

    if typ == "tap":
        try:
            (subtype, resfile) = resfile.split(":")
        except:
            err("Resource spec '%s' contains no tap subtype" % resource)

    if typ in ["phy"]:
        if not resfile.startswith("/"):
            resfile = "/dev/" + resfile
        if mustexist:
            resfile = os.path.realpath(resfile)
            try:
                stats = os.lstat(resfile)
                if not (stat.S_ISBLK(stats[stat.ST_MODE])):
                    err("Invalid resource")
            except:
                err("Invalid resource")

    if typ in [ "file", "tap" ]:
        resfile = os.path.realpath(resfile)
        if mustexist and not os.path.isfile(resfile):
            err("Invalid resource")

    if typ == "vlan":
        try:
            vlan = int(resfile)
            if vlan < 1 or vlan > 4095:
                err("VLAN ID %d out of range." % vlan)
        except Exception, e:
            err("Invalid VLAN : %s" % resfile)


    #file: resources must be specified with absolute path
    #vlan resources don't start with '/'
    if typ != "vlan":
        if (not resfile.startswith("/")) or \
           (mustexist and not os.path.exists(resfile)):
            err("Invalid resource.")

    # from here on absolute file names with resources
    if typ == "tap":
        typ = typ + ":" + subtype
    resource = typ + ":" + resfile
    return resource


def res_security_check(resource, domain_label):
    """Checks if the given resource can be used by the given domain
       label.  Returns 1 if the resource can be used, otherwise 0.
    """
    rtnval = 1

    # if security is on, ask the hypervisor for a decision
    if on():
        #build canonical resource name
        resource = unify_resname(resource)

        (label, ssidref, policy) = get_res_security_details(resource)
        domac = ['access_control']
        domac.append(['policy', active_policy])
        domac.append(['label', domain_label])
        domac.append(['type', 'dom'])
        decision = get_decision(domac, ['ssidref', str(ssidref)])

        # provide descriptive error messages
        if decision == 'DENIED':
            if label == ssidref2label(NULL_SSIDREF):
                raise XSMError("Resource '"+resource+"' is not labeled")
                rtnval = 0
            else:
                raise XSMError("Permission denied for resource '"+resource+"' because label '"+label+"' is not allowed")
                rtnval = 0

    # security is off, make sure resource isn't labeled
    else:
        # Note, we can't canonicalise the resource here, because people using
        # xm without ACM are free to use relative paths.
        (policytype, label, policy) = get_res_label(resource)
        if policy != 'NULL':
            raise XSMError("Security is off, but '"+resource+"' is labeled")
            rtnval = 0

    return rtnval

def res_security_check_xapi(rlabel, rssidref, rpolicy, xapi_dom_label):
    """Checks if the given resource can be used by the given domain
       label.  Returns 1 if the resource can be used, otherwise 0.
    """
    rtnval = 1
    # if security is on, ask the hypervisor for a decision
    if on():
        if rlabel == xsconstants.XS_INACCESSIBLE_LABEL:
            return 0
        typ, dpolicy, domain_label = xapi_dom_label.split(":")
        if not dpolicy or not domain_label:
            raise VmError("VM security label in wrong format.")
        if active_policy != rpolicy:
            raise VmError("Resource's policy '%s' != active policy '%s'" %
                          (rpolicy, active_policy))
        domac = ['access_control']
        domac.append(['policy', active_policy])
        domac.append(['label', domain_label])
        domac.append(['type', 'dom'])
        decision = get_decision(domac, ['ssidref', str(rssidref)])

        log.info("Access Control Decision : %s" % decision)
        # provide descriptive error messages
        if decision == 'DENIED':
            if rlabel == ssidref2label(NULL_SSIDREF):
                #raise XSMError("Resource is not labeled")
                rtnval = 0
            else:
                #raise XSMError("Permission denied for resource because label '"+rlabel+"' is not allowed")
                rtnval = 0

    # security is off, make sure resource isn't labeled
    else:
        # Note, we can't canonicalise the resource here, because people using
        # xm without ACM are free to use relative paths.
        if rpolicy != 'NULL':
            #raise XSMError("Security is off, but resource is labeled")
            rtnval = 0

    return rtnval


def validate_label_xapi(xapi_label, dom_or_res):
    """
       Make sure that this label is part of the currently enforced policy
       and that it references the current policy.
       dom_or_res defines whether this is a VM ('res') or resource label
       ('res')
    """
    tmp = xapi_label.split(":")
    if len(tmp) != 3:
        return -xsconstants.XSERR_BAD_LABEL_FORMAT
    policytyp, policyref, label = tmp
    return validate_label(policytyp, policyref, label, dom_or_res)


def validate_label(policytype, policyref, label, dom_or_res):
    """
       Make sure that this label is part of the currently enforced policy
       and that it reference the current policy.
    """
    if policytype != xsconstants.ACM_POLICY_ID:
        return -xsconstants.XSERR_WRONG_POLICY_TYPE
    if not policytype or not label:
        return -xsconstants.XSERR_BAD_LABEL_FORMAT
    rc = xsconstants.XSERR_SUCCESS
    if label == xsconstants.XS_INACCESSIBLE_LABEL:
        return rc
    from xen.xend.XendXSPolicyAdmin import XSPolicyAdminInstance
    curpol = XSPolicyAdminInstance().get_loaded_policy()
    if not curpol or curpol.get_name() != policyref:
        rc = -xsconstants.XSERR_BAD_LABEL
    else:
        try:
            label2ssidref(label, curpol.get_name() , dom_or_res)
        except:
            rc = -xsconstants.XSERR_BAD_LABEL
    return rc


def set_resource_label_xapi(resource, reslabel_xapi, oldlabel_xapi):
    """Assign a resource label to a resource
    @param resource: The name of a resource, i.e., "phy:/dev/hda", or
              "tap:qcow:/path/to/file.qcow"

    @param reslabel_xapi: A resource label foramtted as in all other parts of
                          the Xen-API, i.e., ACM:xm-test:blue"
    @rtype: int
    @return Success (0) or failure value (< 0)
    """
    olabel = ""
    if reslabel_xapi == "":
        return rm_resource_label(resource, oldlabel_xapi)

    rc = validate_label_xapi(reslabel_xapi, 'res')
    if rc != xsconstants.XSERR_SUCCESS:
        return rc

    if oldlabel_xapi not in [ "" ]:
        tmp = oldlabel_xapi.split(":")
        if len(tmp) != 3:
            return -xsconstants.XSERR_BAD_LABEL_FORMAT
        otyp, opolicyref, olabel = tmp
        # Only ACM is supported
        if otyp != xsconstants.ACM_POLICY_ID  and \
           otyp != xsconstants.INVALID_POLICY_PREFIX + \
                   xsconstants.ACM_POLICY_ID:
            return -xsconstants.XSERR_WRONG_POLICY_TYPE
    typ, policyref, label = reslabel_xapi.split(":")
    return set_resource_label(resource, typ, policyref, label, olabel)


def is_resource_in_use(resource):
    """
       Domain-0 'owns' resources of type 'VLAN', the rest are owned by
       the guests.
    """
    from xen.xend import XendDomain
    lst = []
    if resource.startswith('vlan'):
        from xen.xend.XendXSPolicyAdmin import XSPolicyAdminInstance
        curpol = XSPolicyAdminInstance().get_loaded_policy()
        policytype, label, policy = get_res_label(resource)
        if curpol and \
           policytype == xsconstants.ACM_POLICY_ID and \
           policy == curpol.get_name() and \
           label in curpol.policy_get_resourcelabel_names():
            # VLAN is in use.
            lst.append(XendDomain.instance().
                         get_vm_by_uuid(XendDomain.DOM0_UUID))
    else:
        dominfos = XendDomain.instance().list('all')
        for dominfo in dominfos:
            if is_resource_in_use_by_dom(dominfo, resource):
                lst.append(dominfo)
    return lst

def devices_equal(res1, res2, mustexist=True):
    """ Determine whether two devices are equal """
    return (unify_resname(res1, mustexist) ==
            unify_resname(res2, mustexist))

def is_resource_in_use_by_dom(dominfo, resource):
    """ Determine whether a resources is in use by a given domain
        @return True or False
    """
    if not dominfo.domid:
        return False
    if dominfo._stateGet() not in [ DOM_STATE_RUNNING ]:
        return False
    devs = dominfo.info['devices']
    uuids = devs.keys()
    for uuid in uuids:
        dev = devs[uuid]
        if len(dev) >= 2 and dev[1].has_key('uname'):
            # dev[0] is type, i.e. 'vbd'
            if devices_equal(dev[1]['uname'], resource, mustexist=False):
                log.info("RESOURCE IN USE: Domain %d uses %s." %
                         (dominfo.domid, resource))
                return True
    return False


def get_domain_resources(dominfo):
    """ Collect all resources of a domain in a map where each entry of
        the map is a list.
        Entries are strored in the following formats:
          tap:qcow:/path/xyz.qcow
    """
    resources = { 'vbd' : [], 'tap' : [], 'vif' : []}
    devs = dominfo.info['devices']
    uuids = devs.keys()
    for uuid in uuids:
        dev = devs[uuid]
        typ = dev[0]
        if typ in [ 'vbd', 'tap' ]:
            resources[typ].append(dev[1]['uname'])
        if typ in [ 'vif' ]:
            sec_lab = dev[1].get('security_label')
            if sec_lab:
                resources[typ].append(sec_lab)
            else:
                # !!! This should really get the label of the domain
                # or at least a resource label that has the same STE type
                # as the domain has
                from xen.util.acmpolicy import ACM_LABEL_UNLABELED
                resources[typ].append("%s:%s:%s" %
                                      (xsconstants.ACM_POLICY_ID,
                                       active_policy,
                                       ACM_LABEL_UNLABELED))

    return resources


def resources_compatible_with_vmlabel(xspol, dominfo, vmlabel):
    """
       Check whether the resources' labels are compatible with the
       given VM label. This is a function to be used when for example
       a running domain is to get the new label 'vmlabel'
    """
    if not xspol:
        return False

    try:
        resfile_lock()
        try:
            access_control = dictio.dict_read("resources",
                                              res_label_filename)
        except:
            # No labeled resources -> must be compatible
            return True
        return __resources_compatible_with_vmlabel(xspol, dominfo, vmlabel,
                                                   access_control)
    finally:
        resfile_unlock()
    return False


def __resources_compatible_with_vmlabel(xspol, dominfo, vmlabel,
                                        access_control,
                                        is_policy_update=False):
    """
        Check whether the resources' labels are compatible with the
        given VM label. The access_control parameter provides a
        dictionary of the resource name to resource label mappings
        under which the evaluation should be done.
        Call this only for a paused or running domain.
    """
    def collect_labels(reslabels, s_label, polname):
        if len(s_label) != 3 or polname != s_label[1]:
            return False
        label = s_label[2]
        if not label in reslabels:
            reslabels.append(label)
        return True

    resources = get_domain_resources(dominfo)
    reslabels = []  # all resource labels

    polname = xspol.get_name()
    for key, value in resources.items():
        if key in [ 'vbd', 'tap' ]:
            for res in resources[key]:
                if not res in access_control:
                    label = [xsconstants.ACM_POLICY_ID,
                             xspol.get_name(),
                             ACM_LABEL_UNLABELED]
                else:
                    label = access_control[res]
                if not collect_labels(reslabels, label, polname):
                    return False
        elif key in [ 'vif' ]:
            for xapi_label in value:
                label = xapi_label.split(":")
                from xen.util.acmpolicy import ACM_LABEL_UNLABELED
                if not (is_policy_update and \
                        label[2] == ACM_LABEL_UNLABELED):
                    if not collect_labels(reslabels, label, polname):
                        return False
        else:
            log.error("Unhandled device type: %s" % key)
            return False

    # Check that all resource labes have a common STE type with the
    # vmlabel
    if len(reslabels) > 0:
        rc = xspol.policy_check_vmlabel_against_reslabels(vmlabel, reslabels)
    else:
        rc = True
    log.info("vmlabel=%s, reslabels=%s, rc=%s" %
             (vmlabel, reslabels, str(rc)))
    return rc;

def set_resource_label(resource, policytype, policyref, reslabel, \
                       oreslabel = None):
    """
       Xend exports this function via XML-RPC.

       Assign a label to a resource
       If the old label (oreslabel) is given, then the resource must have
       that old label.
       A resource label may be changed if
       - the resource is not in use
    @param resource  : The name of a resource, i.e., "phy:/dev/hda"
    @param policyref : The name of the policy
    @param reslabel     : the resource label within the policy
    @param oreslabel    : optional current resource label

    @rtype: int
    @return Success (0) or failure value (< 0)
    """


    try:
        resource = unify_resname(resource, mustexist=False)
    except Exception:
        return -xsconstants.XSERR_BAD_RESOURCE_FORMAT

    try:
        resfile_lock()
        mapfile_lock()

        if reslabel not in [ '', xsconstants.XS_INACCESSIBLE_LABEL ]:
            ssidref = label2ssidref(reslabel, policyref, 'res')

        domains = is_resource_in_use(resource)
        if len(domains) > 0:
            return -xsconstants.XSERR_RESOURCE_IN_USE

        access_control = {}
        try:
             access_control = dictio.dict_read("resources", res_label_filename)
        except:
            pass
        if oreslabel:
            if not access_control.has_key(resource):
                return -xsconstants.XSERR_BAD_LABEL
            tmp = access_control[resource]
            if len(tmp) != 3:
                return -xsconstants.XSERR_BAD_LABEL
            if tmp[2] != oreslabel:
                return -xsconstants.XSERR_BAD_LABEL
        if resource.startswith('vlan:'):
            for key, value in access_control.items():
                if value == tuple([policytype, policyref, reslabel]) and \
                   key.startswith('vlan:'):
                    return -xsconstants.XSERR_BAD_LABEL

        if reslabel == xsconstants.XS_INACCESSIBLE_LABEL:
            policytype = xsconstants.ACM_POLICY_ID
            policyref  = '*'

        if reslabel != "":
            new_entry = { resource : tuple([policytype, policyref, reslabel])}
            access_control.update(new_entry)
            command = "add"
            reslbl = ":".join([policytype, policyref, reslabel])
        else:
            if access_control.has_key(resource):
                del access_control[resource]
            command = "remove"
            reslbl = ""
        run_resource_label_change_script(resource, reslbl, command)
        dictio.dict_write(access_control, "resources", res_label_filename)
    finally:
        resfile_unlock()
        mapfile_unlock()
    return xsconstants.XSERR_SUCCESS

def rm_resource_label(resource, oldlabel_xapi):
    """Remove a resource label from a physical resource
    @param resource: The name of a resource, i.e., "phy:/dev/hda"

    @rtype: int
    @return Success (0) or failure value (< 0)
    """
    tmp = oldlabel_xapi.split(":")
    if len(tmp) != 3:
        return -xsconstants.XSERR_BAD_LABEL_FORMAT
    otyp, opolicyref, olabel = tmp
    # Only ACM is supported
    if otyp != xsconstants.ACM_POLICY_ID and \
       otyp != xsconstants.INVALID_POLICY_PREFIX + xsconstants.ACM_POLICY_ID:
        return -xsconstants.XSERR_WRONG_POLICY_TYPE
    return set_resource_label(resource, "", "", "", olabel)

def get_resource_label_xapi(resource):
    """Get the assigned resource label of a physical resource
      in the format used by then Xen-API, i.e., "ACM:xm-test:blue"

      @rtype: string
      @return the string representing policy type, policy name and label of
              the resource
    """
    res = get_resource_label(resource)
    return format_resource_label(res)

def format_resource_label(res):
    if res:
        if len(res) == 2:
            return xsconstants.ACM_POLICY_ID + ":" + res[0] + ":" + res[1]
        if len(res) == 3:
            return ":".join(res)
    return ""

def get_resource_label(resource):
    """
       Xend exports this function via XML-RPC.

       Get the assigned resource label of a given resource
    @param resource: The name of a resource, i.e., "phy:/dev/hda"

    @rtype: list
    @return tuple of (policy name, resource label), i.e., (xm-test, blue)
    """
    try:
        resource = unify_resname(resource, mustexist=False)
    except Exception:
        return []

    reslabel_map = get_labeled_resources()

    if reslabel_map.has_key(resource):
        return list(reslabel_map[resource])
    else:
        #Try to resolve each label entry
        for key, value in reslabel_map.items():
            try:
                if resource == unify_resname(key):
                    return list(value)
            except:
                pass

    return []


def get_labeled_resources_xapi():
    """ Get a map of all labeled resource with the labels formatted in the
        xen-api resource label format.
    """
    reslabel_map = get_labeled_resources()
    for key, labeldata in reslabel_map.items():
        reslabel_map[key] = format_resource_label(labeldata)
    return reslabel_map


def get_labeled_resources():
    """
        Xend exports this function via XML-RPC

        Get a map of all labeled resources.
    @rtype: list
    @return list of labeled resources
    """
    try:
        resfile_lock()
        try:
            access_control = dictio.dict_read("resources", res_label_filename)
        except:
            return {}
    finally:
        resfile_unlock()
    return access_control


def relabel_domains(relabel_list):
    """
      Relabel the given domains to have a new ssidref.
      @param relabel_list: a list containing tuples of domid, ssidref
                           example: [ [0, 0x00020002] ]
    """
    rel_rules = ""
    for r in relabel_list:
        log.info("Relabeling domain with domid %d to new ssidref 0x%08x",
                r[0], r[1])
        rel_rules += struct.pack("ii", r[0], r[1])
    try:
        rc, errors = acm.relabel_domains(rel_rules)
    except Exception, e:
        log.info("Error after relabel_domains: %s" % str(e))
        rc = -xsconstants.XSERR_GENERAL_FAILURE
        errors = ""
    if (len(errors) > 0):
        rc = -xsconstants.XSERR_HV_OP_FAILED
    return rc, errors


def __update_label_policy_change(sec_lab,
                                 cur_poltype,
                                 cur_polname,
                                 new_poltype,
                                 new_polname,
                                 polnew_labels,
                                 label_map):
    """
    Determine a new resource label given the new policy's type
    and name and the new policy's (resource/VM) labels and the
    (resource/VM) label map that indicates renaming rules for
    labels.
    """
    is_deleted = False
    policytype, policy, label = sec_lab

    if cur_poltype != policytype or \
       cur_polname != policy:
        return sec_lab, is_deleted

    if policytype != xsconstants.ACM_POLICY_ID:
        return sec_lab, is_deleted
    elif label_map.has_key(label) and policy == cur_polname:
        # renaming of an active label; policy may have been renamed
        label = label_map[label]
        polname = new_polname
    elif label not in polnew_labels:
        # label been removed
        policytype = xsconstants.INVALID_POLICY_PREFIX + policytype
        polname = policy
        is_deleted = True
    else:
        # no change to label
        policytype = xsconstants.ACM_POLICY_ID
        polname = new_polname

    return tuple( [ policytype, polname, label ] ), is_deleted


def change_acm_policy(bin_pol, del_array, chg_array,
                      vmlabel_map, reslabel_map, cur_acmpol, new_acmpol,
                      is_reset):
    """
       Change the ACM policy of the system by relabeling
       domains and resources first and doing some access checks.
       Then update the policy in the hypervisor. If this is all successful,
       relabel the domains permanently and commit the relabed resources.

       Need to do / check the following:
        - relabel all resources where there is a 'from' field in
          the policy. [ NOT DOING THIS: and mark those as unlabeled where the label
          does not appear in the new policy anymore (deletion) ]
        - relabel all VMs where there is a 'from' field in the
          policy and mark those as unlabeled where the label
          does not appear in the new policy anymore; no running
          or paused VM may be unlabeled through this
        - check that under the new labeling conditions the VMs
          still have access to their resources as before. Unlabeled
          resources are inaccessible. If this check fails, the
          update failed.
        - Attempt changes in the hypervisor; if this step fails,
          roll back the relabeling of resources and VMs
        - Make the relabeling of resources and VMs permanent

       This function should be called with the lock to the domains
       held (XendDomain.instance().domains_lock)
    """
    from xen.util.acmpolicy import ACM_LABEL_UNLABELED
    rc = xsconstants.XSERR_SUCCESS

    domain_label_map = {}
    new_policyname = new_acmpol.get_name()
    new_policytype = new_acmpol.get_type_name()
    cur_policyname = cur_acmpol.get_name()
    cur_policytype = cur_acmpol.get_type_name()
    polnew_reslabels = new_acmpol.policy_get_resourcelabel_names()
    errors=""

    try:
        resfile_lock()
        mapfile_lock()

        # Get all domains' dominfo.
        from xen.xend import XendDomain
        dominfos = XendDomain.instance().list('all')

        log.info("----------------------------------------------")

        label_changes = []
        # relabel resources

        access_control = {}
        try:
            access_control = dictio.dict_read("resources", res_label_filename)
        except:
            pass

        for key, labeldata in access_control.items():
            if len(labeldata) == 2:
                policy, label = labeldata
                policytype = xsconstants.ACM_POLICY_ID
            elif len(labeldata) == 3:
                policytype, policy, label = labeldata
            else:
                return -xsconstants.XSERR_BAD_LABEL_FORMAT, ""

            new_sec_lab, is_deleted = \
                __update_label_policy_change( tuple([policytype,
                                                     policy,
                                                     label]),
                                             cur_policytype,
                                             cur_policyname,
                                             new_policytype,
                                             new_policyname,
                                             polnew_reslabels,
                                             reslabel_map)

            if is_deleted:
                label_changes.append(key)
            # Update entry
            access_control[key] = new_sec_lab

        # All resources have new labels in the access_control map
        # There may still be labels in there that are invalid now.

        # Do this in memory without writing to disk:
        #  - Relabel all domains independent of whether they are running
        #    or not
        #  - later write back to config files
        polnew_vmlabels = new_acmpol.policy_get_virtualmachinelabel_names()

        for dominfo in dominfos:
            sec_lab = dominfo.get_security_label()
            if not sec_lab:
                continue
            policytype, policy, vmlabel = sec_lab.split(":")
            name  = dominfo.getName()

            if policytype != cur_policytype or \
               policy     != cur_policyname:
                continue

            new_vmlabel = vmlabel
            if vmlabel_map.has_key(vmlabel) and \
               (not is_reset or name == "Domain-0") :
                # renaming of the label; this is only allowed if it's
                # not a reset of the policy or if it is a reset, then
                # only for Domain-0
                new_vmlabel = vmlabel_map[vmlabel]
                polname = new_policyname
            elif new_vmlabel not in polnew_vmlabels and \
               vmlabel != ACM_LABEL_UNLABELED:
                # removal of VM label and not the 'unlabeled' label
                policytype = xsconstants.INVALID_POLICY_PREFIX + policytype
                polname = policy
            else:
                polname = new_policyname

            new_seclab = "%s:%s:%s" % \
                    (policytype, polname, new_vmlabel)

            domain_label_map[dominfo] = [ sec_lab, new_seclab ]

            if dominfo._stateGet() in (DOM_STATE_PAUSED, DOM_STATE_RUNNING):
                compatible = __resources_compatible_with_vmlabel(new_acmpol,
                                                      dominfo,
                                                      new_vmlabel,
                                                      access_control,
                                                      is_policy_update=True)
                log.info("Domain %s with new label '%s' can access its "
                         "resources? : %s" %
                         (name, new_vmlabel, str(compatible)))
                log.info("VM labels in new policy: %s" %
                         new_acmpol.policy_get_virtualmachinelabel_names())
                if not compatible:
                    return (-xsconstants.XSERR_RESOURCE_ACCESS, "")

        for dominfo in dominfos:
            # relabel the VIF interfaces
            changed = False
            for vif_uuid in dominfo.get_vifs():
                sec_lab = dominfo.info['devices'][vif_uuid][1]\
                                 .get('security_label')
                if sec_lab:
                    result, _ = \
                        __update_label_policy_change(tuple(sec_lab.split(':')),
                                                     cur_policytype,
                                                     cur_policyname,
                                                     new_policytype,
                                                     new_policyname,
                                                     polnew_reslabels,
                                                     reslabel_map)
                    new_sec_lab = ':'.join(list(result))
                    if new_sec_lab != sec_lab:
                        changed = True
                        dominfo.info['devices'][vif_uuid][1]\
                                    ['security_label'] = new_sec_lab
            if changed:
                XendDomain.instance().managed_config_save(dominfo)

        rc, errors = hv_chg_policy(bin_pol, del_array, chg_array)
        if rc == 0:
            for key in label_changes:
                run_resource_label_change_script(key, "", "remove")
            # Write the relabeled resources back into the file
            dictio.dict_write(access_control, "resources", res_label_filename)
            # Properly update all VMs to their new labels
            for dominfo, labels in domain_label_map.items():
                sec_lab, new_seclab = labels
                if sec_lab != new_seclab:
                    log.info("Updating domain %s to new label '%s'." % \
                             (dominfo.getName(), new_seclab))
                    # This better be working!
                    res = dominfo.set_security_label(new_seclab,
                                                     sec_lab,
                                                     new_acmpol,
                                                     cur_acmpol)
                    if res[0] != xsconstants.XSERR_SUCCESS:
                        log.info("ERROR: Could not chg label on domain %s: %s" %
                                 (dominfo.getName(),
                                  xsconstants.xserr2string(-int(res[0]))))
    finally:
        log.info("----------------------------------------------")
        mapfile_unlock()
        resfile_unlock()

    return rc, errors

def parse_security_label(security_label):
    tmp = security_label.split(":")
    if len(tmp) != 3:
        return ""
    else:
        return security_label

def set_security_label(policy, label):
    if label and policy and label != "" and policy != "":
        return "%s:%s:%s" % (xsconstants.ACM_POLICY_ID, policy, label)
    else:
        return ""

def ssidref2security_label(ssidref):
    from xen.xend.XendXSPolicyAdmin import XSPolicyAdminInstance
    return XSPolicyAdminInstance().ssidref_to_vmlabel(ssidref)

def get_security_label(self, xspol=None):
    """
       Get the security label of a domain
       @param xspol   The policy to use when converting the ssid into
                      a label; only to be passed during the updating
                      of the policy
    """
    domid = self.getDomid()

    if not xspol:
        from xen.xend.XendXSPolicyAdmin import XSPolicyAdminInstance
        xspol = XSPolicyAdminInstance().get_loaded_policy()

    label = ""
    if xspol:
        label = xspol.policy_get_domain_label_formatted(domid)
    if domid != 0:
        label = self.info.get('security_label', label)
    return label


def check_can_run(sec_label):
    """ Check whether a VM could run, given its vm label. A VM can run if
       - it is authorized
       - is not in conflict with any running domain
    """
    try:
        mapfile_lock()

        if sec_label == None or sec_label == "":
            vm_label = ACM_LABEL_UNLABELED
        else:
            poltype, policy, vm_label = sec_label.split(':')
            if policy != get_active_policy_name():
                return -xsconstants.XSERR_BAD_POLICY_NAME
        ssidref = label2ssidref(vm_label, policy, 'dom')
        if ssidref != xsconstants.INVALID_SSIDREF:
            if not has_authorization(ssidref):
                return -xsconstants.XSERR_VM_NOT_AUTHORIZED
            if is_in_conflict(ssidref):
                return -xsconstants.XSERR_VM_IN_CONFLICT
            return -xsconstants.XSERR_SUCCESS
        else:
            return -xsconstants.XSERR_BAD_LABEL
    finally:
        mapfile_unlock()


__cond = threading.Condition()
__script_runner = None
__orders = []

def run_resource_label_change_script(resource, label, command):
    global __cond, __orders, __script_runner

    def __run_resource_label_change_script():
        global __cond, __orders
        script = XendOptions.instance().get_resource_label_change_script()
        if script:
            parms = {}
            while True:
                __cond.acquire()
                if len(__orders) == 0:
                    __cond.wait()

                parms['label'], \
                   parms['command'], \
                   parms['resource'] = __orders[0]

                __orders = __orders[1:]
                __cond.release()

                log.info("Running resource label change script %s: %s" %
                         (script, parms))
                parms.update(os.environ)
                xpopen.call(" ".join(script, params))
        else:
            log.info("No script given for relabeling of resources.")
    if not __script_runner:
        __script_runner = \
                 threading.Thread(target=__run_resource_label_change_script,
                                  args=())
        __script_runner.start()

    __cond.acquire()
    __orders.append((label,command,resource))
    __cond.notify()
    __cond.release()
