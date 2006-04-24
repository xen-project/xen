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
#============================================================================

import commands
import logging
import sys, os, string, re
import traceback
import shutil
from xen.lowlevel import acm
from xen.xend import sxp

#global directories and tools for security management
policy_dir_prefix = "/etc/xen/acm-security/policies"
boot_filename = "/boot/grub/menu.lst"
xensec_xml2bin = "/usr/sbin/xensec_xml2bin"
xensec_tool = "/usr/sbin/xensec_tool"

#global patterns for map file
#police_reference_tagname = "POLICYREFERENCENAME"
primary_entry_re = re.compile("\s*PRIMARY\s+.*", re.IGNORECASE)
secondary_entry_re = re.compile("\s*SECONDARY\s+.*", re.IGNORECASE)
label_template_re =  re.compile(".*security_label_template.xml", re.IGNORECASE)
mapping_filename_re = re.compile(".*\.map", re.IGNORECASE)
policy_reference_entry_re = re.compile("\s*POLICYREFERENCENAME\s+.*", re.IGNORECASE)
vm_label_re = re.compile("\s*LABEL->SSID\s+VM\s+.*", re.IGNORECASE)
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



log = logging.getLogger("xend.util.security")

# Our own exception definition. It is masked (pass) if raised and
# whoever raises this exception must provide error information.
class ACMError(Exception):
    def __init__(self,value):
        self.value = value
    def __str__(self):
        return repr(self.value)



def err(msg):
    """Raise ACM exception.
    """
    sys.stderr.write("ACMError: " + msg + "\n")
    raise ACMError(msg)



active_policy = None


def refresh_security_policy():
    """
    retrieves security policy
    """
    global active_policy

    try:
        active_policy = acm.policy()
    except:
        active_policy = "INACTIVE"

# now set active_policy
refresh_security_policy()

def on():
    """
    returns none if security policy is off (not compiled),
    any string otherwise, use it: if not security.on() ...
    """
    refresh_security_policy()
    return (active_policy not in ['INACTIVE', 'NULL'])



# Assumes a 'security' info  [security access_control ...] [ssidref ...]
def get_security_info(info, field):
    """retrieves security field from self.info['security'])
    allowed search fields: ssidref, label, policy
    """
    if isinstance(info, dict):
        security = info['security']
    elif isinstance(info, list):
        security = sxp.child_value(info, 'security', )
    if not security:
        if field == 'ssidref':
            #return default ssid
            return 0
        else:
            err("Security information not found in info struct.")

    if field == 'ssidref':
        search = 'ssidref'
    elif field in ['policy', 'label']:
            search = 'access_control'
    else:
        err("Illegal field in get_security_info.")

    for idx in range(0, len(security)):
        if search != security[idx][0]:
            continue
        if search == 'ssidref':
            return int(security[idx][1])
        else:
            for aidx in range(0, len(security[idx])):
                if security[idx][aidx][0] == field:
                    return str(security[idx][aidx][1])

    if search == 'ssidref':
        return 0
    else:
        return None



def get_security_printlabel(info):
    """retrieves printable security label from self.info['security']),
    preferably the label name and otherwise (if label is not specified
    in config and cannot be found in mapping file) a hex string of the
    ssidref or none if both not available
    """
    try:
        if not on():
            return "INACTIVE"
        if active_policy in ["DEFAULT"]:
            return "DEFAULT"

        printlabel = get_security_info(info, 'label')
        if printlabel:
            return printlabel
        ssidref = get_security_info(info, 'ssidref')
        if not ssidref:
            return None
        #try to translate ssidref to a label
        result = ssidref2label(ssidref)
        if not result:
            printlabel = "0x%08x" % ssidref
        else:
            printlabel = result
        return printlabel
    except ACMError:
        #don't throw an exception in xm list
        return "ERROR"



def getmapfile(policyname):
    """
    in: if policyname is None then the currently
    active hypervisor policy is used
    out: 1. primary policy, 2. secondary policy,
    3. open file descriptor for mapping file, and
    4. True if policy file is available, False otherwise
    """
    if not policyname:
        policyname = active_policy
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
            err("Mapping file \'" + map_filename + "\' not found." +
                " Use xm makepolicy to create it.")

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
        err("Mapping file inconsistencies found. Try makepolicy to create a new one.")



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

    (primary, secondary, f, pol_exists) = getmapfile(None)
    if not f:
        if (pol_exists):
            err("Mapping file for policy \'" + policyname + "\' not found.\n" +
                "Please use makepolicy command to create mapping file!")
        else:
            err("Policy file for \'" + active_policy + "\' not found.")

    #2. get labelnames for both ssidref parts
    pri_ssid = ssidref & 0xffff
    sec_ssid = ssidref >> 16
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

    #3. get the label that is in both lists (combination must be a single label)
    if secondary == "NULL":
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



def label2ssidref(labelname, policyname):
    """
    returns ssidref corresponding to labelname;
    maps current policy to default directory
    to find mapping file    """

    if policyname in ['NULL', 'INACTIVE', 'DEFAULT']:
        err("Cannot translate labels for \'" + policyname + "\' policy.")

    (primary, secondary, f, pol_exists) = getmapfile(policyname)

    #2. get labelnames for ssidref parts and find a common label
    pri_ssid = []
    sec_ssid = []
    for line in f:
        l = line.split()
        if (len(l) < 5) or (l[0] != "LABEL->SSID"):
            continue
        if primary and (l[2] == primary) and (l[3] == labelname):
            pri_ssid.append(int(l[4], 16))
        if secondary and (l[2] == secondary) and (l[3] == labelname):
            sec_ssid.append(int(l[4], 16))
    f.close()

    #3. sanity check and composition of ssidref
    if (len(pri_ssid) == 0) or ((len(sec_ssid) == 0) and (secondary != "NULL")):
        err("Label \'" + labelname + "\' not found.")
    elif (len(pri_ssid) > 1) or (len(sec_ssid) > 1):
        err("Label \'" + labelname + "\' not unique in policy (policy error)")
    if secondary == "NULL":
        return pri_ssid[0]
    else:
        return (sec_ssid[0] << 16) | pri_ssid[0]



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
        security = sxp.child_value(config, 'security',)
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
        err("Policy \'" + policyname + "\' in label does not match active policy \'"
            + active_policy +"\'!")

    new_ssidref = label2ssidref(labelname, policyname)
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

    if active_policy in ["DEFAULT"]:
        label = "DEFAULT"
    else:
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
    or ['access_control', ['policy', policy], ['label', label]]
    """

    if not on():
        err("No policy active.")

    #translate labels before calling low-level function
    if arg1[0] == 'access_control':
        if (arg1[1][0] != 'policy') or (arg1[2][0] != 'label') :
            err("Argument type not supported.")
        ssidref = label2ssidref(arg1[2][1], arg1[1][1])
        arg1 = ['ssidref', str(ssidref)]
    if arg2[0] == 'access_control':
        if (arg2[1][0] != 'policy') or (arg2[2][0] != 'label') :
            err("Argument type not supported.")
        ssidref = label2ssidref(arg2[2][1], arg2[1][1])
        arg2 = ['ssidref', str(ssidref)]
    try:
        decision = acm.getdecision(arg1[0], arg1[1], arg2[0], arg2[1])
    except:
        err("Cannot determine decision.")

    if decision:
        return decision
    else:
        err("Cannot determine decision (Invalid parameter).")



def make_policy(policy_name):
    policy_file = string.join(string.split(policy_name, "."), "/")
    if not os.path.isfile(policy_dir_prefix + "/" + policy_file + "-security_policy.xml"):
        err("Unknown policy \'" + policy_name + "\'")

    (ret, output) = commands.getstatusoutput(xensec_xml2bin + " -d " + policy_dir_prefix + " " + policy_file)
    if ret:
        err("Creating policy failed:\n" + output)



def load_policy(policy_name):
    global active_policy
    policy_file = policy_dir_prefix + "/" + string.join(string.split(policy_name, "."), "/")
    if not os.path.isfile(policy_file + ".bin"):
        if os.path.isfile(policy_file + "-security_policy.xml"):
            err("Binary file does not exist." +
                "Please use makepolicy to build the policy binary.")
        else:
            err("Unknown Policy " + policy_name)

    #require this policy to be the first or the same as installed
    if active_policy not in ['DEFAULT', policy_name]:
        err("Active policy \'" + active_policy +
            "\' incompatible with new policy \'" + policy_name + "\'")
    (ret, output) = commands.getstatusoutput(xensec_tool + " loadpolicy " + policy_file + ".bin")
    if ret:
        err("Loading policy failed:\n" + output)
    else:
        # refresh active policy
        refresh_security_policy()



def dump_policy():
    if active_policy in ['NULL', 'INACTIVE']:
        err("\'" + active_policy + "\' policy. Nothing to dump.")

    (ret, output) = commands.getstatusoutput(xensec_tool + " getpolicy")
    if ret:
       err("Dumping hypervisor policy failed:\n" + output)
    print output



def list_labels(policy_name, condition):
    if (not policy_name) and (active_policy) in ["NULL", "INACTIVE", "DEFAULT"]:
        err("Current policy \'" + active_policy + "\' has no labels defined.\n")

    (primary, secondary, f, pol_exists) = getmapfile(policy_name)
    if not f:
        if pol_exists:
            err("Cannot find mapfile for policy \'" + policy_name +
                "\'.\nPlease use makepolicy to create mapping file.")
        else:
            err("Unknown policy \'" + policy_name + "\'")

    labels = []
    for line in f:
        if condition.match(line):
            label = line.split()[3]
            if label not in labels:
                labels.append(label)
    return labels
