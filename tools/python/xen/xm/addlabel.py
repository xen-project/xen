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
# Copyright (C) 2006 International Business Machines Corp.
# Author: Reiner Sailer <sailer@us.ibm.com>
# Author: Bryan D. Payne <bdpayne@us.ibm.com>
#============================================================================

"""Labeling a domain configuration file or a resource.
"""
import os
import sys

import xen.util.xsm.xsm as security
from xen.xm.opts import OptionError
from xen.util import xsconstants, auxbin
from xen.xm import main as xm_main
from xen.xm.main import server

def help():
    return """
    Format: xm addlabel <label> dom <configfile> [<policy>]
            xm addlabel <label> mgt <domain name> [<policy type>:<policy>]
            xm addlabel <label> res <resource> [[<policy type>:]<policy>]
            xm addlabel <label> vif-<idx> <domain name> [<policy type>:<policy>]
    
    This program adds an acm_label entry into the 'configfile'
    for a domain, allows to label a xend-managed domain, resources
    of the VIF of a mangaged domain (requires xm to be used in
    Xen-API mode).

    For xend-managed domains, the 'mgt' parameter should be used and
    the 'xm' tool must have been configured to use the xen-npi for
    communication with xen. If a policy is provided as last parameter,
    its type must also be given. Currently only one type of policy is
    supported and identified as 'ACM'. An example for a valid string
    is 'ACM:xm-test'. """


def validate_config_file(configfile):
    """Performs a simple sanity check on the configuration file passed on
       the command line.  We basically just want to make sure that it's
       not a domain image file so we check for a few configuration values
       and then we are satisfied.  Returned 1 on success, otherwise 0.
    """
    # read in the config file
    globs = {}
    locs = {}
    try:
        execfile(configfile, globs, locs)
    except:
        print "Invalid configuration file."
        return 0

    # sanity check on the data from the file
    # requiring 'memory,' 'name,' and ether 'kernel' or 'bootloader'
    count = 0
    required = ['kernel', 'bootloader', 'memory', 'name']
    for (k, v) in locs.items():
        if k in required:
            count += 1
    if count < len(required) - 1:
        print "Invalid configuration file."
        return 0
    else:
        return 1


def add_resource_label(label, resource, policyref, policy_type):
    """Adds a resource label to the global resource label file.
    """

    if xm_main.serverType != xm_main.SERVER_XEN_API:
        old = server.xend.security.get_resource_label(resource)
        if len(old) == 0:
            try:
                rc = server.xend.security.set_resource_label(resource,
                                                             policy_type,
                                                             policyref,
                                                             label)
            except Exception, e:
                raise
            if rc != xsconstants.XSERR_SUCCESS:
                security.err("An error occurred labeling the resource: %s" % \
                             xsconstants.xserr2string(-rc))
        else:
            old = security.format_resource_label(old)
            security.err("'%s' is already labeled with '%s'." % \
                         (resource,old))
    else:
        res = [ policy_type, policyref, label ]
        res_xapi = security.format_resource_label(res)
        old = server.xenapi.XSPolicy.get_resource_label(resource)
        if old == "":
            try:
                server.xenapi.XSPolicy.set_resource_label(resource,
                                                          res_xapi,
                                                          "")
            except Exception, e:
                raise security.XSMError("Could not label this resource: %s" %
                                        str(e))
        else:
            raise security.XSMError("'%s' is already labeled with '%s'" %
                                    (resource,old))

def add_domain_label(label, configfile, policyref):
    # sanity checks: make sure this label can be instantiated later on
    ssidref = security.label2ssidref(label, policyref, 'dom')

    new_label = "access_control = ['policy=%s,label=%s']\n" % \
                (policyref, label)
    if not os.path.isfile(configfile):
        security.err("Configuration file \'" + configfile + "\' not found.")
    config_fd = open(configfile, "ra+")
    for line in config_fd:
        if not security.access_control_re.match(line):
            continue
        config_fd.close()
        security.err("Config file \'" + configfile + "\' is already labeled.")
    config_fd.write(new_label)
    config_fd.close()

def add_domain_label_xapi(label, domainname, policyref, policy_type):
    sec_lab = "%s:%s:%s" % (policy_type, policyref, label)
    if xm_main.serverType != xm_main.SERVER_XEN_API:
        old_seclab = server.xend.security.get_domain_label(domainname)
        if old_seclab[0] == '\'':
            old_seclab = old_seclab[1:]
        results = server.xend.security.set_domain_label(domainname,
                                                        sec_lab,
                                                        old_seclab)
        rc, ssidref = results
        if rc == xsconstants.XSERR_SUCCESS:
            if ssidref != 0:
                print "Successfully set the label of domain '%s' to '%s'.\n" \
                      % (domainname,label)
            else:
                print "Successfully set the label of the dormant domain " \
                      "'%s' to '%s'." % (domainname,label)
        else:
            msg = xsconstants.xserr2string(-rc)
            raise security.XSMError("An error occurred relabeling "
                                    "the domain: %s" % msg)
    else:
        uuids = server.xenapi.VM.get_by_name_label(domainname)
        if len(uuids) == 0:
            raise OptionError('A VM with that name does not exist.')
        if len(uuids) != 1:
            raise OptionError('There are multiple domains with the same name.')
        uuid = uuids[0]
        try:
            old_lab = server.xenapi.VM.get_security_label(uuid)
            rc = server.xenapi.VM.set_security_label(uuid, sec_lab, old_lab)
        except Exception, e:
            raise security.XSMError("Could not label the domain: %s" % e)
        if int(rc) < 0:
            raise OptionError('Could not label domain.')
        else:
            ssidref = int(rc)
            if ssidref != 0:
                print "Successfully set the label of domain '%s' to '%s'.\n" \
                      % (domainname,label)
            else:
                print "Successfully set the label of the dormant domain " \
                      "'%s' to '%s'." % (domainname,label)

def add_vif_label(label, vmname, idx, policyref, policy_type):
    if xm_main.serverType != xm_main.SERVER_XEN_API:
        raise OptionError('Need to be configure for using xen-api.')
    vm_refs = server.xenapi.VM.get_by_name_label(vmname)
    if len(vm_refs) == 0:
        raise OptionError('A VM with the name %s does not exist.' %
                          vmname)
    vif_refs = server.xenapi.VM.get_VIFs(vm_refs[0])
    if len(vif_refs) <= idx:
        raise OptionError("Bad VIF index.")
    vif_ref = server.xenapi.VIF.get_by_uuid(vif_refs[idx])
    if not vif_ref:
        print "Internal error: VIF does not exist."
    sec_lab = "%s:%s:%s" % (policy_type, policyref, label)
    try:
        old_lab = server.xenapi.VIF.get_security_label(vif_ref)
        rc = server.xenapi.VIF.set_security_label(vif_ref,
                                                  sec_lab, old_lab)
        if int(rc) != 0:
            print "Could not label the VIF."
        else:
            print "Successfully labeled the VIF."
    except Exception, e:
        print "Could not label the VIF: %s" % str(e)


def main(argv):
    policyref = None
    policy_type = ""
    if len(argv) not in (4, 5):
        raise OptionError('Needs either 2 or 3 arguments')

    label = argv[1]

    if len(argv) == 5:
        policyref = argv[4]
    elif security.on() == xsconstants.XS_POLICY_ACM:
        policyref = security.active_policy
        policy_type = xsconstants.ACM_POLICY_ID
    else:
        raise OptionError("ACM security is not enabled. You must specify "\
                          "the policy on the command line.")

    if argv[2].lower() == "dom":
        configfile = argv[3]
        if configfile[0] != '/':
            for prefix in [os.path.realpath(os.path.curdir), auxbin.xen_configdir()]:
                configfile = prefix + "/" + configfile
                if os.path.isfile(configfile):
                    break
        if not validate_config_file(configfile):
            raise OptionError('Invalid config file')
        else:
            add_domain_label(label, configfile, policyref)
    elif argv[2].lower() == "mgt":
        domain = argv[3]
        if policy_type == "":
            tmp = policyref.split(":")
            if len(tmp) != 2:
                raise OptionError("Policy name in wrong format.")
            policy_type, policyref = tmp
        add_domain_label_xapi(label, domain, policyref, policy_type)
    elif argv[2].lower() == "res":
        resource = argv[3]
        if policy_type == "":
            tmp = policyref.split(":")
            if len(tmp) == 1:
                policy_type = xsconstants.ACM_POLICY_ID
            elif len(tmp) == 2:
                policy_type, policyref = tmp
            else:
                raise OptionError("Policy name in wrong format.")
        add_resource_label(label, resource, policyref, policy_type)
    elif argv[2].lower().startswith("vif-"):
        try:
            idx = int(argv[2][4:])
            if idx < 0:
                raise
        except:
            raise OptionError("Bad VIF device index.")
        vmname = argv[3]
        if policy_type == "":
            tmp = policyref.split(":")
            if len(tmp) != 2:
                raise OptionError("Policy name in wrong format.")
            policy_type, policyref = tmp
        add_vif_label(label, vmname, idx, policyref, policy_type)
    else:
        raise OptionError('Need to specify either "dom", "mgt" or "res" as '
                          'object to add label to.')
            
if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
