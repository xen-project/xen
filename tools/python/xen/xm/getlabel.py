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
# Author: Bryan D. Payne <bdpayne@us.ibm.com>
#============================================================================

"""Show the label for a domain or resoruce.
"""
import sys, os, re
import xen.util.xsm.xsm as security
from xen.util import xsconstants, auxbin
from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.xm.main import server

def help():
    return """
    Usage: xm getlabel dom <configfile>
           xm getlabel mgt <domain name>
           xm getlabel res <resource>
           xm getlabel vif-<idx> <vmname>
           
    This program shows the label for a domain from its configuration
    file, the label of a Xend-managed domain, that of a resources or
    the label of a virtual network interface of a managed domain
    (requires xm to be used in Xen-API mode).
    """

def get_resource_label(resource):
    """Gets the resource label
    """
    if xm_main.serverType == xm_main.SERVER_XEN_API:
        reslabel = server.xenapi.XSPolicy.get_resource_label(resource)
        if reslabel == "":
            raise security.XSMError("Resource not labeled")
        print reslabel
    else:
        reslabel = server.xend.security.get_resource_label(resource)
        if len(reslabel) == 0:
            raise security.XSMError("Resource not labeled")
        print ":".join(reslabel)


def get_domain_label(configfile):
    # open the domain config file
    fd = None
    if configfile[0] == '/':
        fd = open(configfile, "rb")
    else:
        for prefix in [".", auxbin.xen_configdir() ]:
            abs_file = prefix + "/" + configfile
            if os.path.isfile(abs_file):
                fd = open(abs_file, "rb")
                break
    if not fd:
        raise OptionError("Configuration file '%s' not found." % configfile)

    # read in the domain config file, finding the label line
    ac_entry_re = re.compile("^access_control\s*=.*", re.IGNORECASE)
    ac_exit_re = re.compile(".*'\].*")
    acline = ""
    record = 0
    for line in fd.readlines():
        if ac_entry_re.match(line):
            record = 1
        if record:
            acline = acline + line
        if record and ac_exit_re.match(line):
            record = 0
    fd.close()

    # send error message if we didn't find anything
    if acline == "":
        raise security.XSMError("Domain not labeled")

    # print out the label
    (title, data) = acline.split("=", 1)
    data = data.strip()
    data = data.lstrip("[\'")
    data = data.rstrip("\']")
    print "policytype=%s," % xsconstants.ACM_POLICY_ID + data

def get_vif_label(vmname, idx):
    if xm_main.serverType != xm_main.SERVER_XEN_API:
        raise OptionError('xm needs to be configure to use the xen-api.')
    vm_refs = server.xenapi.VM.get_by_name_label(vmname)
    if len(vm_refs) == 0:
        raise OptionError('A VM with the name %s does not exist.' %
                          vmname)
    vif_refs = server.xenapi.VM.get_VIFs(vm_refs[0])
    if len(vif_refs) <= idx:
        raise OptionError("Bad VIF index.")
    vif_ref = server.xenapi.VIF.get_by_uuid(vif_refs[idx])
    if not vif_ref:
        print "No VIF with this UUID."
    sec_lab = server.xenapi.VIF.get_security_label(vif_ref)
    print "%s" % sec_lab

def get_domain_label_xapi(domain):
    if xm_main.serverType != xm_main.SERVER_XEN_API:
        sec_lab = server.xend.security.get_domain_label(domain)
        if len(sec_lab) > 0 and sec_lab[0] == '\'':
            sec_lab = sec_lab[1:]
    else:
        uuids = server.xenapi.VM.get_by_name_label(domain)
        if len(uuids) == 0:
            raise OptionError('A VM with that name does not exist.')
        if len(uuids) != 1:
            raise OptionError('There are multiple domains with the same name.')
        uuid = uuids[0]
        sec_lab = server.xenapi.VM.get_security_label(uuid)
    print "%s" %sec_lab

def main(argv):
    if len(argv) != 3:
        raise OptionError('Requires 2 arguments')

    if argv[1].lower() == "dom":
        configfile = argv[2]
        get_domain_label(configfile)
    elif argv[1].lower() == "mgt":
        domainname = argv[2]
        get_domain_label_xapi(domainname)
    elif argv[1].lower() == "res":
        resource = argv[2]
        get_resource_label(resource)
    elif argv[1].lower().startswith("vif-"):
        try:
            idx = int(argv[1][4:])
            if idx < 0:
                raise
        except:
            raise OptionError("Bad VIF device index.")
        vmname = argv[2]
        get_vif_label(vmname, idx)
    else:
        raise OptionError('First subcommand argument must be "dom"'
                          ', "mgt" or "res"')

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
