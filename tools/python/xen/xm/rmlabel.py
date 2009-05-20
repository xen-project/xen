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

"""Remove a label from a domain configuration file or a resoruce.
"""
import os
import re
import sys
import xen.util.xsm.xsm as security
from xen.util import xsconstants, auxbin
from xen.util.acmpolicy import ACM_LABEL_UNLABELED
from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.xm.main import server

def help():
    return """
    Example: xm rmlabel dom <configfile>
             xm rmlabel res <resource>
             xm rmlabel mgt <domain name>
             xm rmlabel vif-<idx> <domain name>

    This program removes an acm_label entry from the 'configfile'
    for a domain, the label from a Xend-managed domain or a resources
    or from the network interface of a Xend-managed domain (requires
    xm to be used in Xen-API mode). If the label does not exist for
    the given domain or resource, then rmlabel fails and reports an error.
    """


def rm_resource_label(resource):
    """Removes a resource label from the global resource label file.
    """
    # Try Xen-API first if configured to use it
    if xm_main.serverType == xm_main.SERVER_XEN_API:
        try:
            oldlabel = server.xenapi.XSPolicy.get_resource_label(resource)
            if oldlabel != "":
                server.xenapi.XSPolicy.set_resource_label(resource,"",
                                                          oldlabel)
            else:
                raise security.XSMError("Resource not labeled")
        except Exception, e:
            raise security.XSMError("Could not remove label "
                                    "from resource: %s" % e)
        return
    else:
        oldlabel = server.xend.security.get_resource_label(resource)
        if len(oldlabel) != 0:
            rc = server.xend.security.set_resource_label(resource,
                                                         "",
                                                         "",
                                                         "")
            if rc != xsconstants.XSERR_SUCCESS:
                raise security.XSMError("An error occurred removing the "
                                        "label: %s" % \
                                        xsconstants.xserr2string(-rc))
        else:
            raise security.XSMError("Resource not labeled")

def rm_domain_label(configfile):
    # open the domain config file
    fd = None
    fil = None
    if configfile[0] == '/':
        fil = configfile
        fd = open(fil, "rb")
    else:
        for prefix in [".", auxbin.xen_configdir() ]:
            fil = prefix + "/" + configfile
            if os.path.isfile(fil):
                fd = open(fil, "rb")
                break
    if not fd:
        raise OptionError("Configuration file '%s' not found." % configfile)
        
    # read in the domain config file, removing label
    ac_entry_re = re.compile("^access_control\s*=.*", re.IGNORECASE)
    ac_exit_re = re.compile(".*'\].*")
    file_contents = ""
    comment = 0
    removed = 0
    for line in fd.readlines():
        if ac_entry_re.match(line):
            comment = 1
        if comment:
            removed = 1
            line = "#"+line
        if comment and ac_exit_re.match(line):
            comment = 0
        file_contents = file_contents + line
    fd.close()

    # send error message if we didn't find anything to remove
    if not removed:
        raise security.XSMError('Domain not labeled')

    # write the data back out to the file
    fd = open(fil, "wb")
    fd.writelines(file_contents)
    fd.close()

def rm_domain_label_xapi(domain):
    if xm_main.serverType != xm_main.SERVER_XEN_API:
        old_lab = server.xend.security.get_domain_label(domain)

        vmlabel = ""
        if old_lab != "":
            tmp = old_lab.split(":")
            if len(tmp) == 3:
                vmlabel = tmp[2]

        if old_lab != "" and  vmlabel != ACM_LABEL_UNLABELED:
            server.xend.security.set_domain_label(domain, "", old_lab)
            print "Successfully removed label from domain %s." % domain
        else:
            raise security.XSMError("Domain was not labeled.")
    else:
        uuids = server.xenapi.VM.get_by_name_label(domain)
        if len(uuids) == 0:
            raise OptionError('A VM with that name does not exist.')
        if len(uuids) != 1:
            raise OptionError('Too many domains with the same name.')
        uuid = uuids[0]
        try:
            old_lab = server.xenapi.VM.get_security_label(uuid)

            vmlabel = ""
            if old_lab != "":
                tmp = old_lab.split(":")
                if len(tmp) == 3:
                    vmlabel = tmp[2]

            if old_lab != "":
                server.xenapi.VM.set_security_label(uuid, "", old_lab)
            else:
                raise security.XSMError("Domain was not labeled.")
        except Exception, e:
            raise security.XSMError('Could not remove label from domain: %s' % e)

def rm_vif_label(vmname, idx):
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
        raise security.XSMError("A VIF with this UUID does not exist.")
    try:
        old_lab = server.xenapi.VIF.get_security_label(vif_ref)
        if old_lab != "":
            rc = server.xenapi.VIF.set_security_label(vif_ref, "", old_lab)
            if int(rc) != 0:
                raise security.XSMError("Could not remove the label from"
                                        " the VIF.")
            else:
                print "Successfully removed the label from the VIF."
        else:
            raise security.XSMError("VIF is not labeled.")
    except Exception, e:
        raise security.XSMError("Could not remove the label from the VIF: %s" %
                                str(e))


def main (argv):

    if len(argv) != 3:
        raise OptionError('Requires 2 arguments')
    
    if argv[1].lower() == "dom":
        configfile = argv[2]
        rm_domain_label(configfile)
    elif argv[1].lower() == "mgt":
        domain = argv[2]
        rm_domain_label_xapi(domain)
    elif argv[1].lower().startswith("vif-"):
        try:
            idx = int(argv[1][4:])
            if idx < 0:
                raise
        except:
            raise OptionError("Bad VIF device index.")
        vmname = argv[2]
        rm_vif_label(vmname, idx)
    elif argv[1].lower() == "res":
        resource = argv[2]
        rm_resource_label(resource)
    else:
        raise OptionError('Unrecognised type argument: %s' % argv[1])

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)    
