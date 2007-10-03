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
#============================================================================

"""Listing available labels for a policy.
"""
import sys
import traceback
import string
from xen.util.xsm.xsm import XSMError, err, list_labels, active_policy
from xen.util.xsm.xsm import vm_label_re, res_label_re, all_label_re
from xen.xm.opts import OptionError
from xen.util.acmpolicy import ACMPolicy
from xen.util import xsconstants
from xen.xm.main import server
from xen.xm import main as xm_main


def help():
    return """
    Prints labels of the specified type (default is dom)
    that are defined in policy (default is current hypervisor policy)."""

def main(argv):
    policy = None
    ptype = None
    for arg in argv[1:]:
        key_val = arg.split('=')
        if len(key_val) == 2 and key_val[0] == 'type':
            if ptype:
                raise OptionError('type is definied twice')
            ptype = key_val[1].lower()

        elif len(key_val) == 1:
            if policy:
                raise OptionError('policy is defined twice')
            policy = arg
        else:
            raise OptionError('Unrecognised option: %s' % arg)

    if xm_main.serverType != xm_main.SERVER_XEN_API:
        labels(policy, ptype)
    else:
        labels_xapi(policy, ptype)

def labels(policy, ptype):
    if not policy:
        policy = active_policy
        if active_policy in ['NULL', 'INACTIVE', 'DEFAULT']:
            raise OptionError('No policy active, you must specify a <policy>')
        if active_policy in ['INACCESSIBLE']:
            raise OptionError('Cannot access the policy. Try as root.')

    if not ptype or ptype == 'dom':
        condition = vm_label_re
    elif ptype == 'res':
        condition = res_label_re
    elif ptype == 'any':
        condition = all_label_re
    else:
        err("Unknown label type \'" + ptype + "\'")

    try:
        labels = list_labels(policy, condition)
        labels.sort()
        for label in labels:
            print label

    except XSMError:
        sys.exit(-1)
    except:
        traceback.print_exc(limit = 1)

def labels_xapi(policy, ptype):
    policystate = server.xenapi.XSPolicy.get_xspolicy()
    if int(policystate['type']) == xsconstants.XS_POLICY_ACM:
        acmpol = ACMPolicy(xml=policystate['repr'])
        if policy and policy != acmpol.get_name():
            print "Warning: '%s' is not the currently loaded policy." % policy
            return labels(policy, ptype)
        names1 = []
        names2 = []
        if not ptype or ptype == 'dom' or ptype == 'any':
            names1 = acmpol.policy_get_virtualmachinelabel_names()
        if ptype == 'res' or ptype == 'any':
            names2 = acmpol.policy_get_resourcelabel_names()
        if len(names1) > 0:
            names = set(names1)
            names.union(names2)
        else:
            names = set(names2)
        for n in names:
            print n
    elif int(policystate['type']) == 0:
        err("No policy installed on the system.")
    else:
        err("Unsupported type of policy installed on the system.")

if __name__ == '__main__':
    main(sys.argv)
