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
from xen.util.security import ACMError, err, list_labels, active_policy
from xen.util.security import vm_label_re, res_label_re, all_label_re
from xen.xm.opts import OptionError


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

    if not policy:
        policy = active_policy
        if active_policy in ['NULL', 'INACTIVE', 'DEFAULT']:
            raise OptionError('No policy active, you must specify a <policy>')

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

    except ACMError:
        sys.exit(-1)
    except:
        traceback.print_exc(limit = 1)

if __name__ == '__main__':
    main(sys.argv)


