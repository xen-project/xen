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
import os
import commands
import shutil
import string
from xen.util.security import ACMError, err, list_labels, active_policy
from xen.util.security import vm_label_re, res_label_re, all_label_re

def usage():
    print "\nUsage: xm labels [<policy>] [<type=dom|res|any>]\n"
    print " Prints labels of the specified type (default is dom)"
    print " that are defined in policy (default is current"
    print " hypervisor policy).\n"
    err("Usage")


def main(argv):
    try:
        policy = None
        type = None
        for i in argv[1:]:
            i_s = string.split(i, '=')
            if len(i_s) > 1:
                if (i_s[0] == 'type') and (len(i_s) == 2):
                    if not type:
                        type = i_s[1]
                    else:
                        usage()
                else:
                    usage()
            else:
                if not policy:
                    policy = i
                else:
                    usage()

        if not policy:
            policy = active_policy
            if active_policy in ['NULL', 'INACTIVE', 'DEFAULT']:
                err("No policy active. Please specify the <policy> parameter.")

        if not type or (type in ['DOM', 'dom']):
            condition = vm_label_re
        elif type in ['RES', 'res']:
            condition = res_label_re
        elif type in ['ANY', 'any']:
            condition = all_label_re
        else:
            err("Unknown label type \'" + type + "\'")

        labels = list_labels(policy, condition)
        labels.sort()
        for label in labels:
            print label
    except ACMError:
        pass
    except:
        traceback.print_exc(limit=1)


if __name__ == '__main__':
    main(sys.argv)


