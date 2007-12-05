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

"""List the resource label information from the global resource label file
"""
import sys
from xen.util import xsconstants
from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.xm.main import server

def help():
    return """
    This program lists information for each resource in the
    global resource label file."""

def print_resource_data(access_control):
    """Prints out a resource dictionary to stdout
    """
    for resource in access_control:
        tmp = access_control[resource]
        if len(tmp) == 2:
            policytype = xsconstants.ACM_POLICY_ID
            (policy, label) = access_control[resource]
        elif len(tmp) == 3:
            policytype, policy, label = access_control[resource]
        print resource
        print "      type: "+ policytype
        print "    policy: "+ policy
        print "    label:  "+ label

def main (argv):
    if len(argv) > 1:
        raise OptionError("No arguments required")

    if xm_main.serverType == xm_main.SERVER_XEN_API:
        access_control = server.xenapi.XSPolicy.get_labeled_resources()
        for key, value in access_control.items():
            access_control[key] = tuple(value.split(':'))
    else:
        access_control = server.xend.security.get_labeled_resources()

    print_resource_data(access_control)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)    
