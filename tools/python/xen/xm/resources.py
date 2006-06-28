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
import sys, os
import string
import traceback
from xml.marshal import generic
from xen.util import security

def usage():
    print "\nUsage: xm resource\n"
    print "  This program lists information for each resource in the"
    print "  global resource label file\n"


def print_resource_data(access_control):
    """Prints out a resource dictionary to stdout
    """
    for resource in access_control:
        (policy, label) = access_control[resource]
        print resource
        print "    policy: "+policy
        print "    label:  "+label


def get_resource_data():
    """Returns the resource dictionary.
    """
    file = security.res_label_filename
    if not os.path.isfile(file):
        security.err("Resource file not found.")

    fd = open(file, "rb")
    access_control = generic.load(fd)
    fd.close()
    return access_control


def main (argv):
    try:
        access_control = get_resource_data()
        print_resource_data(access_control)

    except security.ACMError:
        pass
    except:
        traceback.print_exc(limit=1)


if __name__ == '__main__':
    main(sys.argv)


