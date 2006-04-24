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
"""Compiling a XML source policy file into mapping and binary versions.
"""
import sys
import traceback
import os
import commands
import shutil
import string
from xen.util.security import ACMError, err, make_policy


def usage():
    print "\nUsage: xm makepolicy <policy>\n"
    print " Translate an XML source policy and create"
    print " mapping file and binary policy.\n"
    err("Usage")



def main(argv):
    try:
        if len(argv) != 2:
            usage()
        make_policy(argv[1])

    except ACMError:
        pass
    except:
        traceback.print_exc(limit=1)



if __name__ == '__main__':
    main(sys.argv)


