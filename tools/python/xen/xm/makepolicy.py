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
from xen.util.security import ACMError, err, make_policy
from xen.util import xsconstants
from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.xm.setpolicy import setpolicy

def usage():
    print "\nUsage: xm makepolicy <policy>\n"
    print " Translate an XML source policy and create"
    print " mapping file and binary policy.\n"
    err("Usage")


def main(argv):
    if len(argv) != 2:
        raise OptionError('No XML policy file specified')
    if xm_main.serverType == xm_main.SERVER_XEN_API:
        print "This command is deprecated for use with Xen-API " \
              "configuration. Consider using\n'xm setpolicy'."
        setpolicy(xsconstants.ACM_POLICY_ID, argv[1],
                  xsconstants.XS_INST_LOAD, True)
    else:
        make_policy(argv[1])

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
