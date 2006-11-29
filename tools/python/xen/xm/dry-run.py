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

"""Tests the security settings for a domain and its resources.
"""
import sys
from xen.util import security
from xen.xm import create
from xen.xend import sxp
from xen.xm.opts import OptionError

def help():
    return """
    This program checks each resource listed in the configfile
    to see if the domain created by the configfile can access
    the resources.  The status of each resource is listed
    individually along with the final security decision."""

def main (argv):
    if len(argv) != 2:
        raise OptionError('Invalid number of arguments')
    
    passed = 0
    (opts, config) = create.parseCommandLine(argv)
    if create.check_domain_label(config, verbose=1):
        if create.config_security_check(config, verbose=1):
            passed = 1
    else:
        print "Checking resources: (skipped)"
        
    if passed:
        print "Dry Run: PASSED"
    else:
        print "Dry Run: FAILED"
        sys.exit(-1)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
