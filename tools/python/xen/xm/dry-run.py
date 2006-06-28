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
from xen.util import security
from xen.xm import create
from xen.xend import sxp

def usage():
    print "\nUsage: xm dry-run <configfile>\n"
    print "This program checks each resource listed in the configfile"
    print "to see if the domain created by the configfile can access"
    print "the resources.  The status of each resource is listed"
    print "individually along with the final security decision.\n"


def check_domain_label(config):
    """All that we need to check here is that the domain label exists and
       is not null when security is on.  Other error conditions are
       handled when the config file is parsed.
    """
    answer = 0
    secon = 0
    default_label = security.ssidref2label(security.NULL_SSIDREF)
    if security.on():
        secon = 1

    # get the domain acm_label
    dom_label = None
    dom_name = None
    for x in sxp.children(config):
        if sxp.name(x) == 'security':
            dom_label = sxp.child_value(sxp.name(sxp.child0(x)), 'label')
        if sxp.name(x) == 'name':
            dom_name = sxp.child0(x)

    # sanity check on domain label
    print "Checking domain:"
    if (not secon) and (not dom_label):
        print "   %s: PERMITTED" % (dom_name)
        answer = 1
    elif (secon) and (dom_label) and (dom_label != default_label):
        print "   %s: PERMITTED" % (dom_name)
        answer = 1
    else:
        print "   %s: DENIED" % (dom_name)
        if not secon:
            print "   --> Security off, but domain labeled"
        else:
            print "   --> Domain not labeled"
        answer = 0

    return answer


def main (argv):
    if len(argv) != 2:
        usage()
        return

    try:
        passed = 0
        (opts, config) = create.parseCommandLine(argv)
        if check_domain_label(config):
            if create.config_security_check(config, verbose=1):
                passed = 1
        else:
            print "Checking resources: (skipped)"

        if passed:
            print "Dry Run: PASSED"
        else:
            print "Dry Run: FAILED"
    except security.ACMError:
        pass


if __name__ == '__main__':
    main(sys.argv)
