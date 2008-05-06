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
import xen.util.xsm.xsm as security
from xen.xm import create
from xen.xend import sxp
from xen.util import xsconstants
from xen.xm.opts import OptionError

def help():
    return """
    This program checks each resource listed in the configfile
    to see if the domain created by the configfile can access
    the resources.  The status of each resource is listed
    individually along with the final security decision."""


def check_domain_label(config, verbose):
    """All that we need to check here is that the domain label exists and
       is not null when security is on.  Other error conditions are
       handled when the config file is parsed.
    """
    answer = 0
    default_label = None
    secon = 0
    if security.on() == xsconstants.XS_POLICY_ACM:
        default_label = security.ssidref2label(security.NULL_SSIDREF)
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
    if verbose:
        print "Checking domain:"
    if (not secon) and (not dom_label):
        answer = 1
        if verbose:
            print "   %s: PERMITTED" % (dom_name)
    elif (secon) and (dom_label) and (dom_label != default_label):
        answer = 1
        if verbose:
            print "   %s: PERMITTED" % (dom_name)
    else:
        print "   %s: DENIED" % (dom_name)
        if not secon:
            print "   --> Security off, but domain labeled"
        else:
            print "   --> Domain not labeled"
        answer = 0

    return answer

def config_security_check(config, verbose):
    """Checks each resource listed in the config to see if the active
       policy will permit creation of a new domain using the config.
       Returns 1 if the config passes all tests, otherwise 0.
    """
    answer = 1

    # get the domain acm_label
    domain_label = None
    domain_policy = None
    for x in sxp.children(config):
        if sxp.name(x) == 'security':
            domain_label = sxp.child_value(sxp.name(sxp.child0(x)), 'label')
            domain_policy = sxp.child_value(sxp.name(sxp.child0(x)), 'policy')

    # if no domain label, use default
    if not domain_label and security.on() == xsconstants.XS_POLICY_ACM:
        try:
            domain_label = security.ssidref2label(security.NULL_SSIDREF)
        except:
            import traceback
            traceback.print_exc(limit=1)
            return 0
        domain_policy = 'NULL'
    elif not domain_label:
        domain_label = ""
        domain_policy = 'NULL'

    if verbose:
        print "Checking resources:"

    # build a list of all resources in the config file
    resources = []
    for x in sxp.children(config):
        if sxp.name(x) == 'device':
            if sxp.name(sxp.child0(x)) == 'vbd':
                resources.append(sxp.child_value(sxp.child0(x), 'uname'))

    # perform a security check on each resource
    for resource in resources:
        try:
            security.res_security_check(resource, domain_label)
            if verbose:
                print "   %s: PERMITTED" % (resource)

        except security.XSMError:
            print "   %s: DENIED" % (resource)
            (poltype, res_label, res_policy) = security.get_res_label(resource)
            if not res_label:
                res_label = ""
            print "   --> res: %s (%s:%s)" % (str(res_label),
                                           str(poltype), str(res_policy))
            print "   --> dom: %s (%s:%s)" % (str(domain_label),
                                           str(poltype), str(domain_policy))

            answer = 0

    return answer


def main (argv):
    if len(argv) != 2:
        raise OptionError('Invalid number of arguments')
    
    passed = 0
    (opts, config) = create.parseCommandLine(argv)
    if check_domain_label(config, verbose=1):
        if config_security_check(config, verbose=1):
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
