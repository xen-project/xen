#!/usr/bin/python
"""
 Copyright (C) International Business Machines Corp., 2006
 Author: Stefan Berger <stefanb@us.ibm.com>

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; under version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""
from Test import *
import xen.util.xsm.xsm as security
from xen.xm.main import server
from xen.util import xsconstants
import re

try:
    from acm_config import *
except:
    ACM_LABEL_RESOURCES = False

labeled_resources = {}
acm_verbose = False

def isACMEnabled():
    return security.on()


def getSystemPolicyName():
    s,o = traceCommand("xm getpolicy")
    m = re.compile("Policy name[\s]*: ([A-z\-]+)").search(o)
    if m:
        polname = m.group(1)
        return polname
    return ""


def ACMLoadPolicy_XenAPI(policy='xm-test'):
    polname = getSystemPolicyName()
    if polname != policy:
        # Try it, maybe it's not activated
        traceCommand("xm setpolicy %s %s" %
                     (xsconstants.ACM_POLICY_ID, policy))
        polname = getSystemPolicyName()
        if polname != policy:
            FAIL("Need to have a system with no or policy '%s' active, "
                 "not %s" % (policy,polname))
        else:
            s, o = traceCommand("xm activatepolicy --load")
    else:
        s, o = traceCommand("xm activatepolicy --load")
        if not re.search("Successfully", o):
            FAIL("Could not set the policy '%s'." % policy)


def ACMLoadPolicy(policy='xm-test'):
    from xen.xm import main
    if main.serverType == main.SERVER_XEN_API:
        ACMLoadPolicy_XenAPI()
    else:
        cmd='xm dumppolicy | grep -E "^POLICY REFERENCE = ' + policy + '.$"'
        s, o = traceCommand(cmd)
        if o != "":
            return
        s, o = traceCommand("xm makepolicy %s" % (policy))
        if s != 0:
            FAIL("Need to be able to do 'xm makepolicy %s' but could not" %
                 (policy))
        s, o = traceCommand("xm loadpolicy %s" % (policy))
        if s != 0:
            FAIL("Could not load the required policy '%s'.\n"
                 "Start the system without any policy.\n%s" %
                 (policy, o))

def ACMPrepareSystem(resources):
    if isACMEnabled():
        ACMLoadPolicy()
        ACMLabelResources(resources)

def ACMLabelResources(resources):
    for k, v in resources.items():
        if k == "disk":
            for vv in v:
                res = vv.split(',')[0]
                ACMLabelResource(res)

# Applications may label resources explicitly by calling this function
def ACMLabelResource(resource, label='red'):
    if not isACMEnabled():
        return
    if acm_verbose:
        print "labeling resource %s with label %s" % (resource, label)
    if not ACM_LABEL_RESOURCES:
        SKIP("Skipping test since not allowed to label resources in "
             "test suite")
    if not isACMResourceLabeled(resource):
        ACMUnlabelResource(resource)
        s, o = traceCommand("xm addlabel %s res %s" % (label, resource))
        if s != 0:
            FAIL("Could not add label to resource")
        else:
            labeled_resources["%s" % resource] = 1


# Application may remove a label from a resource. It has to call this
# function and must do so once a resource for re-labeling a resource
def ACMUnlabelResource(resource):
    s, o = traceCommand("xm rmlabel res %s" % (resource))
    labeled_resources["%s" % resource] = 0


def isACMResourceLabeled(resource):
    """ Check whether a resource has been labeled using this API
        and while running the application """
    try:
        if labeled_resources["%s" % resource] == 1:
            if acm_verbose:
                print "resource %s already labeled!" % resource
            return True
    except:
        return False
    return False
