#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>
#
# A test that tries to start a domain using a resource that it is
# not supposed to be able to use due to its labeling

from XmTestLib import *
from acm_utils import *
import commands
import os

testlabel1 = "blue"
resource1  = "phy:ram0"

config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel1),
          "disk"          :"%s,hda1,w" % (resource1)}

domain1 = XmTestDomain(name="domain-%s" % testlabel1,
                       extraConfig=config)

ACMLabelResource(resource1,"red")

try:
    domain1.start(noConsole=True)
    # Should never get here
    FAIL("Could start domain with resource that it is not supposed to access.")
except DomainError, e:
    #That's exactly what we want to have in this case
    dummy = 0

# Verify via dry-run
status, output = traceCommand("xm dry-run /tmp/xm-test.conf | "
                              "grep -v \"Dry Run\"")
if not re.search("%s: DENIED" %resource1, output):
    FAIL("'xm dry-run' did not show expected result that operation was NOT "
         "permitted: \n%s" % output)
