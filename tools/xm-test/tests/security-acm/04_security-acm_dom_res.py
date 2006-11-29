#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>
#
# Simple test that starts two labeled domains using labeled resources each
#

from XmTestLib import *
from acm_utils import *
import commands
import os

testlabel1 = "green"
resource1  = "phy:ram0"
testlabel2 = "red"
resource2  = "phy:/dev/ram1"

config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel1),
          "disk"          :"%s,hda1,w" % (resource1)}
domain1 = XmTestDomain(name="domain-%s" % testlabel1,
                       extraConfig=config)

# Explicity label the resource
ACMLabelResource(resource1, testlabel1)

try:
    domain1.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to start 1st labeled test domain.")

# Verify with xm dry-run
status, output = traceCommand("xm dry-run /tmp/xm-test.conf | "
                              "grep -v \"Dry Run\"")

if status != 0:
    FAIL("'xm dry-run' failed")
if not re.search("%s: PERMITTED" % resource1, output):
    FAIL("'xm dry-run' did not succeed.")

config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel2),
          "disk"          :"%s,hda1,w" % (resource2)}

domain2 = XmTestDomain(name="domain-%s" % testlabel2,
                       extraConfig=config)

# Explicity label the resource
ACMLabelResource(resource2, testlabel2)

try:
    domain2.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to start 2nd labeled test domain.")

# Verify with xm dry-run
status, output = traceCommand("xm dry-run /tmp/xm-test.conf | "
                              "grep -v \"Dry Run\"")

if status != 0:
    FAIL("'xm dry-run' failed")
if not re.search("%s: PERMITTED" % resource2, output):
    FAIL("'xm dry-run' did not succeed.")

domain2.destroy()
domain1.destroy()
