#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>
#
# A test that exercises the conflict set of the chinese wall policy.
# Start a first domain and then a second one. The second one is
# expected NOT to be starteable.

from XmTestLib import *
from acm_utils import *
import commands
import os

testlabel1 = "blue"
testlabel2 = "red"

config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel1)}

domain1 = XmTestDomain(name="domain-%s" % testlabel1,
                       extraConfig=config)

try:
    domain1.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to start 1st labeled test domain")

# Verify with xm dry-run
status, output = traceCommand("xm dry-run /tmp/xm-test.conf | "
                              "grep -v \"Dry Run\"")
if status != 0:
    FAIL("'xm dry-run' failed")
if not re.search("PERMITTED", output):
    FAIL("'xm dry-run' did not succeed.")

config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel2)}

domain2 = XmTestDomain(name="domain-%s" % testlabel2,
                       extraConfig=config)

try:
    domain2.start(noConsole=True)
    # Should never get here!
    FAIL("Could start a domain in a conflict set - "
         "this should not be possible")
except DomainError, e:
    #This is exactly what we want in this case
    status = 0

# Verify with xm dry-run
status, output = traceCommand("xm dry-run /tmp/xm-test.conf | "
                              "grep -v \"Dry Run\"")
if status != 0:
    FAIL("'xm dry-run' failed.")
if not re.search("PERMITTED", output):
    FAIL("'xm dry-run' did not show that operation was permitted.")

domain1.destroy()
