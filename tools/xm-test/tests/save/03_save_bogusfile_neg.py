#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>
# Test Description:
# Negative Test:
# Create a new domain. Save this domain to bogus file reference. Verify fail.

import time

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Save currently not supported for HVM domains")

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

domain.closeConsole()

# Save it out
status, output = traceCommand("xm save %s /NOWHERE/test.state" % domain.getName())
eyecatcher1 = "Traceback"
eyecatcher2 = "Error:"
where1 = output.find(eyecatcher1)
where2 = output.find(eyecatcher2)
if status == 0:
    FAIL("xm save returned bad status, expected non 0, status is: %i" % status)
elif where1 == 0:
    FAIL("xm save returned a stack dump, expected nice error message")
elif where2 == -1:
    FAIL("xm save returned bad output, expected Error:, output is: %s" % output)
