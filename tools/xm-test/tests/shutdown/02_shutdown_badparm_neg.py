#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Paul Larson  <pl@us.ibm.com>

# Description:
# Positive Tests:
# Test for xm shutdown
# 1) Create domain
# 2) call xm shutdown with a bad parameter, expect failure

import commands

from XmTestLib import *

eyecatcher = "Error:"

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

# Start it
try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))


ret, output = traceCommand("xm shutdown -x %s" % domain.getName())
where = output.find(eyecatcher)
if (ret == 0):
    FAIL("xm shutdown returned invalid %i == 0" % ret)
elif where == -1:
    FAIL("xm shutdown failed to report error for bad arg")

# Stop the domain (nice shutdown)
domain.stop()
