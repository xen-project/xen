#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Paul Larson  <pl@us.ibm.com>

# Description:
# Positive Tests:
# Test for xm shutdown
# 1) Create domain, verify it's up with console
# 2) shut down the domain, verify it's down

import time
import commands

from XmTestLib import *

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

# Start it
try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

try:
    # Make sure a command succeeds
    run = console.runCmd("ls /bin")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
status, output = traceCommand("xm shutdown %s" % domain.getName())
if status != 0:
    FAIL("good xm shutdown exited with bad %i != 0" % status)

# Verify the domain is gone
time.sleep(10)

if isDomainRunning(domain.getName()):

    traceCommand("xm list")
    if isDomainRunning(domain.getName()):
        FAIL("Guest domain failed to shutdown")
    else:
        FAIL("I had to run an xm list to update xend state!")


