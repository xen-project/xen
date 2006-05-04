#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import sys
import re
import time

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Sysrq not supported for HVM domains")

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

status, output = traceCommand("xm sysrq %s s" % domain.getName())

if status != 0:
    FAIL("Good sysrq failed with: %i != 0", status)

# -- CHECK OUTPUT

# Run 'ls'
try:
    # Check the dmesg output on the domU
    run = console.runCmd("dmesg | grep Emerg\n")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()

# Save a transcript for human review
# saveLog(console.getHistory())

# Check dmesg for the sysrq notice
if not re.search("Emergency", run["output"]):
    FAIL("Sync SysRq not delivered")
