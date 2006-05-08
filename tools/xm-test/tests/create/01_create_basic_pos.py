#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import sys
import re
import time

from XmTestLib import *

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

if int(getInfo("free_memory")) < domain.config.getOpt("memory"):
    SKIP("This test needs %i MB of free memory (%i MB avail)" %
         (domain.config.getOpt("memory"), int(getInfo("free_memory"))))

# Start it
try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

try:
    # Run 'ls'
    run = console.runCmd("ls")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

# Save a transcript for human review
saveLog(console.getHistory())
    
# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()

# Check the output of 'ls'

if not re.search("proc", run["output"]):
    if verbose:
        print run["output"]
    FAIL("'ls' output looks wrong (didn't see /proc)")
