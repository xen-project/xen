#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>

import sys
import re
import time

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
    # Run 'ls'
    run = console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
domain.closeConsole()

# Check the output of 'ls'
if not re.search("proc", run["output"]):
    FAIL("'ls' output looks wrong (Didn't see proc)")

# destroy domain - positive test
status, output = traceCommand("xm destroy %s" % domain.getName())
if status != 0:
    FAIL("xm destroy returned invalid %i != 0" % status)
