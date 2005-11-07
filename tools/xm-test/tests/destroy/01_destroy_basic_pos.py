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
    domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# Attach a console to it
try:
    console = XmConsole(domain.getName(), historySaveCmds=True)
except ConsoleError, e:
    FAIL(str(e))

try:
    # Activate the console
    console.sendInput("foo")
    # Run 'ls'
    run = console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
console.closeConsole()

# Check the output of 'ls'
if not re.search("proc", run["output"]):
    FAIL("'ls' output looks wrong (Didn't see proc)")

# destroy domain - positive test
status, output = traceCommand("xm destroy %s" % domain.getName())
if status != 0:
    FAIL("xm destroy returned invalud %i != 0" % status)
