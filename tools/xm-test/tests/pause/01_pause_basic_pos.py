#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Paul Larson  <pl@us.ibm.com>

# Description:
# Positive Tests:
# Tests for xm pause
# 1) Create domain, verify it's up with console
# 2) pause the domain
# 3) verify it's paused by failure to connect console

import time
import commands

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
    # Make sure a command succeeds
    run = console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
console.closeConsole()

# Pause the domain
status, output = traceCommand("xm pause %s" % domain.getName())
if status != 0:
	FAIL("xm pause returned invalid %i != 0", status)

# Attach a console to it
try:
    console = XmConsole(domain.getName(), historySaveCmds=True)
except ConsoleError, e:
    FAIL(str(e))
try:
    run = console.runCmd("ls")
    #If we get here, console attached to paused domain (unexpected)
    FAIL("console attached to supposedly paused domain")
except ConsoleError, e:
    pass

# Close the console
console.closeConsole()

status, output = traceCommand("xm unpause %s" % domain.getName())
if status != 0:
	FAIL("xm unpause returned invalid %i != 0", status)

# Stop the domain (nice shutdown)
domain.stop()

