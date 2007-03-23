#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Paul Larson  <pl@us.ibm.com>

# Description:
# Positive Tests:
# Tests for xm unpause
# 1) Create domain, verify it's up with console
# 2) randomly pause and unpause the domain
# 3) unpause it one last time
# 4) verify it's still alive with console

import time
import commands
from random import *

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
    run = console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
domain.closeConsole()

seed(time.time())

for i in range(100):
    pauseit = randint(0,1)
    if(pauseit):
        # Pause the domain
        status, output = traceCommand("xm pause %s" % domain.getName())
        if status != 0:
            FAIL("xm pause returned invalid %i != 0", status)
    else:
        # Unpause the domain
        status, output = traceCommand("xm unpause %s" % domain.getName())
        if status != 0:
            FAIL("xm unpause returned invalid %i != 0", status)

# Make sure the domain is unpaused before we finish up
status, output = traceCommand("xm unpause %s" % domain.getName())
if status != 0:
    FAIL("xm unpause returned invalid %i != 0", status)

# Are we still alive after all that?
try:
    console = domain.getConsole()
    run = console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
domain.closeConsole()

if run["return"] != 0:
    FAIL("console failed to attach to supposedly unpaused domain")

# Stop the domain (nice shutdown)
domain.stop()

