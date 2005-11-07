#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import sys
import re
import time

from XmTestLib import *


# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

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
    console.sendInput("input")
    # Run 'ls'
    run = console.runCmd("ls")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))
    

status, output = traceCommand("xm block-attach %s phy:ram1 sdb1 w" % domain.getName())
if status != 0:
        FAIL("xm block-attach returned invalid %i != 0" % status)

try:	
	run = console.runCmd("cat /proc/partitions")
except ConsoleError, e:
	FAIL(str(e))

# Close the console
console.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()

if not re.search("sdb1",run["output"]):
    FAIL("Device is not actually connected to the domU")
