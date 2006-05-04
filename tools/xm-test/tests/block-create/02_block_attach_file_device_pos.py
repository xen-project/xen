#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import sys
import re
import time

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-attach not supported for HVM domains")

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# Set console to save commands and make sure we can run cmds
try:
    console.setHistorySaveCmds(value=True)
    # Run 'ls'
    run = console.runCmd("ls")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))
    

status, output = traceCommand("xm block-attach %s file:/dev/ram1 sdb2 w" % domain.getName())
if status != 0:
        FAIL("xm block-attach returned invalid %i != 0" % status)

try:
	run = console.runCmd("cat /proc/partitions")
except ConsoleError, e:
        FAIL(str(e))

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()

if not re.search("sdb2",run["output"]):
	FAIL("Device is not actually connected to the domU")
