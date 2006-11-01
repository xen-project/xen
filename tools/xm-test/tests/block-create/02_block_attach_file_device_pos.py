#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import re

from XmTestLib import *
from XmTestLib.block_utils import *

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
    

block_attach(domain, "file:/dev/ram1", "xvda1")

try:
    run = console.runCmd("cat /proc/partitions")
except ConsoleError, e:
        FAIL(str(e))

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()

if not re.search("xvda1",run["output"]):
    FAIL("Device is not actually connected to the domU")
