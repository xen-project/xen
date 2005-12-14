#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import sys
import re
import time

from XmTestLib import *
from network_utils import *

if ENABLE_VMX_SUPPORT:
    SKIP("Network-attach not supported for VMX domains")

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

## Real test - attach and detach
status, msg = network_attach(domain.getName(), console)
if status:
    FAIL(msg)

status, msg = network_detach(domain.getName(), console)
if status:
    FAIL(msg)



# Close the console
console.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()
