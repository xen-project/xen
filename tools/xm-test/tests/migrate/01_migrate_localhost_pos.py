#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Paul Larson  <pl@us.ibm.com>

# Description:
# Positive Tests:
# Tests for xm migrate
# 1) Create domain, verify it's up with console
# 2) live migrate the domain to localhost
# 3) verify it's migrated, see that it has a new domain ID
# 4) verify it's still working properly by running a command on it

import re
import time
import commands

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Migrate currently not supported for HVM domains")

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
    # Set a variable to check on the other side
    run = console.runCmd("foo=bar")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
domain.closeConsole()

old_domid = domid(domain.getName())

# Migrate the domain
try:
    status, output = traceCommand("xm migrate -l %s localhost" % domain.getName(),
                                  timeout=90)
except TimeoutError, e:
    FAIL(str(e))
    
if status != 0:
    FAIL("xm migrate returned invalid %i != 0" % status)

new_domid = domid(domain.getName())

if (old_domid == new_domid):
    FAIL("xm migrate failed, domain id is still %s" % old_domid)

# Attach a console to it
try:
    console = domain.getConsole()
    console.debugMe = True
except ConsoleError, e:
    pass

console.setHistorySaveCmds(value=True)
console.sendInput("ls")

# Run 'ls'
try:
    # Check the dmesg output on the domU
    run = console.runCmd("echo xx$foo")
except ConsoleError, e:
    FAIL(str(e))
    
if not re.search("bar", run["output"]):
    FAIL("Migrated domain has been reset")

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()

