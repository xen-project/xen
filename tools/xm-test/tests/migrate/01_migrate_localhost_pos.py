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
    run = console.runCmd("ls /bin")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
console.closeConsole()

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
    console = XmConsole(domain.getName(), historySaveCmds=True)
except ConsoleError, e:
    pass

# Run 'ls'
try:
    # Check the dmesg output on the domU
    run = console.runCmd("ls /bin")
except ConsoleError, e:
    FAIL(str(e))

if not re.search("chmod", run["output"]):
    FAIL("invalid console output from ls after migration")

# Close the console
console.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()

