#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

# Save a domain and attempt to restore it
#
# Since we don't want to depend on the fact that save/01_basic_pos.py
# ran successfully, we try to save the domain here again

import time

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Restore currently not supported for HVM domains")

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# Make sure the domain isn't DOA
try:
    console.runCmd("foo=bar")
except ConsoleError, e:
    FAIL(str(e))

domain.closeConsole()

# Save it out
try:
    s, o = traceCommand("xm save %s /tmp/test.state" % domain.getName(),
                        timeout=30)
except TimeoutError, e:
    FAIL(str(e))
    
if s != 0:
    FAIL("save command exited %i != 0" % s)

# FIXME: Give the system some time to update the internal state
traceCommand("xm list")

# Make sure it's gone
if isDomainRunning(domain.getName()):
    FAIL("Domain still running after save!")

# Let things settle
time.sleep(2)

# Restore it in
status, output = traceCommand("xm restore /tmp/test.state",
                              timeout=30)
if s != 0:
    FAIL("restore command exited %i != 0" % s)

# Make sure it's running
if not isDomainRunning(domain.getName()):
    FAIL("Restore didn't result in a running %s domain!" % domain.getName())

# Make sure it's alive
try:
    newConsole = domain.getConsole()
    # Enable debug dumping because this generates a Oops on x86_64
    newConsole.debugMe = True
    newConsole.sendInput("ls")
    run = newConsole.runCmd("echo xx$foo")
    if not re.search("bar", run["output"]):
        FAIL("Restored domain has been reset")
except ConsoleError, e:
    FAIL("Restored domain is dead (%s)" % str(e))

domain.closeConsole()

# This only works because the domain
# still has the same name
domain.stop()
