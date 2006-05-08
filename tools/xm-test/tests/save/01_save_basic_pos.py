#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import time

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Save currently not supported for HVM domains")

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
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

# Make sure it's gone
if isDomainRunning(domain.getName()):
    FAIL("Domain still running after save!")
