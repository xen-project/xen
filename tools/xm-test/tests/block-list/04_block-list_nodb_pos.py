#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com)

# Positive Test: attempt list of domain wtih no block devices


from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-list not supported for HVM domains")

domain = XmTestDomain()

try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

status, output = traceCommand("xm block-list %s" % domain.getId())
if status != 0:
    FAIL("xm block-list returned bad status, expected 0, status is %i" % status)

if output != "":
    FAIL("xm block-list should not list anything for domain with no block devices")
