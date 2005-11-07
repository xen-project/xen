#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com)

# Positive Test: attempt list of domain wtih no block devices


from XmTestLib import *

domain = XmTestDomain()

try:
    domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

status, output = traceCommand("xm block-list %s" % domain.getId())
if status != 0:
    FAIL("xm block-list returned bad status, expected 0, status is %i" % status)

if USE_BLKDEV_FOR_ROOT:
    SKIP("Using block device for root, so this case does not apply")

if output != "":
    FAIL("xm block-list should not list anything for domain with no block devices")
