#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import random
import re

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Mem-set not supported for HVM domains")

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to start domain:"
        print e.extra
    FAIL(str(e))

times = random.randint(10,50)

xen_mem = XenMemory(console)

origmem = xen_mem.get_mem_from_domU()
currmem = origmem

for i in range(0,times):
    amt = random.randint(-10,10)

    target = currmem + amt

    # Make sure we're not going over or under
    if target < domain.minSafeMem():
        continue
    if target > origmem:
        continue

    if verbose:
        print "[%i/%i] Current: %i Target: %i" % (i, times, currmem, target)

    cmd = "xm mem-set %s %i" % (domain.getName(), target)
    status, output = traceCommand(cmd)

    if status != 0:
        if verbose:
            print "mem-set failed:"
            print output
        FAIL("mem-set from %i to %i failed" % (currmem, target))
    
    domUmem = xen_mem.get_mem_from_domU()

    currmem = target
    actual = int(getDomInfo(domain.getName(), "Mem"))

    if actual != currmem:
        FAIL("Expected %i MB, xm reported %i MB" % (currmem, actual))
    if domUmem != currmem:
        FAIL("Expected %i MB, domU reported %i MB" % (currmem, domUmem))
        

