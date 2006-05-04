#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

# 1) Make sure we have a multi cpu system
# 2) Create a test domain and pin its VCPU0 to CPU 0 and then 1

import sys;
import re;

from XmTestLib import *

# Verify that we can run this test on this host
if smpConcurrencyLevel() <= 1:
    print "*** NOTE: This machine does not have more than one physical"
    print "          or logical cpu.  The vcpu-pin test cannot be run!"
    SKIP("Host not capable of running test")

domain = XmTestDomain()

try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

status, output = traceCommand("xm vcpu-pin %s 0 0" % domain.getName())

if status != 0:
    FAIL("xm vcpu-pin returned invalid %i != 0" % status)

cpu = getVcpuInfo(domain.getName())[0]

if cpu != 0:
    FAIL("failed to switch VCPU 0 to CPU 0")

status, output = traceCommand("xm vcpu-pin %s 0 1" % domain.getName())

if status != 0:
    FAIL("xm vcpu-pin returned invalid %i != 0" % status)

cpu = getVcpuInfo(domain.getName())[0]

if cpu != 1:
    FAIL("failed to switch VCPU 0 to CPU 1")

domain.stop()
