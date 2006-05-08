#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Authors: Dan Smith <danms@us.ibm.com>
#          Ryan Harper <ryanh@us.ibm.com>

# 1) Make sure we have a multi cpu system
# 2) Create a test domain with 2 VCPUs
# 3) Verify that both VCPUs are alive
# 4) Disable DOM VCPU1 by setting the VCPU count to 1
# 5) Assert that the VCPU has been disabled
# 6) Enable DOM VCPU1 (restore VCPU count to 2)
# 7) Assert that the VCPUs are both alive again

import sys
import re
import time

from XmTestLib import *

check_status = 1
max_tries = 10

def safecmd(cmd):
    i=0
    while i < max_tries:
        status, output = traceCommand(cmd)
        if status == 0:
            break
        i = i+1
        # print "output: [%s]"%(output)
        time.sleep(1)
    return status, output

# Verify that we can run this test on this host
if smpConcurrencyLevel() <= 1:
    print "*** NOTE: This machine does not have more than one physical"
    print "          or logical cpu.  The vcpu-disable test cannot be run!"
    SKIP("Host not capable of running test")

# Start a XmTestDomain with 2 VCPUs
domain = XmTestDomain(extraConfig={"vcpus":2})

try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# Disable VCPU 1
cmd = "xm vcpu-set %s 1" % domain.getName()
status, output = safecmd(cmd)
if check_status and status != 0:
    FAIL("\"%s\" returned invalid %i != 0" %(cmd,status))

# Wait for the change to become active
for i in [1,2,3,4,5,6,7,8,9,10]:
    domUvcpu1 = getVcpuInfo(domain.getName())[1]
    status, output = traceCommand("xm vcpu-list")
    if domUvcpu1 is None:
        break
    time.sleep(1)

if domUvcpu1 is not None:
    print "domUvcpu1: [%s] output: [%s]"%(domUvcpu1, output)
    FAIL("failed to disable VCPU1")

# Enable VCPU 1
cmd = "xm vcpu-set %s 2" % domain.getName()
status, output = safecmd(cmd)
if check_status and status != 0:
    FAIL("\"%s\" returned invalid %i != 0" %(cmd,status))

for i in [1,2,3,4,5,6,7,8,9,10]:
    domUvcpu1 = getVcpuInfo(domain.getName())[1]
    if domUvcpu1 is not None:
        break
    time.sleep(1)

domain.destroy()
