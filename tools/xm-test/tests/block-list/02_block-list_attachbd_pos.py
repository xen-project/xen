#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com)

# Positive Test: create domain, attach block device, verify list


from XmTestLib import *
from XmTestLib.block_utils import block_attach

if ENABLE_HVM_SUPPORT:
    SKIP("Block-list not supported for HVM domains")

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

#Attach one virtual block device to domainU
block_attach(domain, "phy:/dev/ram0", "xvda1")

#Verify block-list on Domain0
status, output = traceCommand("xm block-list %s" % domain.getId())
eyecatcher = "51713"
where = output.find(eyecatcher)
if status != 0:
    FAIL("xm block-list returned bad status, expected 0, status is %i" % status)
elif where < 0 :
    FAIL("Fail to list block device")

#Verify attached block device on DomainU
try:
    run = console.runCmd("cat /proc/partitions | grep xvda1")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

domain.stop()

if run["return"] != 0:
    FAIL("Failed to verify that block dev is attached on DomainU")
