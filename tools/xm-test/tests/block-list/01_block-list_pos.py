#!/usr/bin/python
                                                                                              
# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com)

# Positive Test: create domain with block attached at build time, verify list


from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-list not supported for HVM domains")

config = {"disk":"phy:/dev/ram0,xvda1,w"}
domain = XmTestDomain(extraConfig=config)

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

status, output = traceCommand("xm block-list %s" % domain.getId())
eyecatcher = "51713"
where = output.find(eyecatcher)
if status != 0:
    FAIL("xm block-list returned bad status, expected 0, status is %i" % status)
elif where < 0:
    FAIL("Fail to list block device")

#Verify the block device on DomainU
try:
    run = console.runCmd("cat /proc/partitions | grep xvda1")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

domain.stop()

if run["return"] != 0:
    FAIL("Failed to verify that block dev is attached on DomainU")
