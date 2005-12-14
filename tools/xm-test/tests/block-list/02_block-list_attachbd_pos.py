#!/usr/bin/python
                                                                                              
# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com)

# Positive Test: create domain, attach block device, verify list


from XmTestLib import *

if ENABLE_VMX_SUPPORT:
    SKIP("Block-list not supported for VMX domains")

domain = XmTestDomain()
                                                                                              
try:
    domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

#Attach one virtual block device to domainU
status, output = traceCommand("xm block-attach %s phy:/dev/ram0 hda1 w" % domain.getId())
if status != 0:
    FAIL("Fail to attach block device")

#Verify block-list on Domain0
status, output = traceCommand("xm block-list %s" % domain.getId())
eyecatcher = "769"
where = output.find(eyecatcher)
if status != 0:
    FAIL("xm block-list returned bad status, expected 0, status is %i" % status)
elif where < 0 :
    FAIL("Fail to list block device")

#Verify attached block device on DomainU
try:
    console = XmConsole(domain.getName())
except ConsoleError, e:
    FAIL(str(e))

try:
    console.sendInput("input")
    run = console.runCmd("cat /proc/partitions | grep hda1")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

if run["return"] != 0:
    FAIL("Failed to verify that block dev is attached on DomainU")
