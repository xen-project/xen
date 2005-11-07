#!/usr/bin/python
                                                                                              
# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com)

# Positive Test: create domain with block attached at build time, verify list


from XmTestLib import *

domain = XmTestDomain()

domain.configAddDisk("phy:/dev/ram0", "hda1", "w")

try:
    domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

status, output = traceCommand("xm block-list %s" % domain.getId())
eyecatcher = "769"
where = output.find(eyecatcher)
if status != 0:
    FAIL("xm block-list returned bad status, expected 0, status is %i" % status)
elif where < 0:
    FAIL("Fail to list block device")

#Verify the block device on DomainU
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
