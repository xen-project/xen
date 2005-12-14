#!/usr/bin/python
                                                                                              
# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

# Positive Test: create domain with block attach, attach another, verify both in list


from XmTestLib import *

if ENABLE_VMX_SUPPORT:
    SKIP("Block-list not supported for VMX domains")

config = {"disk":"phy:/dev/ram0,hda1,w"}
domain = XmTestDomain(extraConfig=config)

try:
    domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

status, output = traceCommand("xm block-list %s" % domain.getId())
if status != 0:
    FAIL("Fail to list block device")

#Add another virtual block device to the domain
status, output = traceCommand("xm block-attach %s phy:/dev/ram1 hda2 w" % domain.getId())
if status != 0:
    FAIL("Fail to attach block device")

#Verify block-list on Domain0
status, output = traceCommand("xm block-list %s" % domain.getId())
eyecatcher1 = "769"
eyecatcher2 = "770"
where1 = output.find(eyecatcher1)
where2 = output.find(eyecatcher2)
if status != 0:
    FAIL("xm block-list returned bad status, expected 0, status is %i" % status)
elif (where1 < 0) and (where2 < 0):
    FAIL("Fail to list all block devices after attaching another block device")

#Verify attached block device on DomainU
try:
    console = XmConsole(domain.getName())
except ConsoleError, e:
    FAIL(str(e))

try:
    console.sendInput("input")
    run = console.runCmd("cat /proc/partitions | grep hda1;cat /proc/partitions | grep hda2")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

if run["return"] != 0:
    FAIL("Failed to verify that block dev is attached on DomainU")
