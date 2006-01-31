#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-detach not supported for HVM domains")

config = {"disk":"phy:/dev/ram0,hda1,w"}
domain = XmTestDomain(extraConfig=config)

try:
    domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

try:
    console  = XmConsole(domain.getName(), historySaveCmds=True)
    console.sendInput("input")
    run = console.runCmd("cat /proc/partitions | grep hda1")
    run2 = console.runCmd("cat /proc/partitions")
except ConsoleError, e:
    FAIL(str(e))

if run["return"] != 0:
    FAIL("block device isn't attached; can't detach!")

status, output = traceCommand("xm block-detach %s 769" % domain.getName(),
                              logOutput=True)
if status != 0:
    FAIL("block-detach returned invalid %i != 0" % status)

try:

    run = console.runCmd("cat /proc/partitions | grep hda1")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

console.closeConsole()
domain.stop()

if run["return"] == 0:
    FAIL("domU reported block device still connected!")
