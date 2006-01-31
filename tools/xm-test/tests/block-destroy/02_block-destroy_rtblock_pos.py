#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-detach not supported for HVM domains")

domain = XmTestDomain()

try:
    domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

status, output = traceCommand("xm block-attach %s phy:/dev/ram0 hda1 w" % domain.getName())
if status != 0:
    FAIL("Failed to attach block device")
    pass

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
    FAIL("Failed to verify that block dev is attached")

status, output = traceCommand("xm block-detach %s 769" % domain.getName())
if status != 0:
    FAIL("block-detach returned invalid %i != 0" % status)

try:
    run = console.runCmd("cat /proc/partitions | grep hda1")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

if run["return"] == 0:
    FAIL("block-detach failed to detach block device")
    
    
