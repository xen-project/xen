#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *
from XmTestLib.block_utils import block_detach

if ENABLE_HVM_SUPPORT:
    SKIP("Block-detach not supported for HVM domains")

config = {"disk":"phy:/dev/ram0,xvda1,w"}
domain = XmTestDomain(extraConfig=config)

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

try:
    run = console.runCmd("cat /proc/partitions | grep xvda1")
    run2 = console.runCmd("cat /proc/partitions")
except ConsoleError, e:
    FAIL(str(e))

if run["return"] != 0:
    FAIL("block device isn't attached; can't detach!")

block_detach(domain, "xvda1")
try:

    run = console.runCmd("cat /proc/partitions | grep xvda1")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

domain.closeConsole()
domain.stop()

if run["return"] == 0:
    FAIL("domU reported block device still connected!" % run["return"])
