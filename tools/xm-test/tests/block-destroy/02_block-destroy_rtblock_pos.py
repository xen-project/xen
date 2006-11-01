#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *
from XmTestLib.block_utils import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-detach not supported for HVM domains")

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

block_attach(domain, "phy:/dev/ram0", "xvda1")
try:
    run = console.runCmd("cat /proc/partitions | grep xvda1")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

if run["return"] != 0:
    FAIL("Failed to verify that block dev is attached")

block_detach(domain, "xvda1")
try:
    run = console.runCmd("cat /proc/partitions | grep xvda1")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

domain.stop()

if run["return"] == 0:
    FAIL("block-detach failed to detach block device")
