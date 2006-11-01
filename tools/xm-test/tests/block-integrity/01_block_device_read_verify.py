#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Harry Butterworth <butterwo@uk.ibm.com>

# This test initialises a ram disk in dom0 with data from /dev/urandom and
# then imports the ram disk device as a physical device into a domU. The md5
# checksum of the data in the ramdisk is calculated in dom0 and also
# calculated by the domU reading the data through the blk frontend and
# backend drivers.  The test succeeds if the checksums match indicating that
# the domU successfully read all the correct data from the device.

import re

from XmTestLib import *
from XmTestLib.block_utils import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-attach not supported for HVM domains")

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    FAIL(str(e))

console.setHistorySaveCmds(value=True)

traceCommand("cat /dev/urandom > /dev/ram1")

s, o = traceCommand("md5sum /dev/ram1")

dom0_md5sum_match = re.search(r"^[\dA-Fa-f]{32}", o, re.M)

block_attach(domain, "phy:ram1", "xvda1")

try:
    run = console.runCmd("md5sum /dev/xvda1")
except ConsoleError, e:
    FAIL(str(e))

domU_md5sum_match = re.search(r"^[\dA-Fa-f]{32}", run["output"], re.M)

domain.closeConsole()

domain.stop()

if dom0_md5sum_match == None:
    FAIL("Failed to get md5sum of test ram disk in dom0.")

if domU_md5sum_match == None:
    FAIL("Failed to get md5sum of test ram disk in domU.")

if verbose:
    print "md5sum dom0:"
    print dom0_md5sum_match.group()
    print "md5sum domU:"
    print domU_md5sum_match.group()

if dom0_md5sum_match.group() != domU_md5sum_match.group():
    FAIL("MISCOMPARE: data read in domU did not match data provided by domO.")
