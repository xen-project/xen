#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Harry Butterworth <butterwo@uk.ibm.com>

# This test imports a ram disk device as a physical device into a domU.
# The domU initialises the ram disk with data from /dev/urandom and calculates
# the md5 checksum of the data (using tee as it is written so as to avoid
# reading it back from the device which might potentially mask problems).
# The domU is stopped and the md5 checksum of the data on the device is
# calculated by dom0.  The test succeeds if the checksums match, indicating
# that all the data written by domU was sucessfully committed to the device.

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

block_attach(domain, "phy:ram1", "xvda1")

console.setTimeout(120)

try:
    run = console.runCmd("dd if=/dev/urandom bs=512 count=`cat /sys/block/xvda1/size` | tee /dev/xvda1 | md5sum")
except ConsoleError, e:
    FAIL(str(e))

domU_md5sum_match = re.search(r"^[\dA-Fa-f]{32}", run["output"], re.M)

domain.closeConsole()

domain.stop()

s, o = traceCommand("md5sum /dev/ram1")

dom0_md5sum_match = re.search(r"^[\dA-Fa-f]{32}", o, re.M)

if domU_md5sum_match == None:
    FAIL("Failed to get md5sum of data written in domU.")

if dom0_md5sum_match == None:
    FAIL("Failed to get md5sum of data read back in dom0.")

if verbose:
    print "md5sum domU:"
    print domU_md5sum_match.group()
    print "md5sum dom0:"
    print dom0_md5sum_match.group()

if domU_md5sum_match.group() != dom0_md5sum_match.group():
    FAIL("MISCOMPARE: data read in dom0 did not match data written by domU.")
