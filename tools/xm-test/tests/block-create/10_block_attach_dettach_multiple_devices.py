#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import re
import random
from xen.util import blkif

from os import path.basename

from XmTestLib import *
from XmTestLib.block_utils import *

def availableRamdisks():
    i = 0
    while os.access("/dev/ram%d" % i, os.F_OK ):
    	i += 1

    return i

def attach(phy, devname):
    block_attach(domain, "phy:%s" % phy, devname)
    run = console.runCmd("cat /proc/partitions")
    if not re.search(basename(devname), run["output"]):
        return -2, "Failed to attach block device: /proc/partitions does not show that!"

    return 0, None


def detach(devname):
    block_detach(domain, devname)

    run = console.runCmd("cat /proc/partitions")
    if re.search(basename(devname), run["output"]):
        return -2, "Failed to detach block device: /proc/partitions still showing that!"

    return 0, None
	
if ENABLE_HVM_SUPPORT:
    SKIP("Block-attach not supported for HVM domains")

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

try:
    console.setHistorySaveCmds(value=True)
    # Run 'ls'
    run = console.runCmd("ls")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))
    

ramdisks = availableRamdisks()-1
print "ramdisks=%d" % ramdisks
i = 0 
devices = []

while i < ramdisks or devices:
    op = random.randint(0,1) # 1 = attach, 0 = detach
    if (not devices or op) and i < ramdisks:
        i += 1
	devname = "/dev/hda%d" % i
	phy = "/dev/ram%d" % i
	print "Attaching %s to %s" % (devname, phy)
	status, msg = attach( phy, devname )
	if status:
	    FAIL(msg)
	else:
	    devices.append(devname)

    elif devices:
        devname = random.choice(devices)
	devices.remove(devname)
	print "Detaching %s" % devname
	status, msg = detach(devname)
	if status:
	    FAIL(msg)

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()
