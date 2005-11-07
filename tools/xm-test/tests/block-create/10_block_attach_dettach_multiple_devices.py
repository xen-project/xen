#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import sys
import re
import time
import random
from xen.util import blkif

from os import path.basename

from XmTestLib import *

def availableRamdisks():
    i = 0
    while os.access("/dev/ram%d" % i, os.F_OK ):
    	i += 1

    return i

def attach(phy, devname):
    # Attach 
    status, output = traceCommand("xm block-attach %s phy:%s %s w" % (domain.getName(), phy, devname))
    if status != 0:
    	return -1, "xm block-attach returned invalid %i != 0" % status
	
    run = console.runCmd("cat /proc/partitions")
    if not re.search(basename(devname), run["output"]):
        return -2, "Failed to attach block device: /proc/partitions does not show that!"

    return 0, None


def dettach(devname):
    devnum = blkif.blkdev_name_to_number(devname)
    
    status, output = traceCommand("xm block-detach %s %d" % (domain.getName(), devnum))
    if status != 0:
        return -1, "xm block-attach returned invalid %i != 0" % status

    run = console.runCmd("cat /proc/partitions")
    if re.search(basename(devname), run["output"]):
        return -2, "Failed to dettach block device: /proc/partitions still showing that!"

    return 0, None
	
# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

try:
    domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# Attach a console to it
try:
    console = XmConsole(domain.getName(), historySaveCmds=True)
except ConsoleError, e:
    FAIL(str(e))

try:
    # Activate the console
    console.sendInput("input")
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
	status, msg = dettach(devname)
	if status:
	    FAIL(msg)

# Close the console
console.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()
