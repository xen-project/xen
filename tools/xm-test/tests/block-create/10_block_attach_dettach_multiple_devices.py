#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Copyright (C) flonatel GmbH & Co. KG, 2009
# Authors: Murillo F. Bernardes <mfb@br.ibm.com>
#          Andreas Florath <xen@flonatel.org>

# Block devices are by random attached to and detached from the domU. 

import re
import random
from xen.util import blkif

from os.path import basename

from XmTestLib import *
from XmTestLib.block_utils import *

def availableRamdisks():
    i=0
    while os.access("/dev/ram%d" % i, os.F_OK):
        i+=1
    return i-1

def attach(phy, devname):
    block_attach(domain, "phy:%s" % phy, devname)
    run = console.runCmd("cat /proc/partitions")
    if not re.search(basename(devname), run["output"]):
        return -2, "Failed to attach block device: " \
                   + "/proc/partitions does not show that!"
    return 0, None


def detach(devname):
    block_detach(domain, devname)
    run = console.runCmd("cat /proc/partitions")
    if re.search(basename(devname), run["output"]):
        return -2, "Failed to detach block device: " \
                   + "/proc/partitions still showing that!"
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

ramdisk_cnt = availableRamdisks()

detached = range(0, ramdisk_cnt)
attached = []

def attach_device():
    n = random.choice(detached)
    status, msg = attach("ram%d" % n, "xvda%d" % n)
    if status:
        FAIL(msg)
    detached.remove(n)
    attached.append(n)

def detach_device():
    n = random.choice(attached)
    status, msg = detach("xvda%d" % n)
    if status:
        FAIL(msg)
    detached.append(n)
    attached.append(n)

# First attach some
for i in xrange(0, ramdisk_cnt/2):
    attach_device()

for i in xrange(0, ramdisk_cnt*5):
    op = random.randint(0,1) # 1 = attach, 0 = detach
    if op:
        detach_device()
    else:
        attach_device()
    
# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()
