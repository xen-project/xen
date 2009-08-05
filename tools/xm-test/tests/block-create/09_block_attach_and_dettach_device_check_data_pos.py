#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Copyright (C) flonatel GmbH & Co. KG, 2009
# Authors: Murillo F. Bernardes <mfb@br.ibm.com>
#          Andreas Florath <xen@flonatel.org>

import re

from XmTestLib import *
from XmTestLib.block_utils import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-attach not supported for HVM domains")

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain(extraConfig={"extra":"rw"})

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
    
s, o = traceCommand("mke2fs -j -q -F /dev/ram1")
if s != 0:
    FAIL("mke2fs returned %i != 0" % s)

for i in range(10):
    block_attach(domain, "phy:ram1", "xvda1")
    run = console.runCmd("cat /proc/partitions")
    if not re.search("xvda1", run["output"]):
        FAIL("Failed to attach block device: /proc/partitions does not show that!")
    
    console.runCmd("mkdir -p /mnt/xvda1; mount /dev/xvda1 /mnt/xvda1")
    
    if i:
        run = console.runCmd("cat /mnt/xvda1/myfile | grep %s" % (i-1))
        if run['return']:
            FAIL("File created was lost or not updated!")
    
    console.runCmd("echo \"%s\" > /mnt/xvda1/myfile" % i)
    run = console.runCmd("cat /mnt/xvda1/myfile")
    print run['output']
    console.runCmd("umount /mnt/xvda1")
    
    block_detach(domain, "xvda1")
    run = console.runCmd("cat /proc/partitions")
    if re.search("xvda1", run["output"]):
        FAIL("Failed to dettach block device: /proc/partitions still showing that!")

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()
