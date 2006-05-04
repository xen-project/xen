#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import sys
import re
import time

from XmTestLib import *

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
    
s, o = traceCommand("mke2fs -q -F /dev/ram1")
if s != 0:
    FAIL("mke2fs returned %i != 0" % s)

for i in range(10):
	status, output = traceCommand("xm block-attach %s phy:ram1 hda1 w" % domain.getName())
	if status != 0:
        	FAIL("xm block-attach returned invalid %i != 0" % status)
	# verify that it comes
	run = console.runCmd("cat /proc/partitions")
	if not re.search("hda1", run["output"]):
		FAIL("Failed to attach block device: /proc/partitions does not show that!")
	
	console.runCmd("mkdir -p /mnt/hda1; mount /dev/hda1 /mnt/hda1")
	
	if i:
		run = console.runCmd("cat /mnt/hda1/myfile | grep %s" % (i-1))
		if run['return']:
			FAIL("File created was lost or not updated!")
	
	console.runCmd("echo \"%s\" > /mnt/hda1/myfile" % i)
	run = console.runCmd("cat /mnt/hda1/myfile")
	print run['output']
	console.runCmd("umount /mnt/hda1")
	
	status, output = traceCommand("xm block-detach %s 769" % domain.getName())
	if status != 0:
		FAIL("xm block-detach returned invalid %i != 0" % status)
	# verify that it goes
	run = console.runCmd("cat /proc/partitions")
	if re.search("hda1", run["output"]):
		FAIL("Failed to dettach block device: /proc/partitions still showing that!")

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()
