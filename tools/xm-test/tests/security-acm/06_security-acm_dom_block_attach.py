#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Stefan Berger <stefanb@us.ibm.com>
# Based on block-create/01_block_attach_device_pos.py
#
# Create a domain and attach 2 resources to it. The first resource
# should be attacheable, the 2nd one should not be due to the label it has.

import re
from XmTestLib import *
from XmTestLib import block_utils
from acm_utils import *

testlabel1 = "blue"
resource1 = "phy:ram1"
resourcelabel1 = "blue"
resource2 = "phy:/dev/ram0"
resourcelabel2 = "red"

if ENABLE_HVM_SUPPORT:
    SKIP("Block-attach not supported for HVM domains")

# Create a domain (default XmTestDomain, with our ramdisk)
config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel1)}

domain = XmTestDomain(extraConfig=config)

try:
    console = domain.start()
except DomainError, e:
    FAIL(str(e))

# Attach a console to it
try:
    console.setHistorySaveCmds(value=True)
    # Run 'ls'
    run = console.runCmd("ls")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))


# Explicitly label the 1st resource
ACMLabelResource(resource1, resourcelabel1)
block_utils.block_attach(domain, resource1, "xvda1")

try:
    run1 = console.runCmd("cat /proc/partitions")
except ConsoleError, e:
    FAIL(str(e))

#Explicitly label the 2nd resource
ACMLabelResource(resource2, resourcelabel2)
#Cannot call block_attach here since we legally may fail the command
status, output = traceCommand("xm block-attach %s %s %s w" %
                               (domain.getName(), resource2, "xvda2" ))

for i in range(10):
    if block_utils.get_state(domain, "xvda2") == 4:
        break
    time.sleep(1)

try:
    run2 = console.runCmd("cat /proc/partitions")
except ConsoleError, e:
    FAIL(str(e))

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()

if not re.search("xvda1",run1["output"]):
    FAIL("Labeled device 'xvda1' is not actually connected to the domU")

if not re.search("xvda1",run2["output"]):
    FAIL("Labeled device 'xbvda1' has disappeared?!")

if re.search("xvda2",run2["output"]):
    FAIL("Labeled device 'xvda2' is connected to the domU but should not be")
