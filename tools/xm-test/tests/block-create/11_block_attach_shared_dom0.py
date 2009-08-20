#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-attach not supported for HVM domains")

# Mount /dev/ram0

s, o = traceCommand("mkfs -j /dev/ram0")
if s != 0:
    FAIL("Unable to mkfs -j /dev/ram0")

s, o = traceCommand("mkdir -p mnt");
if s != 0:
    FAIL("Unable to create ./mnt")

s, o = traceCommand("mount /dev/ram0 mnt -o rw")
if s != 0:
    FAIL("Unable to mount /dev/ram0 on ./mnt")

# Now try to start a DomU with write access to /dev/ram0

config = {"disk":"phy:/dev/ram0,xvda1,w"}

domain = XmTestDomain(extraConfig=config);

try:
    domain.start()
    s, o = traceCommand("umount mnt")
    FAIL("Bug #331: Started a DomU with write access to a rw mounted block device")
except DomainError, e:
    s, o = traceCommand("umount mnt")

domain.destroy()
