#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

dom1 = XmTestDomain()
dom2 = XmTestDomain(dom1.getName() + "-2")

dom1.configAddDisk("phy:/dev/ram0", "hda1", "w")
dom2.configAddDisk("phy:/dev/ram0", "hda1", "w")

try:
    dom1.start()
except DomainError, e:
    FAIL("Unable to start domain")

try:
    dom2.start()
    FAIL("Bug #331: Started a DomU with write access to an in-use block device")
except DomainError, e:
    pass
    
