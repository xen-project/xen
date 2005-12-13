#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

config = {"disk":"phy:/dev/ram0,hda1,w"}

dom1 = XmTestDomain(extraConfig=config)
dom2 = XmTestDomain(dom1.getName() + "-2",
                    extraConfig=config)

try:
    dom1.start()
except DomainError, e:
    FAIL("Unable to start domain")

try:
    dom2.start()
    dom1.destroy()
    FAIL("Bug #331: Started a DomU with write access to an in-use block device")
except DomainError, e:
    dom1.destroy()
