#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *
from XmTestLib.block_utils import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-list not supported for HVM domains")

domain = XmTestDomain()

try:
    domain.start(noConsole=True)
except DomainError, e:
    FAIL(str(e))

s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list returned !0 when no devices attached")
if o:
    FAIL("block-list without devices reported something!")

block_attach(domain, "phy:/dev/ram0", "hda1")

s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list failed")
if o.find("769") == -1:
    FAIL("block-list didn't show the block device I just attached!")

block_attach(domain, "phy:/dev/ram1", "hda2")

s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list failed")
if o.find("770") == -1:
    FAIL("block-list didn't show the other block device I just attached!")

block_detach(domain, "hda1")

s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list failed after detaching a device")
if o.find("769") != -1:
    FAIL("hda1 still shown in block-list after detach!")
if o.find("770") == -1:
    FAIL("hda2 not shown after detach of hda1!")

block_detach(domain, "hda2")

s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list failed after detaching another device")
if o.find("770") != -1:
    FAIL("hda2 still shown in block-list after detach!")
if o:
    FAIL("block-list still shows something after all devices detached!")
    
domain.stop()
