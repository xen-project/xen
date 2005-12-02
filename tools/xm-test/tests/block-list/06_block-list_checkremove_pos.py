#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

domain = XmTestDomain()

try:
    domain.start()
except DomainError, e:
    FAIL(str(e))

try:
    console = XmConsole(domain.getName())
except ConsoleError, e:
    FAIL(str(e))

s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list returned !0 when no devices attached")
if o:
    FAIL("block-list without devices reported something!")

s, o = traceCommand("xm block-attach %s phy:/dev/ram0 hda1 w" % domain.getName())
if s != 0:
    FAIL("Unable to attach /dev/ram0->hda1")

s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list failed")
if o.find("769") == -1:
    FAIL("block-list didn't show the block device I just attached!")

s, o = traceCommand("xm block-attach %s phy:/dev/ram1 hda2 w" % domain.getName())
if s != 0:
    FAIL("Unable to attach /dev/ram1->hda2")

s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list failed")
if o.find("770") == -1:
    FAIL("block-list didn't show the other block device I just attached!")

s, o = traceCommand("xm block-detach %s 769" % domain.getName())
if s != 0:
    FAIL("block-detach of hda1 failed")

time.sleep(1)
s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list failed after detaching a device")
if o.find("769") != -1:
    FAIL("hda1 still shown in block-list after detach!")
if o.find("770") == -1:
    FAIL("hda2 not shown after detach of hda1!")

s, o = traceCommand("xm block-detach %s 770" % domain.getName())
if s != 0:
    FAIL("block-detach of hda2 failed")

time.sleep(1)
s, o = traceCommand("xm block-list %s" % domain.getName())
if s != 0:
    FAIL("block-list failed after detaching another device")
if o.find("770") != -1:
    FAIL("hda2 still shown in block-list after detach!")
if o:
    FAIL("block-list still shows something after all devices detached!")
    

