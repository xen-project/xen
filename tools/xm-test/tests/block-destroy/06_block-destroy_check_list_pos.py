#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import time
import re

def checkBlockList(domain):
    s, o = traceCommand("xm block-list %s" % domain.getName())
    if s != 0:
        FAIL("block-list failed")
    if re.search("769", o):
        return True
    else:
        return False

def checkXmLongList(domain):
    s, o = traceCommand("xm list --long %s" % domain.getName())
    if s != 0:
        FAIL("xm list --long <dom> failed")
    if re.search("hda1", o):
        return True
    else:
        return False

if ENABLE_VMX_SUPPORT:
    SKIP("Block-detach not supported for VMX domains")

domain = XmTestDomain()

try:
    domain.start()
except DomainError,e:
    FAIL(str(e))

s, o = traceCommand("xm block-attach %s phy:/dev/ram0 hda1 w" % domain.getName())
if s != 0:
    FAIL("block-attach failed")

if not checkBlockList(domain):
    FAIL("block-list does not show that hda1 was attached")

if not checkXmLongList(domain):
    FAIL("xm long list does not show that hda1 was attached")

time.sleep(2)

s, o = traceCommand("xm block-detach %s hda1" % domain.getName())
if s != 0:
    FAIL("block-detach failed")

time.sleep(2)

if checkBlockList(domain):
    FAIL("block-list does not show that hda1 was removed")

if checkXmLongList(domain):
    FAIL("xm long list does not show that hda1 was removed")


