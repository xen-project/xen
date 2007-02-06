#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *
from XmTestLib.block_utils import *

import re, time

def checkXmLongList(domain):
    s, o = traceCommand("xm list --long %s" % domain.getName())
    if s != 0:
        FAIL("xm list --long <dom> failed")
    if re.search("xvda1", o):
        return True
    else:
        return False

if ENABLE_HVM_SUPPORT:
    SKIP("Block-detach not supported for HVM domains")

domain = XmTestDomain()

try:
    domain.start()
except DomainError,e:
    FAIL(str(e))

block_attach(domain, "phy:/dev/ram0", "xvda1")

if not checkXmLongList(domain):
    FAIL("xm long list does not show that xvda1 was attached")

block_detach(domain, "xvda1")

if checkXmLongList(domain):
    # device info is removed by hotplug scripts - give them a chance
    # to fire (they run asynchronously with us). 
    time.sleep(1)
    if checkXmLongList(domain):
        FAIL("xm long list does not show that xvda1 was removed")
