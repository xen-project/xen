#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

# Test Description:
# Positive Test
# Test for creating domain with mem=256.

import sys
import re
import time

from XmTestLib import *

rdpath = os.environ.get("RD_PATH")
if not rdpath:
    rdpath = "../ramdisk"

#get current free memory info
mem = int(getInfo("free_memory"))
if mem < 256:
    SKIP("This test needs 256 MB of free memory (%i MB avail)" % mem)

#create a domain with mem=256
config = {"memory": 256}
domain_mem256=XmTestDomain(extraConfig=config)

#start it
try:
    domain_mem256.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain_mem256 because:"
        print e.extra
    FAIL(str(e))

#verify it is running with 256MB mem

eyecatcher1 = str(isDomainRunning(domain_mem256.getName()))
if eyecatcher1 != "True":
    FAIL("Failed to verify that a 256MB domain started")

eyecatcher2 = getDomMem(domain_mem256.getName())
if eyecatcher2 not in range(254, 257):
    FAIL("Started domain with 256MB, but it got %i MB" % eyecatcher2)

#stop the domain (nice shutdown)
domain_mem256.stop()
