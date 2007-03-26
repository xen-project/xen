#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

# Test Description:
# Positive Test
# Test for creating domain with mem=.

import sys
import re
import time

from XmTestLib import *

rdpath = os.environ.get("RD_PATH")
if not rdpath:
    rdpath = "../ramdisk"

#get current free memory info
mem = int(getInfo("free_memory"))
if mem < 128:
    SKIP("This test needs 128 MB of free memory (%i MB avail)" % mem)

#create a domain with mem=128
config={"memory": 128}
domain_mem128=XmTestDomain(extraConfig=config)

#start it
try:
    domain_mem128.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain_mem128 because:"
        print e.extra
    FAIL(str(e))

#verify it is running with 128MB mem

eyecatcher1 = str(isDomainRunning(domain_mem128.getName()))
if eyecatcher1 != "True":
    FAIL("Failed to verify that a 128MB domain started")

eyecatcher2 = getDomMem(domain_mem128.getName())
if eyecatcher2 not in range(126, 129):
    FAIL("Started domain with 128MB, but it got %i MB" % eyecatcher2)

#stop the domain (nice shutdown)
domain_mem128.stop()
