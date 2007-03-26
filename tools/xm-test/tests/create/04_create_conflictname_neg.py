#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

# Test Description:
# Negative Test:
# Test for creating domains with same name. Verify fail.

import sys
import re

from XmTestLib import *

# Create a domain with name "default" (default XmTestDomain, with our ramdisk)
domain1 = XmTestDomain("default")

#start it
try:
    domain1.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain1 because:"
        print e.extra
    FAIL(str(e))

# Create second domain with same name "default"
domain2 = XmTestDomain("default")

#start it
eyecatcher = "Pass"
try:
    domain2.start(noConsole=True)
except DomainError, e:
    eyecatcher = "Fail"
    # Stop the domain1 (nice shutdown)
    domain1.stop()

if eyecatcher != "Fail":
    domain2.stop()
    FAIL("xm create let me create a duplicate-named domain!") 
