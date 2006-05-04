#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>
#	  Li Ge <lge@us.ibm.com>

# Positive Test:
# Test Description:
# 1. Create a domain
# 2. Destroy the domain by id
 
import sys
import re
import time

from XmTestLib import *

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

# Start it
try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# destroy domain - positive test
status, output = traceCommand("xm destroy %s" % domain.getId())
if status != 0:
    FAIL("xm destroy returned invalid %i != 0" % status)
