#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

#
# Test that the library and ramdisk are working to the point
# that we can start a DomU and read /proc
#

from XmTestLib import *

import re

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    FAIL(str(e))

try:
    run = console.runCmd("cat /proc/cpuinfo")
except ConsoleError, e:
    FAIL(str(e))

if run["return"] != 0:
    FAIL("Unable to read /proc/cpuinfo")

if not re.search("processor", run["output"]):
    print run["output"]
    FAIL("/proc/cpuinfo looks wrong!")
