#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

# Test description: 
# Negative Test:
# Test for creating domain with no ramdisk and no root. Verify fail.

import sys
import re
import time

from XmTestLib import *

status, output = traceCommand("xm create /dev/null name=NOROOT memory=64 kernel=%s" % getDefaultKernel())

# sleep a while to wait for the kernel fails to mount root and NOROOT
# goes away from the xm list
time.sleep(15)

eyecatcher = "NOROOT"
status, output = traceCommand("xm list")
where = output.find(eyecatcher)
if where != -1:
	FAIL("xm create test05 passed with no root and no ramdisk. Expected result: Fail.")
