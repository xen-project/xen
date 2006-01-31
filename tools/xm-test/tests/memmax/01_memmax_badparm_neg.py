#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>
## Description:	Test xm memmax bad parameter

import re

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Mem-max not supported for HVM domains")

status, output = traceCommand("xm mem-max")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm memmax returned invalid %i == 0" % status)
elif where < 0:
    FAIL("xm memmax failed to report error for missing arg")


status, output = traceCommand("xm mem-max 6666")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm memmax returned invalid %i == 0" % status)
elif where < 0:
    FAIL("xm memmax failed to report error for bad arg")
