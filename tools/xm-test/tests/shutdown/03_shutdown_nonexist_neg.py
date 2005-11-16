#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Paul Larson  <pl@us.ibm.com>

# Description:
# Positive Tests:
# Test for xm shutdown
# 1) call xm shutdown with a nonexistant domain, expect failure

import commands

from XmTestLib import *

eyecatcher = "Error:"

ret, output = traceCommand("xm shutdown 9999")
where = output.find(eyecatcher)
if (ret == 0):
    FAIL("xm shutdown returned invalid %i == 0" % ret)
elif where == -1:
    FAIL("xm shutdown failed to report error for bad domid")
