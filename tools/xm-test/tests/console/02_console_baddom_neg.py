#!/usr/bin/python
# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

# Test Description:
# Negative Tests:
# Test for attempting to connect to non existent domname, domid. Verify fail.

import re

from XmTestLib import *

status, output = traceCommand("xm console 5000")
eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm console returned invalid %i != 0" % status)
elif where == -1:
    FAIL("xm console failed to report error on bad domid")

status, output = traceCommand("xm console NON_EXIST")
eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm console returned invalid %i != 0" % status)
elif where == -1:
    FAIL("xm console failed to report error on bad domname") 
