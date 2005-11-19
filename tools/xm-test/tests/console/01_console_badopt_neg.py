#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>
 
# Test Description:
# Negative Tests:
# Test console command with non existent option in the command line.
# Verify fail.

import re
 
from XmTestLib import *

status, output = traceCommand("xm console -x")
eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm console returned invalid %i != 0" % status)
elif where == -1:
    FAIL("xm console didn't report error on bad argument")
