#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com> 

# Test description:
# Negative Test:
# Test for creating domain with non existent option in the command line.
# Verify fail.

import re

from XmTestLib import *

status, output = traceCommand("xm create -x")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if where == -1:
    FAIL("xm create failed to report error on bad arg")
