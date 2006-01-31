#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com> 

# Test description:
# Negative Test:
# Test for saving domain with non existent option in the command line.
# Verify fail.

import re

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Save currently not supported for HVM domains")

status, output = traceCommand("xm save -x")
eyecatcher1 = "Error:"
eyecatcher2 = "Traceback"
where1 = output.find(eyecatcher1)
where2 = output.find(eyecatcher2)
if status == 0:
    FAIL("xm save returned bad status, expected non 0, status is: %i" % status)
elif where2 == 0:
    FAIL("xm save returned a stack dump, expected nice error message") 
elif where1 == -1:
    FAIL("xm save returned bad output, expected Error:, output is: %s" % output)
