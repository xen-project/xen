#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm list 6666")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm list returned invalid %i != 0" % status)
elif where == -1:
    FAIL("xm list failed to report error for invalid domid")

