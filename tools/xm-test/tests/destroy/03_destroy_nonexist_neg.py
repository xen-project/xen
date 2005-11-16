#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm destroy -x")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm destroy returned invalid %i != 0" % status)
elif where == -1:
    FAIL("xm destroy failed to report error for bad arg")
