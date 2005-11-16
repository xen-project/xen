#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm create")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm create returned invalid %i != 0" % status)
elif where == -1:
    FAIL("xm create failed to report error on missing args")

