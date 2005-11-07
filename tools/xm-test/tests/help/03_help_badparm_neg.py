#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm -x")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if where != 0:
    FAIL("xm failed to report error for bad arg")
