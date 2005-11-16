#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm help")
eyecatcher = "Usage:"
where = output.find(eyecatcher)
if where == -1:
    FAIL("xm help: didn't see the usage string")
