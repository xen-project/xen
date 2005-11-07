#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm help --long")
#print output

eyecatcher = "xm full list of subcommands:"
where = output.find(eyecatcher)
if where == -1:
    FAIL("xm help --long failed to show long listing")
