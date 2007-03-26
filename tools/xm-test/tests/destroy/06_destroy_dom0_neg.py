#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm destroy 0")
if status == 0:
    FAIL("xm destroy returned bad status, expected non 0, status is: %i" % status)
elif not re.search("Error", output, re.I):
    FAIL("xm destroy returned bad output, expected Error:, output is: %s" % output)
