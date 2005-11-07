#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm dmesg")
if status != 0:
    FAIL("xm dmesg returned invalid %i != 0" % status)
elif not re.search("\(XEN\)", output):
    FAIL("xm dmesg didn't output and (XEN) lines")

