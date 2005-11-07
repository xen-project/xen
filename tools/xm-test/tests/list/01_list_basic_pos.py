#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm list")
if status != 0:
    FAIL("xm list returned invalid %i != 0" % status)
elif not re.search("Domain-0", output):
    FAIL("xm list output invalid; didn't see Domain-0")
