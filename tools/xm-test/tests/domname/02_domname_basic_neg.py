#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm domname 1492")
if status == 0:
    FAIL("domname(1492) returned invalid: %i != 0" % status)
elif not re.search("Error", output):
    FAIL("domname(1492) failed to report error for invalid domid")

