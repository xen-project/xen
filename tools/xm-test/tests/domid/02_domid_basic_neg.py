#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm domid non_existent_domain")
if status == 0:
    FAIL("domid(non_existent_domain) returned invalid %i != 0" % status)
elif not re.search("Error", output):
    FAIL("domid(non_existent_domain) failed to report error")

