#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import re

status, output = traceCommand("xm list --long")

if status != 0:
    FAIL("xm list --long returned invalid %i != 0" % status)

if not re.search("\(domain", output):
    FAIL("long listing missing any (domain ...) root!")

if not re.search("\(domid 0\)", output):
    FAIL("long listing missing (domid 0)!")

if re.search("Traceback", output):
    FAIL("long listing generated a Traceback!")
