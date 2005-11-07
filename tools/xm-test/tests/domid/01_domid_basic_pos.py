#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm domid Domain-0")
if status != 0:
    FAIL("domid(Domain-0) returned invalid %i != 0" % status)
elif output != "0":
    if verbose:
        print output
    FAIL("domid(Domain-0) failed to report domid 0")
