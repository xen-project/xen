#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import re

from XmTestLib import *

status, output = traceCommand("xm domname 0")
if status != 0:
    FAIL("domname(0) returned invalid %i != 0" % status)
elif output != "Domain-0":
    if verbose:
        print output
    FAIL("domname(0) failed to return Domain-0 for domid 0")
    
