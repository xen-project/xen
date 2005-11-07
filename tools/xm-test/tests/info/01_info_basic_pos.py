#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

status, output = traceCommand("xm info")

if status != 0:
    FAIL("xm info returned %i != 0" % status)
