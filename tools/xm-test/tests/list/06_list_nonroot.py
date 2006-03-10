#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Copyright (C) XenSource Ltd, 2005
# Author: Ewan Mellor <ewan@xensource.com>

from XmTestLib import *

becomeNonRoot()

status, output = traceCommand("xm list")
eyecatcher = "Error: Most commands need root access"
where = output.find(eyecatcher)
if where == -1:
    FAIL("xm list: didn't see the root hint, saw %s" % output)
