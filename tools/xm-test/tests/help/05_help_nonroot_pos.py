#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Copyright (C) XenSource Ltd, 2005
# Author: Dan Smith <danms@us.ibm.com>
# Author: Woody Marvel <marvel@us.ibm.com>
# Author: Ewan Mellor <ewan@xensource.com>

from XmTestLib import *

becomeNonRoot()

status, output = traceCommand("xm help")
eyecatcher = "Usage:"
where = output.find(eyecatcher)
if where == -1:
    FAIL("xm help: didn't see the usage string")
