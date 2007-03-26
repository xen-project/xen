#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

from XmTestLib import *

status, output = traceCommand("xm network-attach NOT-EXIST")

eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm network-attach returned bad status, expected non 0, status is: %i" % status )
elif where == -1:
    FAIL("xm network-attach returned bad output, expected Error, output is: %s" % output )
