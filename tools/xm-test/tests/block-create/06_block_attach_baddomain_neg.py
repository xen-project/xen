#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-attach not supported for HVM domains")

status, output = traceCommand("xm block-attach NOT-EXIST phy:ram1 xvda1 w")

eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm block-attach returned bad status, expected non 0, status is: %i" % status )
elif where == -1:
    FAIL("xm block-attach returned bad output, expected Error, output is: %s" % output )
