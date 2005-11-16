#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import time
import re

from XmTestLib import *

status, output = traceCommand("xm pause NOT-EXIST" )

eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm pause returned bad status, expected non 0, status is: %i" % status )
elif where == -1:
    FAIL("xm pause returned bad output, expected Error, output is: %s" % output )
