#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import time
import re

from XmTestLib import *

domain = XmTestDomain()

try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

status, output = traceCommand("xm pause -x %s" % domain.getName())

eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    domain.destroy()
    FAIL("xm pause returned bad status, expected non 0, status is: %i" % status )
elif where == -1:
    domain.destroy()
    FAIL("xm pause returned bad output, expected Error, output is: %s" % output )

domain.destroy()
