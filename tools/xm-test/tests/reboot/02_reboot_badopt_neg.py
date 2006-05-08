#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

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

status, output = traceCommand("xm reboot -x %s" % domain.getName())

eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    domain.destroy()
    FAIL("xm reboot returned invalid %i == 0" % status )
elif where == -1:
    domain.destroy()
    FAIL("xm reboot failed to report error for bad arg")

domain.destroy()
