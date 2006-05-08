#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import sys
import re
import time

from XmTestLib import *

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

status, output = traceCommand("xm list %s" % domain.getName())

if status != 0:
    FAIL("`xm list %s' failed with invalid status %i != 0" % (domain.getName(), status))

domain.closeConsole()
domain.stop()
