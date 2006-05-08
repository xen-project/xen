#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import time
import re

from XmTestLib import *

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

domain.closeConsole()

status, output = traceCommand("xm reboot %s" % domain.getName())

if status != 0:
    FAIL("xm reboot returned %i != 0" % status)

time.sleep(15)

try:
    console = domain.getConsole()
except ConsoleError, e:
    FAIL(str(e))

try:
    console.sendInput("input")
    run = console.runCmd("uptime")
except ConsoleError, e:
    FAIL(str(e))

domain.closeConsole()

domain.destroy()

match = re.match("^[^up]*up ([0-9]+).*$", run["output"])
if match:
    if int(match.group(1)) > 1:
        FAIL("Uptime too large (%i > 1 minutes); domain didn't reboot")
else:
    FAIL("Invalid uptime string: %s (%s)" % (run["output"], match.group(1)))


