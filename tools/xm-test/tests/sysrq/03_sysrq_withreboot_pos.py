#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import time

domain = XmTestDomain()

try:
    domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create domain:"
    print e.extra
    FAIL(str(e))

status, output = traceCommand("xm reboot %s" % domain.getName())
if status != 0:
    FAIL("reboot %s failed with %i != 0" % (domain.getName(), status))

# Wait for the reboot to finish
time.sleep(20)

try:
    console = XmConsole(domain.getName())
    console.sendInput("input")
except ConsoleError, e:
    FAIL(str(e))

status, output = traceCommand("xm sysrq %s s" % domain.getName())
if status != 0:
    FAIL("sysrq failed with %i != 0" % status)

try:
    run = console.runCmd("dmesg | grep -i reboot")
except ConsoleError, e:
    FAIL(str(e))

if run == 0:
    FAIL("reboot/sysrq resulted in reboot!")
