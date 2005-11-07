#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

domain = XmTestDomain()

try:
    domain.start()
except DomainError, e:
    if verbose:
        print "Failed to start domain: "
        print e.extra
    FAIL(str(e))

try:
    console = XmConsole(domain.getName())
    console.sendInput("input")
    # Make sure it's alive before we proceed
    console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

status, output = traceCommand("xm mem-set %s %i" %
                              (domain.getName(), 15))

if status != 0:
    FAIL("xm mem-set %s %i returned invalid %i != 0" %
         (domain.getName(), domain.minSafeMem(), status))

console.setLimit(8192)

try:
    # See if this hits the byte limit
    console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

domain.destroy()
