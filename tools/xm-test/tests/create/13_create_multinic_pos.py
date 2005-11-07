#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

for i in range(0,10):
    domain = XmTestDomain(extraOpts={"nics":"%i" % i})

    try:
        domain.start()
    except DomainError, e:
        FAIL("(%i nics) " % i + str(e))

    try:
        console = XmConsole(domain.getName())
        console.sendInput("input")
        console.runCmd("ls")
    except ConsoleError, e:
        FAIL("(%i nics) Console didn't respond: probably crashed!" % i)

    domain.destroy()
