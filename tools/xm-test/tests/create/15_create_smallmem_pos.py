#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

MEM = 16

domain = XmTestDomain(extraOpts={"memory":"%i" % MEM,
                                 "extra" :"mem=%iM" % MEM})

try:
    domain.start()
except DomainError, e:
    FAIL("Unable to start a domain with %i MB" % MEM)

try:
    console = XmConsole(domain.getName())
    console.setLimit(65536)
    console.sendInput("input")
    console.runCmd("ls")
except ConsoleError, e:
    if e.reason == RUNAWAY:
        FAIL("Bug #380: Starting a console with %i MB crashed the console daemon" % MEM)
    else:
        FAIL("Starting a console with %i MB failed: domain dies immediately!" % MEM)

domain.destroy()
