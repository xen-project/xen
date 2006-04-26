#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

# 32MBs is the default lower limit for creating domains, it should work
MEM = 32

domain = XmTestDomain(extraConfig={"memory": MEM,
                                   "extra" :"mem=%iM" % MEM})

try:
    domain.start()
except DomainError, e:
    FAIL("Unable to start a domain with %i MB" % MEM)

try:
    console = XmConsole(domain.getName())
    console.sendInput("input")
    console.runCmd("ls")
except ConsoleError, e:
    if e.reason == RUNAWAY:
        FAIL("Bug #380: Starting a console with %i MB crashed the console daemon" % MEM)
    else:
        FAIL("Starting a console with %i MB failed: domain dies immediately!" % MEM)

domain.destroy()
