#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

# Create a domain with the minimum memory allocation
MEM = minSafeMem()

domain = XmTestDomain(extraConfig={"memory": MEM,
                                   "extra" :"mem=%iM" % MEM})

try:
    console = domain.start()
except DomainError, e:
    FAIL("Unable to start a domain with %i MB" % MEM)

try:
    console.runCmd("ls")
except ConsoleError, e:
    if e.reason == RUNAWAY:
        FAIL("Bug #380: Starting a console with %i MB crashed the console daemon" % MEM)
    else:
        FAIL("Starting a console with %i MB failed: domain dies immediately!" % MEM)

domain.destroy()
