#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

# The device model, qemu-dm, only supports 8 MAX_NICS currently.
if ENABLE_HVM_SUPPORT:
    MAX_NICS = 8
else:
    MAX_NICS = 10

for i in range(0,MAX_NICS):
    domain = XmTestNetDomain()

    try:
        console = domain.start()
    except DomainError, e:
        FAIL("(%i nics) " % i + str(e))

    try:
        console.runCmd("ls")
    except ConsoleError, e:
        FAIL("(%i nics) Console didn't respond: probably crashed!" % i)

    domain.destroy()
