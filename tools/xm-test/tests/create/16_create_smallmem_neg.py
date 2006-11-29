#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import re
from XmTestLib import *

# This is under the default lower limit of 32 and we expect this test
# to fail. 16MBs isn't enough for the -xen kernel.
MEM = 16

domain = XmTestDomain(extraConfig={"memory": MEM,
                                   "extra" :"mem=%iM" % MEM})

try:
    console = domain.start()
    console.runCmd("ls")
except DomainError, e:
    if not re.search('^Error: Domain memory must be at least \d+ KB', e.extra):
        # PPC gracefully fails like this, rather than crashing.
        FAIL("Unable to start a domain with %i MB" % MEM)
except ConsoleError, e:
    if e.reason == RUNAWAY:
        print "Domain with %i MB has runaway console as expected" % MEM
else:
    FAIL("Starting a console with %i MB passed, expected test to fail" % MEM)

print "Starting a domain with %i MB failed as expected" % MEM
domain.destroy()
