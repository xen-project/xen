#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

#Negative Test: attempt removal of non-attached device from live domain

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Block-detach not supported for HVM domains")

domain = XmTestDomain()
                                                                                                       
try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain")

status, output = traceCommand("xm block-detach %s xvda1" % domain.getId())

eyecatcher1 = "Error:"
eyecatcher2 = "Traceback"
where1 = output.find(eyecatcher1)
where2 = output.find(eyecatcher2)
if status == 0:
    FAIL("xm block-detach returned bad status, expected non 0, status is: %i" % status)
elif where2 == 0:
    FAIL("xm block-detach returned a stack dump, expected nice error message")
elif where1 < 0:
    FAIL("xm block-detach returned bad output, expected Error:, output is: %s" % output)
