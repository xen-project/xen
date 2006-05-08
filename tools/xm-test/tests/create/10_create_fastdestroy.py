#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import re

#
# Check to see if the output resembles the
# "No such process error"
#
def check_for_NSP_error(output):
    if re.search("XendError.*No such process", output):
        return "Bugzilla bug #234"
    else:
        return None

def check_for_DUP_error(output):
    if re.search("Error.*already exists\!", output):
        return "Xend reported duplicate domain (stale state?)"
    else:
        return None

i = 0

for i in range(0,50):
    domain = XmTestDomain("testdomain")
    try:
        domain.start(noConsole=True)
    except DomainError,e:
        print "Failed: " + e.extra
        NSPerror = check_for_NSP_error(e.extra)
        DUPerror = check_for_DUP_error(e.extra)
        if NSPerror:
            FAIL(NSPerror)
        elif DUPerror:
            FAIL(DUPerror)
        else:
            FAIL("xm create returned invalid status: %i" % e.errorcode)
    domain.destroy()

