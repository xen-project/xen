#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

sedf_opts = "20000000 5000000 0 0 0"

domain = XmTestDomain(extraOpts = {"sched":"sedf"})

try:
    domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

for i in range(5):
    status, output = traceCommand("xm sched-sedf %s %s" % (domain.getName(),
                                                           sedf_opts))
    if status != 0:
        FAIL("[%i] xm sedf returned invalid %i != 0" % (i, status))

    
    

