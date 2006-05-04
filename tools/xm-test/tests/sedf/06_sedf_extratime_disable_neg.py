#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>
# Author: Ryan Harper <ryanh@us.ibm.com>

from XmTestLib import *

def get_sedf_params(domain):
    status, output = traceCommand("xm sched-sedf %s" %(domain.getName()))
    return (status, output.split('\n')[1].split())


domain = XmTestDomain(extraConfig = {"sched":"sedf"})

try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# get current param values as baseline
(status, params) = get_sedf_params(domain)

# check rv
if status != 0:
    FAIL("Getting sedf parameters return non-zero rv (%d)", status)

# parse out current params
(name, domid, p, s, l, e, w) = params

# if extratime is off, turn it on and drop slice to 0
if str(e) == "0":
    extratime = 1
    opts = "%s -e %s" %(domain.getName(), extratime)
    (status, output) = traceCommand("xm sched-sedf %s" %(opts))

    # check rv
    if status != 0:
        FAIL("Failed to force extratime on (%d)" % status)

    # drop slice to 0 now that we are in extratime mode
    slice = 0

    opts = "%s -s %s" %(domain.getName(), slice)
    (status, output) = traceCommand("xm sched-sedf %s" %(opts))

    # check rv
    if status != 0:
        FAIL("Failed to force slice to 0 (%d)" % status)


# ASSERT(extratime=1, slice=0)

# attempt to disable extratime without setting slice
extratime = "0"

opts = "%s -e %s " %(domain.getName(), extratime)
(status, output) = traceCommand("xm sched-sedf %s" %(opts))

# we should see this output from xm 
eyecatcher = "Failed to set sedf parameters"

# check for failure
if output.find(eyecatcher) >= 0:
    FAIL("sched-sedf let me disable extratime without a non-zero slice")

# Stop the domain (nice shutdown)
domain.stop()
