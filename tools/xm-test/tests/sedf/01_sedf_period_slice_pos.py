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

# NB: setting period requires non-zero slice 
# scale current period in half
period = str(float(p) / 2)
slice  = str(float(p) / 4)

opts = "%s -p %s -s %s" %(domain.getName(), period, slice)
(status, output) = traceCommand("xm sched-sedf %s" %(opts))

# check rv
if status != 0:
    FAIL("Setting sedf parameters return non-zero rv (%d)" % status)

# validate 
(s,params) = get_sedf_params(domain)

# check rv
if s != 0:
    FAIL("Getting sedf parameters return non-zero rv (%d)" % s)

(name,domid,p1,s1,l1,e1,w1) = params

if p1 != period:
    FAIL("Failed to change domain period from %f to %f" %(p, period))

if s1 != slice:
    FAIL("Failed to change domain slice from %f to %f" %(s, slice))

# Stop the domain (nice shutdown)
domain.stop()
