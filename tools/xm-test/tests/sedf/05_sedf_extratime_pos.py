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

# toggle extratime value
extratime = str((int(e)+1)%2)

direction = "disable"
# NB: when disabling extratime(=0), must pass in a slice
opts = "%s -e %s" %(domain.getName(), extratime)
if extratime == "0":
    opts += " -s %s" %( str( (float(p)/2)+1 ) )
    direction = "enable"
    
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

if e1 != extratime:
    FAIL("Failed to %s extratime" %(direction))

# Stop the domain (nice shutdown)
domain.stop()
