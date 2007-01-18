#!/usr/bin/python
#
# Sched-credit tests modified from SEDF tests
#

import re

from XmTestLib import *

paramsRE = re.compile(r'^[^ ]* *[^ ]* *([^ ]*) *([^ ]*)$')

def get_sched_credit_params(domain):
    status, output = traceCommand("xm sched-credit -d %s | tail -1" %
                                  domain.getName())

    if status != 0:
        FAIL("Getting sched-credit parameters return non-zero rv (%d)",
             status)

    m = paramsRE.match(output)
    if not m:
        FAIL("xm sched-credit gave bad output")
    weight = int(m.group(1))
    cap = int(m.group(2))
    return (weight, cap)

def set_sched_credit_weight(domain, weight):
    status, output = traceCommand("xm sched-credit -d %s -w %d" %(domain.getName(), weight))
    return status

def set_sched_credit_cap(domain, cap):
    status, output = traceCommand("xm sched-credit -d %s -c %d" %(domain.getName(), cap))
    return status


domain = XmTestDomain()

try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# check default param values
(weight, cap) = get_sched_credit_params(domain)

if weight != 256:
    FAIL("default weight is 256 (got %d)", weight)
if cap != 0:
    FAIL("default cap is 0 (got %d)", cap)

# set new parameters
status = set_sched_credit_weight(domain, 512)
if status != 0:
    FAIL("Setting sched-credit weight return non-zero rv (%d)", status)

status = set_sched_credit_cap(domain, 100)
if status != 0:
    FAIL("Setting sched-credit cap return non-zero rv (%d)", status)

# check new param values
(weight, cap) = get_sched_credit_params(domain)

if weight != 512:
    FAIL("expected weight of 512 (got %d)", weight)
if cap != 100:
    FAIL("expected cap of 100 (got %d)", cap)

# Stop the domain (nice shutdown)
domain.stop()
