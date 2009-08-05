#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Mem-set not supported for HVM domains")

domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to start domain: "
        print e.extra
    FAIL(str(e))

try:
    # Make sure it's alive before we proceed
    console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

status, output = traceCommand("xm mem-set %s %i" %
                              (domain.getName(), 18))

if status != 0:
    FAIL("xm mem-set %s %i returned invalid %i != 0" %
         (domain.getName(), domain.minSafeMem(), status))

console.setLimit(65536)

try:
    # See if this hits the byte limit
    console.runCmd("ls")
except ConsoleError, e:
    if e.reason == RUNAWAY:
        # Need to stop the domain before we restart the console daemon
        domain.destroy()
        if isConsoleDead():
            print "*** Attempting restart of xenconsoled"
            s, o = traceCommand("killall xenconsoled")
            s, o = traceCommand("xenconsoled")
            if s != 0:
                print "*** Starting xenconsoled failed: %i" % s
            FAIL("Bug #380: I crashed the console system")
        else:
            FAIL("Bug #145: Ballooning DomU too low caused run-away")
    else:
        FAIL(str(e))

domain.destroy()
