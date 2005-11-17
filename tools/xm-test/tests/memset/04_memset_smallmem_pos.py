#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

domain = XmTestDomain()

try:
    domain.start()
except DomainError, e:
    if verbose:
        print "Failed to start domain: "
        print e.extra
    FAIL(str(e))

try:
    console = XmConsole(domain.getName())
    console.sendInput("input")
    # Make sure it's alive before we proceed
    console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

status, output = traceCommand("xm mem-set %s %i" %
                              (domain.getName(), 15))

if status != 0:
    FAIL("xm mem-set %s %i returned invalid %i != 0" %
         (domain.getName(), domain.minSafeMem(), status))

console.setLimit(8192)

try:
    # See if this hits the byte limit
    console.runCmd("ls")
except ConsoleError, e:
    if e.reason == RUNAWAY:
        # Need to stop the domain before we restart the console daemon
        domain.destroy()
        if verbose:
            print "*** Attempting restart of xenconsoled"
            s, o = traceCommand("killall xenconsoled")
            s, o = traceCommand("xenconsoled")
            if s != 0:
                print "*** Starting xenconsoled failed: %i" % s
        FAIL("Bug #380: I crashed the console system")
    else:
        FAIL(str(e))

domain.destroy()
