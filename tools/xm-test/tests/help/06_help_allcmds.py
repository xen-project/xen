#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import re

MAX_ARGS = 10

# These commands aren't suitable for this test, so we
# ignore them
skipcommands = ["top", "log"]

status, output = traceCommand("xm help --long")

commands = []
badcommands = []

lines = output.split("\n")
for l in lines:
    match = re.match("^    ([a-z][^ ]+).*$", l)
    if match:
        commands.append(match.group(1))

for c in commands:
    if c in skipcommands:
        continue

    arglist = ""
    for i in range(0,MAX_ARGS+1):
        if i > 0:
            arglist += "%i " % i

        status, output = traceCommand("xm %s %s" % (c, arglist))

        if output.find("Traceback") != -1:
            badcommands.append(c + " " + arglist)
            if verbose:
                print "Got Traceback: %s %s" % (c, arglist)

if badcommands:
    FAIL("Got a traceback on: %s" % str(badcommands))
