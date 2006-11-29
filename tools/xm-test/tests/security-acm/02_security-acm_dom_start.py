#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>
#
# Simple test that starts two labeled domains; both domains should start
#
# The following xm subcommands are tested:
# - dumppolicy
# - labels

from XmTestLib import *
from acm_utils import *
import commands
import os

testlabel1 = "green"
testlabel2 = "red"

status, output = traceCommand("xm labels")

labels = ["SystemManagement", "blue", "red", "green"]
for l in labels:
    if not re.search(l, output):
        FAIL("Label '%s' not found in current policy!", l)

status, output = traceCommand("xm dumppolicy")
if status != 0:
    FAIL("'xm dumppolicy' returned an error code.")
lines = ["ssidref 0:  00 00 00 00",
         "ssidref 1:  01 00 00 00",
         "ssidref 2:  00 01 00 00",
         "ssidref 3:  00 00 01 00",
         "ssidref 4:  00 00 00 01"]
for l in lines:
    if not re.search(l, output):
        FAIL("Could not find '%s' in output of 'xm dumppolicy'" % l)

config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel1)}
verbose = True
domain1 = XmTestDomain(name="domain-%s" % testlabel1,
                       extraConfig=config)

try:
    domain1.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to start 1st labeled test domain.")

config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel2)}

domain2 = XmTestDomain(name="domain-%s" % testlabel2,
                       extraConfig=config)

try:
    domain2.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to start 2nd labeled test domain.")

domain2.destroy()
domain1.destroy()
