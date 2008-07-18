#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>
#

import os
import re
import commands
from XmTestLib import *
import xen.util.xsm.xsm as security
from xen.util import xsconstants

def checkLabel(labeldata, expected, domname):
    if labeldata[0] != expected[0]:
        FAIL("Policy type of %s is bad: %s" % (domname, labeldata[0]))
    if labeldata[1] != expected[1]:
        FAIL("Unexpected policy indicated in %s label '%s', expected '%s'." %
             (domname, labeldata[1], expected[1]))
    if labeldata[2] != expected[2]:
        FAIL("%s does not have '%s' label but '%s'." %
             (domname, expected[2], labeldata[2]))

if not isACMEnabled():
    SKIP("Not running this test since ACM not enabled.")

testpolicy = "xm-test"
testlabel1 = "blue"
testlabel2 = "red"
testlabel3 = "green"

# reset the policy - must work
s, o = traceCommand('xm resetpolicy')
if s:
    FAIL("Could not reset the policy.")


s, o = traceCommand('xm resources | grep -E "^[phy|file|vlan]" ')
resnames = []
if o:
    resnames = o.split('\n')

    for res in resnames:
        s, o = traceCommand('xm rmlabel res %s' % res)

#Unlabeled domain must not start under xm-test policy
domain_ul = XmTestDomain(name='domain-unlabeled',
                         extraConfig=None)
del domain_ul.config.opts['access_control']
try:
    domain_ul.start(noConsole=True)
    FAIL("Could start unlabeled domain.")
except DomainError, e:
    domain_ul.destroy()   # delete if xend-managed domain


config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel1)}

domain_blue = XmTestDomain(name='domain-%s' % testlabel1,
                           extraConfig=config)

config = {"access_control":"policy=%s,label=%s" % (testpolicy,testlabel3)}

domain_green = XmTestDomain(name='domain-%s' % testlabel3,
                            extraConfig=config)


try:
    domain_blue.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to start blue labeled test domain")

s, o = traceCommand('xm list Domain-0 --label | grep -E "Domain-0"')
if s:
    FAIL("Could not get the label of Domain-0")

info = o.strip().split(' ')
labeldata = info[-1].split(':')
if len(labeldata) != 3:
    FAIL("Label of Domain-0 is bad: '%s'" % info[-1])
checkLabel(labeldata,
           [xsconstants.ACM_POLICY_ID, "xm-test", "SystemManagement"],
           "Domain-0")

# Should be able to set the Domain-0 label to blue
s, o = traceCommand('xm addlabel blue mgt Domain-0')
if s:
    FAIL("Could not set the label of Domain-0 to 'blue'.")
s,o = traceCommand('xm list Domain-0 --label | grep -E "Domain-0"')
if s:
    FAIL("Could not get the label of Domain-0")

info = o.strip().split()
labeldata = info[-1].split(':')
if len(labeldata) != 3:
     FAIL("Label of Domain-0 is bad: '%s'" % info[-1])
checkLabel(labeldata,
           [xsconstants.ACM_POLICY_ID, "xm-test", "blue"],
           "Domain-0")

#Should not be able to set the label of Domain-0 to 'red'
s, o = traceCommand('xm addlabel red mgt Domain-0')
if not s:
    FAIL("Could set the label of Domain-0 to 'red'.")
s,o = traceCommand('xm list Domain-0 --label | grep -E "Domain-0"')
if s:
    FAIL("Could not get the label of Domain-0")

info = o.strip().split()
labeldata = info[-1].split(':')
if len(labeldata) != 3:
     FAIL("Label of Domain-0 is bad: '%s'" % info[-1])
checkLabel(labeldata,
           [xsconstants.ACM_POLICY_ID, "xm-test", "blue"],
           "Domain-0")

# Should be able to set the label of Domain-0 to 'SystemManagement'
s, o = traceCommand('xm addlabel SystemManagement mgt Domain-0')
if s:
    FAIL("Could not set the label of Domain-0 to 'SystemManagement'.")
s,o = traceCommand('xm list Domain-0 --label | grep -E "Domain-0"')
if s:
    FAIL("Could not get the label of Domain-0")

info = o.strip().split()
labeldata = info[-1].split(':')
if len(labeldata) != 3:
     FAIL("Label of Domain-0 is bad: '%s'" % info[-1])
checkLabel(labeldata,
           [xsconstants.ACM_POLICY_ID, "xm-test", "SystemManagement"],
           "Domain-0")

#Label some resource green
#Label some resource red
#Label some resource blue

s, o = traceCommand('xm addlabel green res file:/tmp/green')
if s:
    FAIL("Could not label resource 'green'.")
s, o = traceCommand('xm addlabel red res file:/tmp/red')
if s:
    FAIL("Could not label resource 'red'.")
s, o = traceCommand('xm addlabel blue res file:/tmp/blue')
if s:
    FAIL("Could not label resrouce 'blue'")

# Start a green domain
try:
    domain_green.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to start green labeled test domain")

# Update the system's policy. Should not work, since blue Domain is running
s, o = traceCommand('xm setpolicy ACM xm-test-update')
if not s:
    FAIL("Could set the new policy even though blue domain is running.")

s, o = traceCommand('xm getpolicy | grep "Policy name"')
info = o.split(':')
poldata = [i.strip() for i in info]

if poldata[1] != 'xm-test':
   FAIL("Policy should be 'xm-test' but is now '%s'." % poldata[1])

# Check that no labels have changed
s, o = traceCommand('xm getlabel res file:/tmp/green')
if s:
    FAIL("Could not get label for green resource.")
label=o.strip()
if label != 'ACM:xm-test:green':
    FAIL("Label for green resource has changed to '%s', but should not have,"
         % label)

s, o = traceCommand('xm getlabel res file:/tmp/red')
if s:
    FAIL("Could not get label for red resource.")
label=o.strip()
if label != 'ACM:xm-test:red':
    FAIL("Label for red resource has changed to '%s', but should not have,"
         % label)

s, o = traceCommand('xm getlabel res file:/tmp/blue')
if s:
    FAIL("Could not get label for blue resource.")
label=o.strip()
if label != 'ACM:xm-test:blue':
    FAIL("Label for blue resource has changed to '%s', but should not have,"
         % label)

# Terminate blue domain
domain_blue.destroy()

# Update the system's policy. Should work and rename the green domain to GREEN
s, o = traceCommand('xm setpolicy ACM xm-test-update')
if s:
    FAIL("Could not set the new policy.")

acm.setCurrentPolicy('xm-test-update')

s, o = traceCommand('xm getpolicy | grep "Policy name"')
info = o.split(':')
poldata = [i.strip() for i in info]

if poldata[1] != 'xm-test-update':
   FAIL("Policy should be 'xm-test-update' but is now '%s'." % poldata[1])

# check previously labeled resources
#  - green should be GREEN now
#  - blue should have been invalidated
#  - red should be the same
s, o = traceCommand('xm getlabel res file:/tmp/green')
if s:
    FAIL("Could not get label for GREEN resource.")
label=o.strip()
if label != 'ACM:xm-test-update:GREEN':
    FAIL("Label for green resource has changed to '%s', but should not have,"
         % label)

s, o = traceCommand('xm getlabel res file:/tmp/red')
if s:
    FAIL("Could not get label for RED resource.")
label=o.strip()
if label != 'ACM:xm-test-update:RED':
    FAIL("Label for RED resource has changed to '%s', expected is '%s',"
         % (label,'ACM:xm-test-update:RED'))

s, o = traceCommand('xm getlabel res file:/tmp/blue')
if s:
    FAIL("Could not get label for blue resource.")
label=o.strip()
if label != 'INV_ACM:xm-test:blue':
    FAIL("Label for blue resource has changed to '%s', expected is '%s',"
         % (label,'INV_ACM:xm-test:blue'))

config = {"access_control":"policy=%s,label=%s" % ('xm-test-update',testlabel2)}

domain_red = XmTestDomain(name='domain-%s' % testlabel2,
                          extraConfig=config)

# Start the red domain - should not work due to conflict set
try:
    domain_red.start(noConsole=True)
    FAIL("Could start 'red' domain.")
except DomainError, e:
    domain_red.destroy()  # delete if xend-managed domain

# Terminate GREEN domain
domain_green.destroy()

# Start the red domain - should work now
try:
    domain_red.start()
except DomainError, e:
    FAIL("Could not start 'red' domain.")

# Stop the red domain.
domain_red.destroy()

# Make Domain-0 GREEN
s, o = traceCommand('xm addlabel GREEN mgt Domain-0')
if s:
    FAIL("Could not set Domain-0's label to 'GREEN'.")
s,o = traceCommand('xm list Domain-0 --label | grep -E "Domain-0"')
if s:
    FAIL("Could not get the label of Domain-0")

info = o.strip().split()
labeldata = info[-1].split(':')
if len(labeldata) != 3:
    FAIL("Label of Domain-0 is bad: '%s'" % info[-1])
checkLabel(labeldata,
           [xsconstants.ACM_POLICY_ID, "xm-test-update", "GREEN"],
           "Domain-0")

# Start the red domain - should not work due to conflict set
try:
    domain_red.start()
    FAIL("Could start 'red' domain.")
except DomainError, e:
    pass

# Set Domain-0's domain to SystemManagement
s, o = traceCommand('xm addlabel SystemManagement mgt Domain-0')
if s:
    FAIL("Could not set Domain-0's label to SystemManagement.")

# Start unlabeled domain - should work
try:
    domain_ul.start(noConsole=True)
except DomainError, e:
    FAIL("Could not start unlabeled domain.")

# Stop red domain
domain_red.destroy()

# Stop unlabeled domain
domain_ul.destroy()


# Mark Domain-0 as red. This must not have any effect on the later reset
s, o = traceCommand('xm addlabel red mgt Domain-0')
if s:
    FAIL("Could not set Domain-0's label to 'red'.")
s,o = traceCommand('xm list Domain-0 --label | grep -E "Domain-0"')
if s:
    FAIL("Could not get the label of Domain-0")

info = o.strip().split()
labeldata = info[-1].split(':')
if len(labeldata) != 3:
    FAIL("Label of Domain-0 is bad: '%s'" % info[-1])
checkLabel(labeldata,
           [xsconstants.ACM_POLICY_ID, "xm-test-update", "red"],
           "Domain-0")

# reset the policy - should work
s, o = traceCommand('xm resetpolicy')
if s:
    FAIL("Could not reset the policy.")

# check previously labeled resources
#  - GREEN should be invalid
#  - red should be invalid
#  - blue should be invalid
s, o = traceCommand('xm getlabel res file:/tmp/green')
if s:
    FAIL("Could not get label for GREEN resource.")
label=o.strip()
exp='INV_ACM:xm-test-update:GREEN'
if label != exp:
    FAIL("Label for green resource has changed to '%s', but should be '%s',"
         % (label, exp))

s, o = traceCommand('xm getlabel res file:/tmp/red')
if s:
    FAIL("Could not get label for RED resource.")
label=o.strip()
exp='INV_ACM:xm-test-update:RED'
if label != exp:
    FAIL("Label for RED resource has changed to '%s', but should be '%s'.,"
         % (label, exp))

s, o = traceCommand('xm getlabel res file:/tmp/blue')
if s:
    FAIL("Could not get label for blue resource.")
label=o.strip()
exp='INV_ACM:xm-test:blue'
if label != exp:
    FAIL("Label for blue resource has changed to '%s', but should be '%s',"
         % (label, exp))
