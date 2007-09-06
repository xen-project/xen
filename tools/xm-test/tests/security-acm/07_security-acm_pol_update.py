#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Test to exercise the xspolicy class

from XmTestLib import xapi
from XmTestLib.XenAPIDomain import XmTestAPIDomain
from XmTestLib import *
from xen.xend import XendAPIConstants
import xen.util.xsm.xsm as security
from xen.util import acmpolicy, xsconstants
from xen.util.acmpolicy import ACMPolicy
from xen.xend.XendDomain import DOM0_UUID
from XmTestLib.acm import *

import commands
import os
import base64

if not isACMEnabled():
    SKIP("Not running this test since ACM not enabled.")

try:
    session = xapi.connect()
except:
    SKIP("Skipping this test since xm is not using the Xen-API.")

xm_test = {}
xm_test['policyname'] = "xm-test"
xm_test['date'] = "Fri Sep 29 14:44:38 2006"
xm_test['url']  = None

vm_label_red   = "%s:xm-test:red" % xsconstants.ACM_POLICY_ID
vm_label_green = "%s:xm-test:green" % xsconstants.ACM_POLICY_ID
vm_label_blue  = "%s:xm-test:blue" % xsconstants.ACM_POLICY_ID
vm_label_sys   = "%s:xm-test:SystemManagement" % xsconstants.ACM_POLICY_ID

vm_label_black = "%s:xm-test:black"

session = xapi.connect()

oldlabel = session.xenapi.VM.get_security_label(DOM0_UUID)

ssidref = session.xenapi.VM.set_security_label(DOM0_UUID,
                                               vm_label_sys,
                                               oldlabel)
if int(ssidref) <= 0 or int(ssidref) != 0x00010001:
    FAIL("(0) Domain-0 label for '%s' has unexpected failure: %08x" %
         (vm_label_sys, int(ssidref)))
print "ssidref for '%s' is 0x%08x" % (vm_label_sys, int(ssidref))


xstype = session.xenapi.XSPolicy.get_xstype()
if int(xstype) & xsconstants.XS_POLICY_ACM == 0:
    SKIP("ACM not enabled/compiled in Xen")

policystate = session.xenapi.XSPolicy.get_xspolicy()
if not policystate.has_key('xs_ref'):
    FAIL("get_xspolicy must return member 'xs_ref'")

xs_ref = policystate['xs_ref']
if xs_ref != "":
    origpolicyxml = session.xenapi.ACMPolicy.get_xml(xs_ref)
else:
    origpolicyxml = ""

f = open("xm-test-security_policy.xml", 'r')
if f:
    newpolicyxml = f.read()
    f.close()
else:
    FAIL("Could not read 'xm-test' policy")

try:
    os.unlink("/boot/xm-test.bin")
except:
    pass

policystate = session.xenapi.XSPolicy.get_xspolicy()

if int(policystate['type']) == 0:
    policystate = session.xenapi.XSPolicy.set_xspolicy(
                          xsconstants.XS_POLICY_ACM,
                          newpolicyxml,
                          xsconstants.XS_INST_LOAD | xsconstants.XS_INST_BOOT,
                          1)
    if int(policystate['flags']) == -1:
        FAIL("Could not set the new policy.")

print "state of policy = %s " % policystate

rc = session.xenapi.XSPolicy.activate_xspolicy(
                          policystate['xs_ref'],
                          xsconstants.XS_INST_LOAD | xsconstants.XS_INST_BOOT)
if int(rc) != xsconstants.XS_INST_LOAD | xsconstants.XS_INST_BOOT:
    FAIL("Could not activate the current policy: rc = %08x" % int(rc))

if not os.path.exists("/boot/xm-test.bin"):
    FAIL("Binary policy was not installed. Check grub config file.")

policystate = session.xenapi.XSPolicy.get_xspolicy()

if int(policystate['flags']) != xsconstants.XS_INST_BOOT | \
                                xsconstants.XS_INST_LOAD:
    FAIL("Flags (%x) are not indicating the correct state of the policy.",
         int(policystate['flags']))

policystate = session.xenapi.XSPolicy.get_xspolicy()
xs_ref = policystate['xs_ref']

newpolicyxml = None
f = open("xm-test-new-security_policy.xml", 'r')
if f:
    newpolicyxml = f.read()
    f.close()
else:
    FAIL("Could not read 'xm-test-new' policy")

cur_acmpol = ACMPolicy(xml = policystate['repr'])
new_acmpol = ACMPolicy(xml = newpolicyxml)

new_acmpol.update_frompolicy(cur_acmpol)

policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                          new_acmpol.toxml(),
                          xsconstants.XS_INST_LOAD | xsconstants.XS_INST_BOOT,
                          1)

f = open("xm-test-security_policy.xml", 'r')
if f:
    newpolicyxml = f.read()
    f.close()
else:
    FAIL("Could not read 'xm-test-new' policy")

cur_acmpol = new_acmpol
new_acmpol = ACMPolicy(xml = newpolicyxml)

new_acmpol.update_frompolicy(cur_acmpol)

policystate = session.xenapi.XSPolicy.set_xspolicy(xsconstants.XS_POLICY_ACM,
                          new_acmpol.toxml(),
                          xsconstants.XS_INST_LOAD | xsconstants.XS_INST_BOOT,
                          1)

dom0_lab = session.xenapi.VM.get_security_label(DOM0_UUID)

ssidref = session.xenapi.VM.set_security_label(DOM0_UUID,
                                               vm_label_sys, dom0_lab)
if int(ssidref) <= 0 or int(ssidref) != 0x00010001:
    FAIL("(1) Domain-0 label for '%s' has unexpected failure: %08x" %
         (vm_label_sys, int(ssidref)))
print "ssidref for '%s' is 0x%08x" % (vm_label_sys, int(ssidref))

try:
    ssidref = session.xenapi.VM.set_security_label(DOM0_UUID,
                                                   vm_label_black,
                                                   vm_label_sys)
    FAIL("Could set label '%s', although it's not in the policy. "
         "ssidref=%s" % (vm_label_black, ssidref))
except:
    pass

ssidref = session.xenapi.VM.set_security_label(DOM0_UUID,
                                               vm_label_red,
                                               vm_label_sys)
if int(ssidref) <= 0:
    FAIL("(2) Domain-0 label for '%s' has unexpected failure: %08x" %
         (vm_label_red, int(ssidref)))
print "ssidref for '%s' is 0x%08x" % (vm_label_red, int(ssidref))

label = session.xenapi.VM.get_security_label(DOM0_UUID)

if label != vm_label_red:
    FAIL("Dom0 label '%s' not as expected '%s'" % (label, vm_label_red))


ssidref = session.xenapi.VM.set_security_label(DOM0_UUID,
                                               vm_label_sys,
                                               vm_label_red)
if int(ssidref) <= 0 or int(ssidref) != 0x00010001:
    FAIL("(3) Domain-0 label for '%s' has unexpected failure: %08x" %
         (vm_label_sys, int(ssidref)))

label = session.xenapi.VM.get_security_label(DOM0_UUID)

if label != vm_label_sys:
    FAIL("Dom0 label '%s' not as expected '%s'" % label, dom0_label)

header = session.xenapi.ACMPolicy.get_header(xs_ref)

if header['policyname'] != xm_test['policyname']:
    FAIL("Name in header is '%s', expected is '%s'." %
         (header['policyname'],xm_test['policyname']))
if header['date'] != xm_test['date']:
    FAIL("Date in header is '%s', expected is '%s'." %
         (header['date'],xm_test['date']))
if header.has_key("url") and header['url' ] != xm_test['url' ]:
    FAIL("URL  in header is '%s', expected is '%s'." %
         (header['url' ],xm_test['url' ]))

# Create another domain
try:
    # XmTestAPIDomain tries to establish a connection to XenD
    domain = XmTestAPIDomain(extraConfig={ 'security_label' : vm_label_blue })
except Exception, e:
    SKIP("Skipping test. Error: %s" % str(e))


vm_uuid = domain.get_uuid()

res = session.xenapi.VM.get_security_label(vm_uuid)
if res != vm_label_blue:
    FAIL("VM has security label '%s', expected is '%s'" %
         (res, vm_label_blue))

try:
    domain.start(noConsole=True)
except:
    FAIL("Could not create domain")


# Attempt to relabel the running domain
ssidref = session.xenapi.VM.set_security_label(vm_uuid,
                                               vm_label_red,
                                               vm_label_blue)
if int(ssidref) <= 0:
    FAIL("Could not relabel running domain to '%s'." % vm_label_red)

# user domain is 'red', dom0 is current 'SystemManagement'.
# Try to move domain-0 to 'red' first, then to 'blue'.

# Moving domain-0 to 'red' should work
ssidref = session.xenapi.VM.set_security_label(DOM0_UUID,
                                               vm_label_red,
                                               vm_label_sys)
if int(ssidref) <= 0:
    FAIL("Could not label domain-0 '%s'" % vm_label_red)

# Moving the guest domain to 'blue' should not work due to conflict set
try:
    ssidref = session.xenapi.VM.set_security_label(vm_uuid,
                                                   vm_label_blue,
                                                   vm_label_red)
    FAIL("Could label guest domain with '%s', although this is in a conflict "
         "set. ssidref=%x" % (vm_label_blue,int(ssidref)))
except:
    pass

label = session.xenapi.VM.get_security_label(vm_uuid)
if label != vm_label_red:
    FAIL("User domain has wrong label '%s', expected '%s'." %
         (label, vm_label_red))

label = session.xenapi.VM.get_security_label(DOM0_UUID)
if label != vm_label_red:
    FAIL("Domain-0 has wrong label '%s'; expected '%s'." %
         (label, vm_label_red))

ssidref = session.xenapi.VM.set_security_label(DOM0_UUID,
                                               vm_label_sys,
                                               vm_label_red)
if int(ssidref) < 0:
    FAIL("Could not set the domain-0 security label to '%s'." %
         (vm_label_sys))

# pause the domain and relabel it...
session.xenapi.VM.pause(vm_uuid)

label = session.xenapi.VM.get_security_label(vm_uuid)
if label != vm_label_red:
    FAIL("User domain has wrong label '%s', expected '%s'." %
         (label, vm_label_red))

ssidref = session.xenapi.VM.set_security_label(vm_uuid,
                                               vm_label_blue,
                                               vm_label_red)
print "guest domain new label '%s'; ssidref is 0x%08x" % \
      (vm_label_blue, int(ssidref))
if int(ssidref) <= 0:
    FAIL("Could not label guest domain with '%s'" % (vm_label_blue))

label = session.xenapi.VM.get_security_label(vm_uuid)
if label != vm_label_blue:
    FAIL("User domain has wrong label '%s', expected '%s'." %
         (label, vm_label_blue))

session.xenapi.VM.unpause(vm_uuid)

rc = session.xenapi.VM.suspend(vm_uuid)

ssidref = session.xenapi.VM.set_security_label(vm_uuid,
                                               vm_label_green,
                                               vm_label_blue)
print "guest domain new label '%s'; ssidref is 0x%08x" % \
      (vm_label_green, int(ssidref))
if int(ssidref) < 0:
    FAIL("Could not label suspended guest domain with '%s'" % (vm_label_blue))

label = session.xenapi.VM.get_security_label(vm_uuid)
if label != vm_label_green:
    FAIL("User domain has wrong label '%s', expected '%s'." %
         (label, vm_label_green))


rc = session.xenapi.VM.resume(vm_uuid, False)

label = session.xenapi.VM.get_security_label(vm_uuid)
if label != vm_label_green:
    FAIL("User domain has wrong label '%s', expected '%s'." %
         (label, vm_label_green))
