#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2007
# Author: Stefan Berger <stefanb@us.ibm.com>

# VM creation test with labeled VM and labeled VDI

from XmTestLib import xapi
from XmTestLib.XenAPIDomain import XmTestAPIDomain
from XmTestLib import *
from xen.xend import XendAPIConstants
import xen.util.xsm.xsm as security
from xen.util import acmpolicy, xsconstants
import commands
import os

vm_label_red    = xsconstants.ACM_POLICY_ID + ":xm-test:red"
vm_label_green  = xsconstants.ACM_POLICY_ID + ":xm-test:green"
vdi_label_red   = xsconstants.ACM_POLICY_ID + ":xm-test:red"
vdi_label_green = xsconstants.ACM_POLICY_ID + ":xm-test:green"

vm_label_unlabeled = xsconstants.ACM_POLICY_ID + ":xm-test:" + \
                     acmpolicy.ACM_LABEL_UNLABELED

vdi_file = "/dev/ram0"
vdi_path = "phy:" + vdi_file

#Note:
# If during the suspend/resume operations 'red' instead of 'green' is
# used, the Chinese Wall policy goes into effect and disallows the
# suspended VM from being resumed...

try:
    # XmTestAPIDomain tries to establish a connection to XenD
    domain = XmTestAPIDomain(extraConfig={ 'security_label' : vm_label_red })
except Exception, e:
    SKIP("Skipping test. Error: %s" % str(e))

vm_uuid = domain.get_uuid()

session = xapi.connect()
xstype = session.xenapi.XSPolicy.get_xstype()
if int(xstype) & xsconstants.XS_POLICY_ACM == 0:
    SKIP("ACM not enabled/compiled in Xen")

f = open("xm-test-security_policy.xml", 'r')
if f:
    newpolicyxml = f.read()
    f.close()
else:
    FAIL("Could not read 'xm-test' policy")

policystate = session.xenapi.XSPolicy.get_xspolicy()
if int(policystate['type']) == 0:
    policystate = session.xenapi.XSPolicy.set_xspolicy(
                         xsconstants.XS_POLICY_ACM,
                         newpolicyxml,
                         xsconstants.XS_INST_BOOT | xsconstants.XS_INST_LOAD,
                         True)
    if int(policystate['flags']) == -1:
        FAIL("Could not set the new policy.")

policystate = session.xenapi.XSPolicy.get_xspolicy()
print "policystate = %s" % policystate
acm_ref = policystate['xs_ref']


#
# Some tests with labeling of resources
#
labels = session.xenapi.XSPolicy.get_labeled_resources()
print "labeled resources are:\n%s" % labels

oldlabel = session.xenapi.XSPolicy.get_resource_label("phy:/dev/ram0")

rc  = session.xenapi.XSPolicy.set_resource_label("phy:/dev/ram0", "",
                                                 oldlabel)

rc  = session.xenapi.XSPolicy.set_resource_label("phy:/dev/ram0",
                                                 vdi_label_green,
                                                 "")

res = session.xenapi.XSPolicy.get_resource_label("phy:/dev/ram0")
if res != vdi_label_green:
    FAIL("(1) get_resource_label returned unexpected result %s, wanted %s" %
         (res, vdi_label_green))


#
# Some test with labeling of VMs
#

res = session.xenapi.VM.get_security_label(vm_uuid)

if res != vm_label_red:
    FAIL("VM.get_security_label returned wrong security label '%s'." % res)

res = session.xenapi.VM.set_security_label(vm_uuid, vm_label_green,
                                                    vm_label_red)

res = session.xenapi.VM.get_security_label(vm_uuid)
if res != vm_label_green:
     FAIL("VM does not show expected label '%s' but '%s'." %
          (vm_label_green, res))

res = session.xenapi.VM.set_security_label(vm_uuid, "", vm_label_green)
if int(res) != 0:
    FAIL("Should be able to unlabel the domain while it's halted.")

res = session.xenapi.VM.get_security_label(vm_uuid)
if res != vm_label_unlabeled:
    FAIL("Unexpected VM security label after removal: %s" % res)

res = session.xenapi.VM.set_security_label(vm_uuid, vm_label_red, res)
if int(res) != 0:
    FAIL("Could not label the VM to '%s'" % vm_label_red)

res = session.xenapi.VM.get_security_label(vm_uuid)
if res != vm_label_red:
    FAIL("VM has wrong label '%s', expected '%s'." % (res, vm_label_red))

sr_uuid = session.xenapi.SR.get_by_name_label("Local")
if len(sr_uuid) == 0:
    FAIL("Could not get a handle on SR 'Local'")


vdi_rec = { 'name_label'  : "My disk",
            'SR'          : sr_uuid[0],
            'virtual_size': 0,
            'sector_size' : 512,
            'parent'      : '',
            'SR_name'     : 'Local',
            'type'        : 'system',
            'shareable'   : False,
            'read-only'   : False,
            'other_config': {'location': vdi_path}
}

vdi_ref = session.xenapi.VDI.create(vdi_rec)

res = session.xenapi.VDI.get_name_label(vdi_ref)
if res != vdi_rec['name_label']:
    print "Destroying VDI now"
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VDI_get_name_label return wrong information")

res = session.xenapi.VDI.get_record(vdi_ref)
print "vdi_record : %s" % res

oldlabel = session.xenapi.XSPolicy.get_resource_label(vdi_path)

#Remove label from VDI device
rc  = session.xenapi.XSPolicy.set_resource_label(vdi_path,
                                                 "",
                                                 oldlabel)


# Attach a VBD to the VM

vbd_rec = { 'VM'      : vm_uuid,
            'VDI'     : vdi_ref,
            'device'  : "xvda1",
            'mode'    : 1,
            'bootable': 0,
}

vbd_ref = session.xenapi.VBD.create(vbd_rec)

res = session.xenapi.VBD.get_record(vbd_ref)

try:
    domain.start(noConsole=True)
    # Should not get here.
    print "Destroying VDI now"
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Could start VM with a VBD that it is not allowed to access.")
except:
    pass
    print "Could not create domain -- that's good"


#
# Label the VDI now
#

rc    = session.xenapi.VDI.set_security_label(vdi_ref, vdi_label_red, "")
if int(rc) != 0:
    FAIL("Could not set the VDI label to '%s'" % vdi_label_red)

label = session.xenapi.VDI.get_security_label(vdi_ref)
if label != vdi_label_red:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Unexpected label '%s' on VDI, wanted '%s'" %
         (label, vdi_label_red))

rc    = session.xenapi.VDI.set_security_label(vdi_ref, "", label)
if int(rc) != 0:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Should be able to unlabel VDI.")

rc    = session.xenapi.VDI.set_security_label(vdi_ref, vdi_label_red, "")
if int(rc) != 0:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Should be able to label VDI with label '%s'" % vid_label_red)

res   = session.xenapi.XSPolicy.get_resource_label(vdi_path)
if res != vdi_label_red:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("(2) get_resource_label on %s returned unexpected result %s, wanted '%s'" %
         (vdi_path, res, vdi_label_red))

res = session.xenapi.VDI.get_security_label(vdi_ref)
if res != vdi_label_red:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("get_security_label returned unexpected result %s, wanted '%s'" %
         (res, vdi_label_red))

domain.start(noConsole=True)

console = domain.getConsole()

domName = domain.getName()

try:
    run = console.runCmd("cat /proc/interrupts")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL("Could not access proc-filesystem")

# Try to relabel while VM is running
try:
    res = session.xenapi.VM.set_security_label(vm_uuid, vm_label_green,
                                               vm_label_red)
except:
    pass

lab = session.xenapi.VM.get_security_label(vm_uuid)
if lab == vm_label_green:
    FAIL("Should not be able to reset the security label while running."
         "tried to set to %s, got %s, old: %s" %(vm_label_green, lab,
         vm_label_red))


#
# Suspend the domain and relabel it
#

try:
    status, output = traceCommand("xm suspend %s" % domName,
                                  timeout=30)
except TimeoutError, e:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Failure from suspending VM: %s." % str(e))

# Try to relabel while VM is suspended -- this should work

rc  = session.xenapi.VM.set_security_label(vm_uuid, vm_label_green,
                                           vm_label_red)
if int(rc) != 0:
    FAIL("VM security label could not be set to %s" % vm_label_green)

res = session.xenapi.VM.get_security_label(vm_uuid)
if res != vm_label_green:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VM (suspended) has label '%s', expected '%s'." %
         (res, vm_label_green))

status, output = traceCommand("xm list")

#Try to resume now -- should fail due to denied access to block device
try:
    status, output = traceCommand("xm resume %s" % domName,
                                  timeout=30)
    if status == 0:
        session.xenapi.VDI.destroy(vdi_ref)
        FAIL("Could resume re-labeled VM: %s" % output)
except Exception, e:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("1. Error resuming the VM: %s." % str(e))

# Relabel VM so it would resume
res = session.xenapi.VM.set_security_label(vm_uuid, vm_label_red,
                                           vm_label_green)
if int(res) != 0:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Could not relabel VM to have it resume.")

res = session.xenapi.VM.get_security_label(vm_uuid)
if res != vm_label_red:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VM (suspended) has label '%s', expected '%s'." %
         (res, vm_label_red))


# Relabel the resource so VM should not resume
try:
    session.xenapi.XSPolicy.set_resource_label(vdi_path,
                                               vdi_label_green,
                                               "")
except Exception, e:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Could not label the VDI to '%s': %x" %
         (vdi_label_green, int(rc)))

#Try to resume now -- should fail due to denied access to block device
try:
    status, output = traceCommand("xm resume %s" % domName,
                                  timeout=30)
    if status == 0:
        session.xenapi.VDI.destroy(vdi_ref)
        FAIL("Could resume re-labeled VM: %s" % output)
except Exception, e:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("2. Error resuming the VM: %s." % str(e))


status, output = traceCommand("xm list")

# Relabel the resource so VM can resume
try:
    session.xenapi.XSPolicy.set_resource_label(vdi_path,
                                               vdi_label_red,
                                               vdi_label_green)
except Exception, e:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Could not label the resource to '%s'" % vid_label_red)

res = session.xenapi.XSPolicy.get_resource_label(vdi_path)
if res != vdi_label_red:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("'%s' has label '%s', expected '%s'." %
         (vdi_path, res, vdi_label_red))

#Try to resume now -- should work
try:
    status, output = traceCommand("xm resume %s" % domName,
                                  timeout=30)
    if status != 0:
        session.xenapi.VDI.destroy(vdi_ref)
        FAIL("Could not resume re-labeled VM: %s" % output)
except Exception, e:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("3. Error resuming the VM: %s." % str(e))


status, output = traceCommand("xm list")

console = domain.getConsole()

try:
    run = console.runCmd("cat /proc/interrupts")
except ConsoleError, e:
    saveLog(console.getHistory())
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Could not access proc-filesystem")

domain.stop()
domain.destroy()
