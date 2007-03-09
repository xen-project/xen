#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Test to test the vtpm class through the Xen-API
#
# Tested methods:
#  VTPM: get_uuid, get_backend, get_by_uuid, get_record
#        create, destroy, get_VM
#  VM: get_VTPMS

from XmTestLib import xapi
from XmTestLib.XenAPIDomain import XmTestAPIDomain
from XmTestLib import *
from vtpm_utils import *
import commands
import os

VTPM_RECORD_KEYS = [ 'backend', 'VM', 'uuid' ]

try:
    # XmTestAPIDomain tries to establish a connection to XenD
    domain = XmTestAPIDomain()
except Exception, e:
    SKIP("Skipping test. Error: %s" % str(e))
vm_uuid = domain.get_uuid()

vtpmcfg = {}
vtpmcfg['backend'] = DOM0_UUID
vtpmcfg['VM'] = vm_uuid

session = xapi.connect()

vtpm_uuid = session.xenapi.VTPM.create(vtpmcfg)

vtpm_be = session.xenapi.VTPM.get_backend(vtpm_uuid)
if vtpm_be != vtpmcfg['backend']:
    FAIL("vTPM's backend is in '%s', expected: '%s'" %
         (vtpm_be, vtpmcfg['backend']))

vtpm_rec = session.xenapi.VTPM.get_record(vtpm_uuid)

miss_keys = []
for k in VTPM_RECORD_KEYS:
    if k not in vtpm_rec.keys():
        miss_keys.append(k)
if len(miss_keys) > 0:
    FAIL("vTPM record is missing key(s): %s" % miss_keys)

if vtpm_rec['uuid']  != vtpm_uuid:
    FAIL("vTPM record shows vtpm uuid '%s', expected: '%s'" %
         (vtpm_rec['uuid'], vtpm_uuid))
if vtpm_rec['VM']  != vm_uuid:
    FAIL("vTPM record shows VM uuid '%s', expected: '%s'" %
         (vtpm_rec['VM'], vm_uuid))
if vtpm_rec['backend'] != vtpmcfg['backend']:
    FAIL("vTPM record shows VM bakcned '%s', expected: '%s'" %
         (vtpm_rev['backend'], vtpmcfg['backend']))

badkeys = []
keys = vtpm_rec.keys()
for k in keys:
    if k not in VTPM_RECORD_KEYS:
        badkeys.append(k)
if len(badkeys) > 0:
    FAIL("Unexpected attributes in result: %s" % badkeys)

if vm_uuid != session.xenapi.VTPM.get_VM(vtpm_uuid):
    FAIL("VM uuid from VTPM.get_VM different (%s) than expected (%s)." %
         (vm_ref, vm_uuid))

uuid = session.xenapi.VTPM.get_uuid(vtpm_uuid)
if uuid != vtpm_uuid:
    FAIL("vTPM from VTPM.get_uuid different (%s) than expected (%s)." %
         (uuid, vtpm_uuid))

vtpm_ref = session.xenapi.VTPM.get_by_uuid(vtpm_uuid)
if vtpm_ref != vtpm_uuid:
    FAIL("vTPM from VTPM.get_by_uuid different (%s) than expected (%s)." %
         (vtpm_ref, vtpm_uuid))

vm_vtpms = session.xenapi.VM.get_VTPMs(vm_uuid)
if len(vm_vtpms) != 1:
    FAIL("Number of vTPMs from get_VTPMs is (%d) not what was expected (%d)" %
         (len(vm_vtpms), 1))
if vtpm_uuid not in vm_vtpms:
    FAIL("Other vTPM uuid (%s) returned from VM.get_VTPMs than expected (%s)" %
         (vm_vtpms[0], vtpm_uuid))

try:
    console = domain.start()
except DomainError, e:
    FAIL("Unable to create domain (%s)" % domName)

try:
    console.sendInput("input")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

try:
    run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL("1. No result from dumping the PCRs")

if re.search("No such file",run["output"]):
    FAIL("TPM frontend support not compiled into (domU?) kernel")

if not re.search("PCR-00:",run["output"]):
    saveLog(console.getHistory())
    FAIL("1. Virtual TPM is not working correctly on /dev/vtpm on backend side: \n%s" % run["output"])

try:
    session.xenapi.VTPM.destroy(vtpm_uuid)
    #Should never get here
    FAIL("Could destroy vTPM while VM is running")
except:
    pass

rc = session.xenapi.VM.suspend(vm_uuid)
if rc:
    FAIL("Could not suspend VM")

try:
    session.xenapi.VTPM.destroy(vtpm_uuid)
    #May not throw an exception in 'suspend' state
except:
    pass

rc = session.xenapi.VM.resume(vm_uuid, False)
if rc:
    FAIL("Could not resume VM")

try:
    console = domain.getConsole()
except ConsoleError, e:
    FAIL(str(e))

try:
    run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL("2. No result from dumping the PCRs. vTPM has been removed?")

if not re.search("PCR-00:",run["output"]):
    saveLog(console.getHistory())
    FAIL("2. Virtual TPM is not working correctly on /dev/vtpm on backend side: \n%s" % run["output"])

domain.stop()

try:
    session.xenapi.VTPM.destroy(vtpm_uuid)
except:
    FAIL("Could NOT destroy vTPM while domain is halted.")

domain.destroy()
