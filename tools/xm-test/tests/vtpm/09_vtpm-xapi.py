#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Test to test the vtpm class through the Xen-API

from XmTestLib import xapi
from XmTestLib.XenAPIDomain import XmTestAPIDomain
from XmTestLib import *
from vtpm_utils import *
import commands
import os

try:
    # XmTestAPIDomain tries to establish a connection to XenD
    domain = XmTestAPIDomain()
except Exception, e:
    SKIP("Skipping test. Error: %s" % str(e))
vm_uuid = domain.get_uuid()

vtpmcfg = {}
vtpmcfg['type'] = "paravirtualised"
vtpmcfg['backend'] = "Domain-0"
vtpmcfg['instance'] = 1
vtpmcfg['VM'] = vm_uuid

session = xapi.connect()

vtpm_uuid = session.xenapi.VTPM.create(vtpmcfg)

vtpm_id = session.xenapi.VTPM.get_instance(vtpm_uuid)
vtpm_be = session.xenapi.VTPM.get_backend(vtpm_uuid)
if vtpm_be != vtpmcfg['backend']:
    FAIL("vTPM's backend is in '%s', expected: '%s'" %
         (vtpm_be, vtpmcfg['backend']))

driver = session.xenapi.VTPM.get_driver(vtpm_uuid)
if driver != vtpmcfg['type']:
    FAIL("vTPM has driver type '%s', expected: '%s'" %
         (driver, vtpmcfg['type']))

vtpm_rec = session.xenapi.VTPM.get_record(vtpm_uuid)

if vtpm_rec['driver']  != vtpmcfg['type']:
    FAIL("vTPM record shows driver type '%s', expected: '%s'" %
         (vtpm_rec['driver'], vtpmcfg['type']))
if vtpm_rec['uuid']  != vtpm_uuid:
    FAIL("vTPM record shows vtpm uuid '%s', expected: '%s'" %
         (vtpm_rec['uuid'], vtpm_uuid))
if vtpm_rec['VM']  != vm_uuid:
    FAIL("vTPM record shows VM uuid '%s', expected: '%s'" %
         (vtpm_rec['VM'], vm_uuid))

success = domain.start()

console = domain.getConsole()

try:
    run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL("No result from dumping the PCRs")

if re.search("No such file",run["output"]):
    vtpm_cleanup(domName)
    FAIL("TPM frontend support not compiled into (domU?) kernel")

domain.stop()
domain.destroy()
