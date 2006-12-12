#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Test to test the vtpm class through the Xen-API

from XmTestLib import xapi
from XmTestLib.XenManagedDomain import XmTestManagedDomain
from XmTestLib import *
from vtpm_utils import *
import commands
import os

def do_test():
    domain = XmTestManagedDomain()
    vm_uuid = domain.get_uuid()

    vtpmcfg = {}
    vtpmcfg['type'] = "paravirtualised"
    vtpmcfg['backend'] = "Domain-0"
    vtpmcfg['instance'] = 1
    vtpmcfg['VM'] = vm_uuid

    server, session = xapi._connect()

    vtpm_uuid = xapi.execute(server.VTPM.create, session, vtpmcfg)

    vtpm_id = xapi.execute(server.VTPM.get_instance, session, vtpm_uuid)
    vtpm_be = xapi.execute(server.VTPM.get_backend , session, vtpm_uuid)
    if vtpm_be != vtpmcfg['backend']:
        FAIL("vTPM's backend is in '%s', expected: '%s'" %
             (vtpm_be, vtpmcfg['backend']))

    driver = xapi.execute(server.VTPM.get_driver, session, vtpm_uuid)
    if driver != vtpmcfg['type']:
        FAIL("vTPM has driver type '%s', expected: '%s'" %
             (driver, vtpmcfg['type']))

    vtpm_rec = xapi.execute(server.VTPM.get_record, session, vtpm_uuid)

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



try:
    do_test()
finally:
    #Make sure all domains are gone that were created in this test case
    xapi.vm_destroy_all()
