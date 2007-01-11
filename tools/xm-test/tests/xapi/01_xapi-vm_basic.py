#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Basic VM creation test

from XmTestLib import xapi
from XmTestLib.XenAPIDomain import XmTestAPIDomain
from XmTestLib import *
from xen.xend import XendAPIConstants
import commands
import os

try:
    # XmTestAPIDomain tries to establish a connection to XenD
    domain = XmTestAPIDomain()
except Exception, e:
    SKIP("Skipping test. Error: %s" % str(e))
vm_uuid = domain.get_uuid()

session = xapi.connect()

domain.start(startpaused=True)

res = session.xenapi.VM.get_power_state(vm_uuid)

if res != XendAPIConstants.XEN_API_VM_POWER_STATE[XendAPIConstants.XEN_API_VM_POWER_STATE_PAUSED]:
    FAIL("VM was not started in 'paused' state")

res = session.xenapi.VM.unpause(vm_uuid)

res = session.xenapi.VM.get_power_state(vm_uuid)

if res != XendAPIConstants.XEN_API_VM_POWER_STATE[XendAPIConstants.XEN_API_VM_POWER_STATE_RUNNING]:
    FAIL("VM could not be put into 'running' state")

console = domain.getConsole()

try:
    run = console.runCmd("cat /proc/interrupts")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL("Could not access proc-filesystem")

res = session.xenapi.VM.pause(vm_uuid)

res = session.xenapi.VM.get_power_state(vm_uuid)

if res != XendAPIConstants.XEN_API_VM_POWER_STATE[XendAPIConstants.XEN_API_VM_POWER_STATE_PAUSED]:
    FAIL("VM could not be put into 'paused' state")

res = session.xenapi.VM.unpause(vm_uuid)

res = session.xenapi.VM.get_power_state(vm_uuid)

if res != XendAPIConstants.XEN_API_VM_POWER_STATE[XendAPIConstants.XEN_API_VM_POWER_STATE_RUNNING]:
    FAIL("VM could not be 'unpaused'")

domain.stop()
domain.destroy()
