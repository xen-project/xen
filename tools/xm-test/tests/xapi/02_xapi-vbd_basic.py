#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2007
# Author: Stefan Berger <stefanb@us.ibm.com>

# Tests related to SR, VDI, VBD
#
# Used methods:
# SR: get_by_name_label, get_VDIs
#
# VDI: create, get_name_label, destroy
#
# VBD: create, get_driver, get_mode, get_VM, get_VDI, get_device
#
# VM: get_VBDs

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

# Do something with SR/VDI/VBD

sr_uuid = session.xenapi.SR.get_by_name_label("Local")
if len(sr_uuid) == 0:
    FAIL("Could not get a handle on SR 'Local'")

vdi_rec = { 'name_label'  : "My disk",
            'SR'          : sr_uuid[0],
            'virtual_size': 1 << 10,
            'sector_size' : 512,
            'type'        : 0,
            'shareable'   : 0,
            'read-only'   : 0
}

vdi_ref = session.xenapi.VDI.create(vdi_rec)

res = session.xenapi.SR.get_VDIs(sr_uuid[0])
if vdi_ref not in res:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("SR_get_VDI does not show new VDI")

res = session.xenapi.VDI.get_name_label(vdi_ref)
if res != vdi_rec['name_label']:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VDI_get_name_label return wrong information")

#MORE method calls to VDI to add here...




vbd_rec = { 'VM'    : vm_uuid,
            'VDI'   : vdi_ref,
            'device': "xvda1",
            'mode'  : 1,
            'driver': 1,
}

vbd_ref = session.xenapi.VBD.create(vbd_rec)

res = session.xenapi.VBD.get_driver(vbd_ref)
print "VBD driver: %s" % res
if res != XendAPIConstants.XEN_API_DRIVER_TYPE[int(vbd_rec['driver'])]:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VBD_get_driver returned wrong information")

res = session.xenapi.VBD.get_mode(vbd_ref)
print "VBD mode: %s" % res
# FIXME: Check this. Should not have to subtract '1'.
if res != XendAPIConstants.XEN_API_VBD_MODE[int(vbd_rec['mode']) - 1]:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VBD_get_mode returned wrong information")

res = session.xenapi.VBD.get_VM(vbd_ref)
if res != vm_uuid:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VBD_get_VM returned wrong result")

res = session.xenapi.VBD.get_VDI(vbd_ref)
if res != vdi_ref:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VBD_get_VDI returned wrong result")

res = session.xenapi.VBD.get_device(vbd_ref)
print "VBD device: %s" % res
if res != vbd_rec['device']+":disk":
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VBD_get_device returned wrong result")

res = session.xenapi.VM.get_VBDs(vm_uuid)
if vbd_ref not in res:
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("VM_get_VBDS does not show created VBD")


rc = domain.start()

console = domain.getConsole()

try:
    run = console.runCmd("cat /proc/interrupts")
except ConsoleError, e:
    saveLog(console.getHistory())
    session.xenapi.VDI.destroy(vdi_ref)
    FAIL("Could not access proc-filesystem")


domain.stop()
domain.destroy()

session.xenapi.VDI.destroy(vdi_ref)

res = session.xenapi.SR.get_VDIs(sr_uuid[0])
if vdi_ref in res:
    FAIL("SR_get_VDI still shows deleted VDI")
