#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Positive Test: create domain with virtual TPM attached at build time,
#                check list of pcrs

from XmTestLib import *
from vtpm_utils import *
import commands
import os
import os.path
import atexit

config = {"vtpm":"instance=1,backend=0"}
domain = XmTestDomain(extraConfig=config)
domName = domain.getName()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    FAIL("Unable to create domain (%s)" % domName)

atexit.register(vtpm_cleanup, vtpm_get_uuid(domid(domName)))

try:
    console.sendInput("input")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

try:
    run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL("No result from dumping the PCRs")

if re.search("No such file",run["output"]):
    FAIL("TPM frontend support not compiled into (domU?) kernel")

domain.closeConsole()

domain.stop()

if not re.search("PCR-00:",run["output"]):
    FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side")
