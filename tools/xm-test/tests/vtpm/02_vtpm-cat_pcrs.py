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

config = {"vtpm":"instance=1,backend=0"}
domain = XmTestDomain(extraConfig=config)
domName = domain.getName()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    vtpm_cleanup(domName)
    FAIL("Unable to create domain (%s)" % domName)

try:
    console.sendInput("input")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL(str(e))

try:
    run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL("No result from dumping the PCRs")

if re.search("No such file",run["output"]):
    vtpm_cleanup(domName)
    FAIL("TPM frontend support not compiled into (domU?) kernel")

domain.closeConsole()

domain.stop()

vtpm_cleanup(domName)

if not re.search("PCR-00:",run["output"]):
    FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side")
