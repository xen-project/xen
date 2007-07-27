#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Positive Test: create domain with virtual TPM attached at build time,
#                check list of pcrs; locally migrate the domain and
#                check list of pcrs again
#                This test does local live migration.

from XmTestLib import *
from vtpm_utils import *
import commands
import os
import os.path
import atexit

config = {"vtpm":"instance=1,backend=0"}
domain = XmTestDomain(extraConfig=config)
domName = domain.getName()
consoleHistory = ""

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

consoleHistory = console.getHistory()
domain.closeConsole()

old_domid = domid(domName)

loop = 0
while loop < 3:
    try:
        status, ouptut = traceCommand("xm migrate -l %s localhost" %
                                      domName,
                                      timeout=90)
    except TimeoutError, e:
        saveLog(consoleHistory)
        FAIL(str(e))

    if status != 0:
        saveLog(consoleHistory)
        FAIL("xm migrate did not succeed. External device migration activated?")


    domName = domain.getName()
    new_domid = domid(domName)

    if (old_domid == new_domid):
        FAIL("xm migrate failed, domain id is still %s (loop=%d)" %
             (old_domid,loop))

    try:
        console = domain.getConsole()
    except ConsoleError, e:
        FAIL(str(e))

    try:
        run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
    except ConsoleError, e:
        saveLog(console.getHistory())
        FAIL("No result from dumping the PCRs")

    if not re.search("PCR-00:",run["output"]):
        saveLog(console.getHistory())
        FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side")

    loop += 1

domain.closeConsole()

domain.stop()
