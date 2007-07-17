#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Positive Test: create domain with virtual TPM attached at build time,
#                extend a pcr
#                check list of pcrs; locally migrate the domain and
#                check list of pcrs again and validate extended pcr
#                This test does local (non-live) migration.

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
    run = console.runCmd("mknod /dev/tpm0 c 10 224")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL("Error while creating /dev/tpm0")

try:
    run = console.runCmd("echo -ne \"\\x00\\xc1\\x00\\x00\\x00\\x22\\x00\\x00\\x00\\x14\\x00\\x00\\x00\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\0xf\\x10\\x11\\x12\\x13\\x14\" > seq; cat seq > /dev/tpm0")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL("Error while extending PCR 0")

try:
    run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL("No result from dumping the PCRs")


if re.search("No such file",run["output"]):
    FAIL("TPM frontend support not compiled into (domU?) kernel")

if not re.search("PCR-00:",run["output"]):
    saveLog(console.getHistory())
    FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side: \n%s" % run["output"])

if not re.search("PCR-00: 1E A7 BD",run["output"]):
    saveLog(console.getHistory())
    FAIL("Extend did not lead to expected result (1E A7 BD ...): \n%s" % run["output"])

consoleHistory = console.getHistory()
domain.closeConsole()

old_domid = domid(domName)

loop = 0
while loop < 3:
    try:
        status, ouptut = traceCommand("xm migrate %s localhost" %
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

    if not re.search("PCR-00: 1E A7 BD",run["output"]):
        saveLog(console.getHistory())
        FAIL("Virtual TPM lost PCR 0 value: \n%s" % run["output"])

    loop += 1

domain.closeConsole()

domain.stop()
