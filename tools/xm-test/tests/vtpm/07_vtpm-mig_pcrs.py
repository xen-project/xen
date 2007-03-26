#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Positive Test: create domain with virtual TPM attached at build time,
#                extend a pcr
#                check list of pcrs; locally migrate the domain and
#                check list of pcrs again and validate extended pcr
#                This test does local live migration.

from XmTestLib import *
from vtpm_utils import *
import commands
import os
import os.path

config = {"vtpm":"instance=1,backend=0"}
domain = XmTestDomain(extraConfig=config)
domName = domain.getName()
consoleHistory = ""

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
    run = console.runCmd("mknod /dev/tpm0 c 10 224")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL("Error while creating /dev/tpm0")

try:
    run = console.runCmd("echo -ne \"\\x00\\xc1\\x00\\x00\\x00\\x22\\x00\\x00\\x00\\x14\\x00\\x00\\x00\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\0xf\\x10\\x11\\x12\\x13\\x14\" > seq; cat seq > /dev/tpm0")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL("Error while extending PCR 0")

try:
    run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL("No result from dumping the PCRs")


if re.search("No such file",run["output"]):
    vtpm_cleanup(domName)
    FAIL("TPM frontend support not compiled into (domU?) kernel")

if not re.search("PCR-00:",run["output"]):
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
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
        status, ouptut = traceCommand("xm migrate -l %s localhost" %
                                      domName,
                                      timeout=90)
    except TimeoutError, e:
        saveLog(consoleHistory)
        vtpm_cleanup(domName)
        FAIL(str(e))

    if status != 0:
        saveLog(consoleHistory)
        vtpm_cleanup(domName)
        FAIL("xm migrate did not succeed. External device migration activated?")


    domName = domain.getName()
    new_domid = domid(domName)

    if (old_domid == new_domid):
        vtpm_cleanup(domName)
        FAIL("xm migrate failed, domain id is still %s (loop=%d)" %
             (old_domid,loop))

    try:
        console = domain.getConsole()
    except ConsoleError, e:
        vtpm_cleanup(domName)
        FAIL(str(e))

    try:
        run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
    except ConsoleError, e:
        saveLog(console.getHistory())
        vtpm_cleanup(domName)
        FAIL("No result from dumping the PCRs")

    if not re.search("PCR-00:",run["output"]):
        saveLog(console.getHistory())
        vtpm_cleanup(domName)
        FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side")

    if not re.search("PCR-00: 1E A7 BD",run["output"]):
        saveLog(console.getHistory())
        vtpm_cleanup(domName)
        FAIL("Virtual TPM lost PCR 0 value: \n%s" % run["output"])

    loop += 1

domain.closeConsole()

domain.stop()

vtpm_cleanup(domName)
