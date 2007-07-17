#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Positive Test: create domain with virtual TPM attached at build time,
#                check list of pcrs; suspend and resume the domain and
#                check list of pcrs again

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

loop = 0
while loop < 3:
    try:
        status, ouptut = traceCommand("xm save %s %s.save" %
                                      (domName, domName),
                                      timeout=30)

    except TimeoutError, e:
        saveLog(consoleHistory)
        FAIL(str(e))

    if status != 0:
        saveLog(consoleHistory)
        FAIL("xm save did not succeed")

    try:
        status, ouptut = traceCommand("xm restore %s.save" %
                                      (domName),
                                      timeout=30)
    except TimeoutError, e:
        os.remove("%s.save" % domName)
        saveLog(consoleHistory)
        FAIL(str(e))

    os.remove("%s.save" % domName)

    if status != 0:
        saveLog(consoleHistory)
        FAIL("xm restore did not succeed")

    try:
        console = domain.getConsole()
    except ConsoleError, e:
        FAIL(str(e))

    try:
        run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
    except ConsoleError, e:
        saveLog(console.getHistory())
        FAIL(str(e))

    if not re.search("PCR-00:",run["output"]):
        saveLog(console.getHistory())
        FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side")

    loop += 1

domain.closeConsole()

domain.stop()

