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
    run = console.runCmd("cat /sys/devices/xen/vtpm-0/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL("No result from dumping the PCRs")

if re.search("No such file",run["output"]):
    vtpm_cleanup(domName)
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
        vtpm_cleanup(domName)
        FAIL(str(e))

    if status != 0:
        saveLog(consoleHistory)
        vtpm_cleanup(domName)
        FAIL("xm save did not succeed")

    try:
        status, ouptut = traceCommand("xm restore %s.save" %
                                      (domName),
                                      timeout=30)
    except TimeoutError, e:
        os.remove("%s.save" % domName)
        saveLog(consoleHistory)
        vtpm_cleanup(domName)
        FAIL(str(e))

    os.remove("%s.save" % domName)

    if status != 0:
        saveLog(consoleHistory)
        vtpm_cleanup(domName)
        FAIL("xm restore did not succeed")

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
        FAIL(str(e))

    if not re.search("PCR-00:",run["output"]):
        saveLog(console.getHistory())
        vtpm_cleanup(domName)
        FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side")

    loop += 1

domain.closeConsole()

domain.stop()

vtpm_cleanup(domName)

