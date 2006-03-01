#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com)

# Positive Test: create domain with virtual TPM attached at build time,
#                check list of pcrs

from XmTestLib import *

def vtpm_cleanup(domName):
	# Since this is only a temporary domain I clean up the domain from the
	# virtual TPM directory
	traceCommand("/etc/xen/scripts/vtpm-delete %s" % domName)

if ENABLE_HVM_SUPPORT:
    SKIP("vtpm-list not supported for HVM domains")

status, output = traceCommand("ls /dev/tpm0")
if re.search("No such file or directory",output):
    SKIP("This machine has no hardware TPM; cannot run this test")

status, output = traceCommand("ps aux | grep vtpm_manager | grep -v grep")
if output == "":
    FAIL("virtual TPM manager must be started to run this test")

# vtpm manager has been detected
config = {"vtpm":"instance=1,backend=0"}
domain = XmTestDomain(extraConfig=config)

try:
    domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    vtpm_cleanup(domain.getName())
    FAIL("Unable to create domain")

domName = domain.getName()

try:
    console = XmConsole(domain.getName())
except ConsoleError, e:
    vtpm_cleanup(domName)
    FAIL(str(e))

try:
    console.sendInput("input")
    run = console.runCmd("ls /sys")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL(str(e))

if re.search("No such file",run["output"]):
    try:
        run = console.runCmd("mkdir /sys")
        run = console.runCmd("mount -t sysfs /sys /sys")
    except ConsoleError, e:
        saveLog(console.getHistory())
        vtpm_cleanup(domName)
        FAIL(str(e))

try:
    run = console.runCmd("cat /sys/devices/platform/tpm_vtpm/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL(str(e))

if re.search("No such file",run["output"]):
    FAIL("TPM frontend support not compiled into (domU?) kernel")

console.closeConsole()

domain.stop()

vtpm_cleanup(domName)

if not re.search("PCR-00:",run["output"]):
	FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side")
