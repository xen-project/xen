#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("vtpm tests not supported for HVM domains")

if not os.path.exists("/dev/tpm0"):
    SKIP("This machine has no hardware TPM; cannot run this test")

status, output = traceCommand("ps aux | grep vtpm_manager | grep -v grep")
if output == "":
    FAIL("virtual TPM manager must be started to run this test")

def vtpm_cleanup(domName):
	traceCommand("/etc/xen/scripts/vtpm-delete %s" % domName)
