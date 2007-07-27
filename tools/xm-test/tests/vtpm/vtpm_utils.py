#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("vtpm tests not supported for HVM domains")

status, output = traceCommand("COLUMNS=200 ; "
                              "ps aux | grep vtpm_manager | grep -v grep")
if output == "":
    SKIP("virtual TPM manager must be started to run this test; might "
         "need /dev/tpm0")

def vtpm_cleanup(domName):
    traceCommand("/etc/xen/scripts/vtpm-delete "
                 "`xenstore-read /local/domain/0/backend/vtpm/%s/0/uuid`" %
                 str(domid(domName)))

def vtpm_cleanup(uuid):
    from xen.xm import main
    if main.serverType != main.SERVER_XEN_API:
        traceCommand("/etc/xen/scripts/vtpm-delete %s" % uuid)

def vtpm_get_uuid(domainid):
    s, o = traceCommand("xenstore-read "
                        "/local/domain/0/backend/vtpm/%s/0/uuid" % domainid)
    return o
