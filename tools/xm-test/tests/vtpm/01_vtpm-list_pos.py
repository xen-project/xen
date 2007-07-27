#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Positive Test: create domain with virtual TPM attached at build time,
#                verify list


from XmTestLib import *
from vtpm_utils import *
import commands
import os
import atexit

config = {"vtpm":"instance=1,backend=0"}
domain = XmTestDomain(extraConfig=config)

try:
    domain.start(noConsole=True)
except DomainError, e:
    if verbose:
        print e.extra
    vtpm_cleanup(domain.getName())
    FAIL("Unable to create domain")


domName = domain.getName()

atexit.register(vtpm_cleanup, vtpm_get_uuid(domid(domName)))

status, output = traceCommand("xm vtpm-list %s" % domain.getId())
eyecatcher = "/local/domain/0/backend/vtpm"
where = output.find(eyecatcher)
if status != 0:
    FAIL("xm vtpm-list returned bad status, expected 0, status is %i" % status)
elif where < 0:
    FAIL("Fail to list virtual TPM device")

domain.stop()
