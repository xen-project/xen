#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Positive Test: create domain with virtual TPM attached at build time,
#                verify list


from XmTestLib import *
from vtpm_utils import *
import commands
import os

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

status, output = traceCommand("xm vtpm-list %s" % domain.getId())
eyecatcher = "/local/domain/0/backend/vtpm"
where = output.find(eyecatcher)
if status != 0:
    vtpm_cleanup(domName)
    FAIL("xm vtpm-list returned bad status, expected 0, status is %i" % status)
elif where < 0:
    vtpm_cleanup(domName)
    FAIL("Fail to list virtual TPM device")

domain.stop()

vtpm_cleanup(domName)
