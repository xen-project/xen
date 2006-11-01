#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Authors: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import os
import time

rdpath = getRdPath()

# status, output = traceCommand("losetup -f %s" % rdpath)
# if status != 0:
#     FAIL("Unable to get a free loop device")
# 
# if verbose:
#     print "Using %s" % output

if ENABLE_HVM_SUPPORT:
    config = None
else:
    config = {"root"   : "/dev/hda1",
              "disk"   : "file:%s/initrd.img,hda1,w" % rdpath
              }
domain = XmTestDomain(name="14_create_blockroot", extraConfig=config)

try:
    console = domain.start()
except DomainError, e:
      FAIL(str(e))

#waitForBoot()

try:
#    console.debugMe = True
    run = console.runCmd("ls")

except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

if run["return"] != 0:
    FAIL("DomU 'ls' failed")
