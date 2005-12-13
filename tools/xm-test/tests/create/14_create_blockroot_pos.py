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

if ENABLE_VMX_SUPPORT:
    domain = XmTestDomain(name="14_create_blockroot")
else:
    config = {"memory" : "64",
              "root"   : "/dev/hda1",
              "name"   : "14_create_blockroot",
              "kernel" : getDefaultKernel(),
              "disk"   : "file:%s/initrd.img,hda1,w" % rdpath
              }
    domConfig = XenConfig()
    domConfig.setOpts(config)
    domain = XenDomain(name=domConfig.getOpt("name"), config=domConfig)

try:
    domain.start()
except DomainError, e:
      FAIL(str(e))

#waitForBoot()

try:
    console = XmConsole(domain.getName(), historySaveCmds=True)
except ConsoleError, e:
    FAIL(str(e))

try:
#    console.debugMe = True
    console.sendInput("foo")
    run = console.runCmd("ls")

except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

if run["return"] != 0:
    FAIL("DomU 'ls' failed")
