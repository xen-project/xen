#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Authors: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import os

CONF_FILE = "/tmp/14_create_blockroot_pos.conf"

rdpath = os.path.abspath(os.environ.get("RD_PATH"))

# status, output = traceCommand("losetup -f %s" % rdpath)
# if status != 0:
#     FAIL("Unable to get a free loop device")
# 
# if verbose:
#     print "Using %s" % output
 
opts = {"memory" : "64",
        "root"   : "/dev/hda1",
        "name"   : "14_create_blockroot",
        "kernel" : getDefaultKernel() }

domain = XenDomain(opts=opts)

domain.configAddDisk("file:%s/initrd.img" % rdpath, "hda1", "w")

try:
    domain.start()
except DomainError, e:
      FAIL(str(e))

waitForBoot()

try:
    console = XmConsole(domain.getName(), historySaveCmds=True)
#    console.debugMe = True
    console.sendInput("foo")
    run = console.runCmd("ls")

except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

if run["return"] != 0:
    FAIL("DomU 'ls' failed")
