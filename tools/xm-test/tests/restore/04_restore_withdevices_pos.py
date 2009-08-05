#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import re

if ENABLE_HVM_SUPPORT:
    SKIP("Restore currently not supported for HVM domains")

config = {"disk": ["phy:/dev/ram0,xvda1,w", "phy:/dev/ram1,xvdb2,w"],
          "vif":  ['', '']}
domain = XmTestDomain(extraConfig=config)

s, o = traceCommand("mke2fs -j -q /dev/ram0")
if s != 0:
    FAIL("Unable to mke2fs /dev/ram0 in dom0")

s, o = traceCommand("mke2fs -j -q /dev/ram1")
if s != 0:
    FAIL("Unable to mke2fs /dev/ram1 in dom0")

try:
    console = domain.start()
except DomainError, e:
    FAIL(str(e))

try:
    run = console.runCmd("mkdir /mnt/a /mnt/b")
    if run["return"] != 0:
        FAIL("Unable to mkdir /mnt/a /mnt/b")

    run = console.runCmd("mount /dev/xvda1 /mnt/a")
    if run["return"] != 0:
        FAIL("Unable to mount /dev/xvda1")

    run = console.runCmd("mount /dev/xvdb2 /mnt/b")
    if run["return"] != 0:
        FAIL("Unable to mount /dev/xvdb2")

    run = console.runCmd("echo xvda1 > /mnt/a/foo")
    if run["return"] != 0:
        FAIL("Unable to write to block device xvda1!")

    run = console.runCmd("echo xvdb2 > /mnt/b/foo")
    if run["return"] != 0:
        FAIL("Unable to write to block device xvdb2!")

    run = console.runCmd("ifconfig eth0 172.30.206.1 netmask 255.255.255.240")
    if run["return"] != 0:
        FAIL("Unable to configure DomU's eth0")

    run = console.runCmd("ifconfig eth1 172.30.206.17 netmask 255.255.255.240")
    if run["return"] != 0:
        FAIL("Unable to configure DomU's eth1")

    run = console.runCmd("ifconfig lo 127.0.0.1")
    if run["return"] != 0:
        FAIL("Unable to configure DomU's lo")


except ConsoleError, e:
    FAIL(str(e))

domain.closeConsole()

try:
    s, o = traceCommand("xm save %s /tmp/test.state" % domain.getName(),
                        timeout=30)
except TimeoutError, e:
    FAIL(str(e))

if s != 0:
    FAIL("xm save exited with %i != 0" % s)

# Let things settle
time.sleep(15)

try:
    s, o = traceCommand("xm restore /tmp/test.state",
                        timeout=30)
except TimeoutError, e:
    FAIL(str(e))

if s != 0:
    FAIL("xm restore exited with %i != 0" % s)

try:
    console = domain.getConsole()
    # Enable debug dumping, as this causes an Oops on x86_64
    console.debugMe = True

    # In case the domain is rebooted
    console.sendInput("ls")

    run = console.runCmd("ls | grep proc")
    if run["return"] != 0:
        FAIL("ls failed on restored domain")
    
    run = console.runCmd("cat /mnt/a/foo")
    if run["return"] != 0:
        FAIL("Unable to read from block device xvda1")
    if not re.search("xvda1", run["output"]):
        FAIL("Failed to read correct data from xvda1")

    run = console.runCmd("cat /mnt/b/foo")
    if run["return"] != 0:
        FAIL("Unable to read from block device xvdb2")
    if not re.search("xvdb2", run["output"]):
        FAIL("Failed to read correct data from xvdb2")

    run = console.runCmd("ifconfig")
    if not re.search("eth0", run["output"]):
        FAIL("DomU's eth0 disappeared")
    if not re.search("172.30.206.1", run["output"]):
        FAIL("DomU's eth0 lost its IP")
    if not re.search("eth1", run["output"]):
        FAIL("DomU's eth1 disappeared")
    if not re.search("172.30.206.17", run["output"]):
        FAIL("DomU's eth1 lost its IP")
    if not re.search("Loopback", run["output"]):
        FAIL("DomU's lo disappeared")
    if not re.search("127.0.0.1", run["output"]):
        FAIL("DomU's lo lost its IP")

except ConsoleError, e:
    FAIL(str(e))
        
