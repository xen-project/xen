#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

domain = XmTestDomain()

domain.configAddDisk("phy:/dev/ram0", "hda1", "w")

s, o = traceCommand("mkfs /dev/ram0")
if s != 0:
    FAIL("Unable to mkfs /dev/ram0 in dom0")

try:
    domain.start()
except DomainError, e:
    FAIL(str(e))

try:
    console = XmConsole(domain.getName())
    console.sendInput("foo")

    run = console.runCmd("mount /dev/hda1 /mnt")
    if run["return"] != 0:
        FAIL("Unable to mount /dev/hda1")

    run = console.runCmd("echo bar > /mnt/foo")
    if run["return"] != 0:
        FAIL("Unable to write to block device!")

except ConsoleError, e:
    FAIL(str(e))

console.closeConsole()

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
    console = XmConsole(domain.getName())

    run = console.runCmd("ls | grep proc")
    if run["return"] != 0:
        FAIL("ls failed on restored domain")
    
    run = console.runCmd("cat /mnt/foo | grep bar")
    if run["return"] != 0:
        FAIL("Unable to read from block device")

except ConsoleError, e:
    FAIL(str(e))
        
