#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>
##
## Description:
## Tests that verify mem-set output and return code
## 1) Test for xm mem-set
##	create domain,
##	verify domain and ls output,
##	mem-set in dom0,
##	verify with xm list memory change external,
##	verify with xm list memory change internal,
##
## Author: Woody Marvel		marvel@us.ibm.com
##

import sys 
import re 
import time 
from XmTestLib import * 

if ENABLE_HVM_SUPPORT:
    SKIP("Mem-set not supported for HVM domains")

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain() 

# Start it
try:
    domain.start() 
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# Attach a console to it
try:
    console = XmConsole(domain.getName()) 
    console.sendInput("input") 
    # Make sure it's up an running before we continue
    console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))
    
# set mem-set for less than default
cmd = "xm mem-set %s %i" % (domain.getName(), 63)
status, output = traceCommand(cmd)
if status != 0:
    if verbose:
        print "mem-set failed:"
        print output
    FAIL("cmd %s returned invalid %i != 0" % (cmd, status))

for i in [1,2,3,4,5,6,7,8,9,10]:
    mem = getDomMem(domain.getName())
    if mem == 63:
        break
    time.sleep(1)

# verify memory set externally
mem = getDomMem(domain.getName())
if not mem:
    FAIL("Failed to get memory amount for domain %s" % domain.getName())
elif mem != 63:
    FAIL("Dom0 failed to verify 63 MB; got %i MB" % mem)

# verify memory set internally
try:
    run = console.runCmd("cat /proc/xen/balloon | grep Current")
except ConsoleError, e:
    FAIL(str(e))

# Check the output of 'cat /proc/xen/balloon'
m = re.match("^Current allocation:\s+(\d+)\skB", run["output"])
if not m: 
    FAIL("The DomU command 'cat /proc/xen/balloon' failed.")

domUmem = int(m.group(1)) / 1024

if domUmem != 63:
    FAIL("DomU reported incorrect memory amount: %i MB" % (domUmem))

# quiesce everything
# Close the console
console.closeConsole() 

# Stop the domain (nice shutdown)
domain.stop()
