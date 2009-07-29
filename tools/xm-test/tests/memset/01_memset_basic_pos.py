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
    console = domain.start() 
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

try:
    # Make sure it's up an running before we continue
    console.runCmd("ls")
except ConsoleError, e:
    FAIL(str(e))

xen_mem = XenMemory(console)
    
origmem = xen_mem.get_mem_from_domU()
newmem = origmem - 1

# set mem-set for less than default
cmd = "xm mem-set %s %i" % (domain.getName(), newmem)
status, output = traceCommand(cmd)
if status != 0:
    if verbose:
        print "mem-set failed:"
        print output
    FAIL("cmd %s returned invalid %i != 0" % (cmd, status))

for i in [1,2,3,4,5,6,7,8,9,10]:
    mem = getDomMem(domain.getName())
    if mem == newmem:
        break
    time.sleep(1)

# verify memory set externally
mem = getDomMem(domain.getName())
if not mem:
    FAIL("Failed to get memory amount for domain %s" % domain.getName())
elif mem != newmem:
    FAIL("Dom0 failed to verify %i MB; got %i MB" % newmem,mem)

# verify memory set internally
domUmem = xen_mem.get_mem_from_domU()

if domUmem != newmem:
    FAIL("DomU reported incorrect memory amount: %i MB" % (domUmem))

# quiesce everything
# Close the console
domain.closeConsole() 

# Stop the domain (nice shutdown)
domain.stop()
