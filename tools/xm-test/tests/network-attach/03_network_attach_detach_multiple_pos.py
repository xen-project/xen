#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

import sys
import re
import time

from XmTestLib import *
from XmTestLib.network_utils import *

if ENABLE_HVM_SUPPORT:
    SKIP("Network-attach not supported for HVM domains")

# Create a domain (default XmTestDomain, with our ramdisk)
domain = XmTestDomain()

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

console.debugMe = True

try:
    # Run 'ls'
    run = console.runCmd("ls")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))
    
for i in range(10):
    print "Attaching %d device" % i 
    status, msg = network_attach(domain.getName(), console)
    if status:
        FAIL(msg)
    
    print "Detaching %d device" % i 
    status, msg = network_detach(domain.getName(), console, i)
    if status:
        FAIL(msg)

# Close the console
domain.closeConsole()

# Stop the domain (nice shutdown)
domain.stop()
