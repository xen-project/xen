#!/usr/bin/python

# Try and create two VMs and a private network betwene the two

import sys

from XmTestLib import *
from XmTestLib.network_utils import *

# Create two domains (default XmTestDomain, with our ramdisk)
try:
    domain1 = XmTestDomain()
    console1 = domain1.start()
    domain2 = XmTestDomain()
    console2 = domain2.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

# Create a network

status, ouptut = traceCommand("xm network-new xapi-network")
if status:
    FAIL(output)

# Attach two domains to it
status, msg = network_attach(domain1.getName(),
                             console1, bridge='xapi-network')
if status:
    FAIL(msg)

status, msg = network_attach(domain2.getName(),
                             console2, bridge='xapi-network')
if status:
    FAIL(msg)

# Configure IP addresses on two domains
try:
    # Run 'ls'
    run = console1.runCmd("ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up")
    run = console2.runCmd("ifconfig eth0 192.168.0.2 netmask 255.255.255.0 up")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

# Now ping...
try:
    run = console1.runCmd("ping -c 4 192.168.0.2")
    if run['return'] > 0:
        FAIL("Could not ping other host")
    run = console2.runCmd("ping -c 4 192.168.0.1")
    if run['return'] > 0:
        FAIL("Could not pint other host")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

status, msg = network_detach(domain1.getName(), console1)
status, msg = network_detach(domain2.getName(), console2)

# Clean up
domain1.closeConsole()
domain1.stop()
domain2.closeConsole()
domain2.stop()

status, ouptut = traceCommand("xm network-del xapi-network")
if status:
    FAIL(output)
