#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author:  <dykman@us.ibm.com>

# Ping tests on local interfaces.
#  - creates a single guest domain
#  - sets up a single NIC
#  - conducts ping tests to the local loopback and IP address.

# ping -c 1 -s $size 127.0.0.1
# ping -c 1 -s $size $local_IP 
#   where $size = 1, 48, 64, 512, 1440, 1500, 1505, 
#                 4096, 4192, 32767, 65507, 65508

pingsizes = [ 1, 48, 64, 512, 1440, 1500, 1505, 4096, 4192, 
              32767, 65507 ]

from XmTestLib import *
rc = 0

# Test creates 1 domain, which requires 2 ips: 1 for the domains and 1 for
# aliases on dom0
if xmtest_netconf.canRunNetTest(2) == False:
    SKIP("Don't have enough free configured IPs to run this test")

domain = XmTestDomain()
domain.newDevice(XenNetDevice, "eth0")

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

try:
    console.setHistorySaveCmds(value=True)

    # First the loopback pings
    lofails=""
    for size in pingsizes:
        out = console.runCmd("ping -q -c 1 -s " + str(size) + " 127.0.0.1")
        if out["return"]:
            lofails += " " + str(size)

    # Next comes eth0
    eth0fails=""
    netdev = domain.getDevice("eth0")
    ip = netdev.getNetDevIP()
    for size in pingsizes:
        out = console.runCmd("ping -q -c 1 -s " + str(size) + " " + ip)
        if out["return"]:
            eth0fails += " " + str(size) 
except ConsoleError, e:
        FAIL(str(e))
except NetworkError, e:
        FAIL(str(e))

domain.stop()

# Tally up failures
failures=""
if len(lofails):
        failures += "ping loopback failed for size" + lofails + ". "
if len(eth0fails):
        failures += "ping eth0 failed for size" + eth0fails + "."
if len(failures):
    FAIL(failures)

