#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author:  <dykman@us.ibm.com>

# TCP tests on local interfaces.
#  - creates a single guest domain
#  - sets up a single NIC
#  - conducts hping tcp tests to the local loopback and IP address

# hping2 127.0.0.1 -c 1 -d $size
# hping2 $local_IP -c 1 -d $size
#   where $size = 1, 48, 64, 512, 1440, 1448, 1500, 1505,
#                 4096, 4192, 32767, 65507, 65508


trysizes = [ 1, 48, 64, 512, 1440, 1448, 1500, 1505, 4096, 4192, 
              32767, 65495 ]

from XmTestLib import *
rc = 0

# Test creates 1 domain, which requires 2 ips: 1 for the domains and 1 for
# aliases on dom0
if xmtest_netconf.canRunNetTest(2) == False:
    SKIP("Don't have enough free configured IPs to run this test")

# Fire up a guest domain w/1 nic
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

    # First do loopback 
    lofails=""
    for size in trysizes:
        out = console.runCmd("hping2 127.0.0.1 -E /dev/urandom -q -c 20 " 
              + "--fast -d " + str(size) + " -N " + str(size))
        if out["return"]:
            lofails += " " + str(size)

    # Next comes eth0
    eth0fails=""
    netdev = domain.getDevice("eth0")
    ip = netdev.getNetDevIP()
    for size in trysizes:
        out = console.runCmd("hping2 " + ip + " -E /dev/urandom -q -c 20 "
              + "--fast -d "+ str(size) + " -N " + str(size))
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
        failures += "TCP hping2 over loopback failed for size" + lofails + ". "
if len(eth0fails):
        failures += "TCP hping2 over eth0 failed for size" + eth0fails + "."
if len(failures):
    FAIL(failures)

