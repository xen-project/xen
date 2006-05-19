#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author:  <dykman@us.ibm.com>

# TCP tests to dom0.
#  - determines dom0 network
#  - creates a single guest domain
#  - sets up a single NIC on same subnet as dom0
#  - conducts hping2 tcp tests to the dom0 IP address

# hping2 $dom0_IP -c 1 -d $size
#   where $size = 1, 48, 64, 512, 1440, 1448, 1500, 1505,
#                 4096, 4192, 32767, 65507, 65508

trysizes = [ 1, 48, 64, 512, 1440, 1500, 1505, 4096, 4192, 
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
    console.setHistorySaveCmds(value=True)
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

try:
    # Ping dom0
    fails=""
    netdev = domain.getDevice("eth0")
    dom0ip = netdev.getDom0AliasIP()
    for size in trysizes:
        out = console.runCmd("hping2 " + dom0ip + " -E /dev/urandom -q -c 20 "
              + "--fast -d " + str(size) + " -N " + str(size))
        if out["return"]:
            fails += " " + str(size) 
            print out["output"]
except ConsoleError, e:
        FAIL(str(e))

domain.stop()

if len(fails):
    FAIL("TCP hping2 to dom0 failed for size" + fails + ".")
