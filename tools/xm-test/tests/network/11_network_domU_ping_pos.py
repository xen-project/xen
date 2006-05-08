#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author:  <dykman@us.ibm.com>

# Ping tests to domU interface
#  - creates two guest domains
#  - sets up a single NIC on each on same subnet 
#  - conducts ping tests to the domU IP address.

# ping -c 1 -s $size $domU_IP 
#   where $size = 1, 48, 64, 512, 1440, 1500, 1505, 
#                 4096, 4192, 32767, 65507, 65508

pingsizes = [ 1, 48, 64, 512, 1440, 1500, 1505, 4096, 4192, 
              32767, 65507 ]

from XmTestLib import *

def netDomain():

    dom = XmTestDomain()
    dom.newDevice(XenNetDevice, "eth0")
    try:
        console = dom.start()
        console.setHistorySaveCmds(value=True)
    except DomainError, e:
        if verbose:
            print "Failed to create test domain because:"
            print e.extra
        FAIL(str(e))
    return dom
    
rc = 0

# Test creates 2 domains, which requires 4 ips: 2 for the domains and 2 for
# aliases on dom0
if xmtest_netconf.canRunNetTest(4) == False:
    SKIP("Don't have enough free configured IPs to run this test")

# Fire up a pair of guest domains w/1 nic each
pinger = netDomain()
pinger_console = pinger.getConsole()
victim = netDomain()

try:
    # Ping the victim over eth0
    fails=""
    v_netdev = victim.getDevice("eth0")
    ip2 = v_netdev.getNetDevIP()
    for size in pingsizes:
        out = pinger_console.runCmd("ping -q -c 1 -s " + str(size) + " " + ip2)
        if out["return"]:
            fails += " " + str(size) 
except ConsoleError, e:
    FAIL(str(e))

pinger.stop()
victim.stop()

if len(fails):
    FAIL("Ping failed for size" + fails + ".")
