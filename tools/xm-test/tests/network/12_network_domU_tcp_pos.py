#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author:  <dykman@us.ibm.com>

# TCP tests to domU interface
#  - creates two guest domains
#  - sets up a single NIC on each on same subnet 
#  - conducts tcp tests to the domU IP address.

# hping2 $domU_IP -c 1 -d $size 
#   where $size = 1, 48, 64, 512, 1440, 1500, 1505, 
#                 4096, 4192, 32767, 65507, 65508

pingsizes = [ 1, 48, 64, 512, 1440, 1500, 1505, 4096, 4192, 16384, 24567, 
              32767, 65495 ]

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
src = netDomain()
src_console = src.getConsole()
dst = netDomain()

try:
    # Ping the victim over eth0
    fails=""
    dst_netdev = dst.getDevice("eth0")
    ip2 = dst_netdev.getNetDevIP()
    for size in pingsizes:
        out = src_console.runCmd("hping2 " + ip2 + " -E /dev/urandom -q -c 20 "
              + "--fast -d " + str(size) + " -N " + str(size))
        if out["return"]:
            fails += " " + str(size) 
            print out["output"]
except ConsoleError, e:
    FAIL(str(e))

src.stop()
dst.stop()

if len(fails):
    FAIL("TCP hping2 failed for size" + fails + ".")
