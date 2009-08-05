#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Copyright (C) flonatel GmbH & Co. KG, 2009
# Authors:  <dykman@us.ibm.com>
#           Andreas Florath <xen@flonatel.org>

# UDP tests to domU interface
#  - creates two guest domains
#  - sets up a single NIC on each on same subnet 
#  - conducts udp tests to the domU IP address.

# hping2 $domU_IP -1 -c 7 -d $size  
#   where $size = 1, 48, 64, 512, 1440, 1500, 1505, 
#                 4096, 4192, 32767, 65507, 65508

pingsizes = [ 1, 48, 64, 512, 1440, 1500, 1505, 4096, 4192, 
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
    
fails = ""

# Test creates 2 domains, which requires 4 ips: 2 for the domains and 2 for
# aliases on dom0
if xmtest_netconf.canRunNetTest(4) == False:
    SKIP("Don't have enough free configured IPs to run this test")

# Fire up a pair of guest domains w/1 nic each
guest1 = netDomain()
guest1_console = guest1.getConsole()
guest1_netdev = guest1.getDevice("eth0")
guest1_ip = guest1_netdev.getNetDevIP()
guest1_dom0_alias_ip = guest1_netdev.dom0_alias_ip
guest2 = netDomain()
guest2_console = guest2.getConsole()
guest2_netdev = guest2.getDevice("eth0")
guest2_ip = guest2_netdev.getNetDevIP()
guest2_dom0_alias_ip = guest2_netdev.dom0_alias_ip

def hping_cmd(ip, size):
    return "hping2 " + ip + " -E /dev/urandom -1 -q " \
             + "-c 7 --fast -d " + str(size) + " -N " + str(size)

# Ping everything from guests
try:
    for size in pingsizes:
        for console in [(guest1_console, "Guest1Console"),
                        (guest2_console, "Guest2Console")]:
            for dest_ip in [guest1_ip, guest1_dom0_alias_ip,
                            guest2_ip, guest2_dom0_alias_ip ]:
                out = console[0].runCmd(hping_cmd(dest_ip, size))
                if out["return"]:
                    fails += " [%d, %s, %s]" % (size, console[1], dest_ip)
except ConsoleError, e:
    FAIL(str(e))

guest1.stop()
guest2.stop()

if len(fails):
    FAIL("UDP hping2 failed for size" + fails + ".")
