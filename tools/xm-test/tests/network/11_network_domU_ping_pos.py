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

def netDomain(ip):
    if ENABLE_HVM_SUPPORT:
        config = {"vif" : ['type=ioemu']}
    else:
        config = {"vif" : ['ip=%s' % ip ]}

    dom = XmTestDomain(extraConfig=config)
    try:
        dom.start()
    except DomainError, e:
        if verbose:
            print "Failed to create test domain because:"
            print e.extra
        FAIL(str(e))
    try:
        # Attach a console
        console = XmConsole(dom.getName(), historySaveCmds=True)
        # Activate the console
        console.sendInput("bhs")
    except ConsoleError, e:
        FAIL(str(e))
    return console
    
rc = 0

Net = XmNetwork()

try:
    # pick an IP address 
    ip1   = Net.ip("dom1", "eth2")
    mask1 = Net.mask("dom1", "eth2")
except NetworkError, e:
    FAIL(str(e))

try:
    # pick another IP address 
    ip2   = Net.ip("dom2", "eth2")
    mask2 = Net.mask("dom2", "eth2")
except NetworkError, e:
    FAIL(str(e))

# Fire up a pair of guest domains w/1 nic each
pinger_console = netDomain(ip1)
victim_console = netDomain(ip2)

try:
    pinger_console.runCmd("ifconfig eth0 inet "+ip1+" netmask "+mask1+" up")
    victim_console.runCmd("ifconfig eth0 inet "+ip2+" netmask "+mask2+" up")

    # Ping the victim over eth0
    fails=""
    for size in pingsizes:
        out = pinger_console.runCmd("ping -q -c 1 -s " + str(size) + " " + ip2)
        if out["return"]:
            fails += " " + str(size) 
except ConsoleError, e:
    FAIL(str(e))

if len(fails):
    FAIL("Ping failed for size" + fails + ".")

