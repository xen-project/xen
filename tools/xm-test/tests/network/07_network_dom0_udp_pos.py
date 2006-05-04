#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author:  <dykman@us.ibm.com>

# UDP tests to dom0.
#  - determines dom0 network
#  - creates a single guest domain
#  - sets up a single NIC on same subnet as dom0
#  - conducts hping2 udp tests to the dom0 IP address

# hping2 $dom0_IP -2 -c 1 -d $size
#   where $size = 1, 48, 64, 512, 1440, 1448, 1500, 1505,
#                 4096, 4192, 32767, 65507, 65508

trysizes = [ 1, 48, 64, 512, 1440, 1500, 1505, 4096, 4192, 
                32767, 65495 ]



from XmTestLib import *
rc = 0

Net = XmNetwork()

try:
    # read an IP address from the config
    ip     = Net.ip("dom1", "eth0")
    mask   = Net.mask("dom1", "eth0")
except NetworkError, e:
        FAIL(str(e))

# Fire up a guest domain w/1 nic
if ENABLE_HVM_SUPPORT:
    brg = "xenbr0"
    config = {"vif" : ['type=ioemu, bridge=%s' % brg]}
else:
    brg = None
    config = {"vif"  : ["ip=%s" % ip]}

domain = XmTestDomain(extraConfig=config)
try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

try:
    # Add a suitable dom0 IP address 
    dom0ip = Net.ip("dom0", "eth0", todomname=domain.getName(), toeth="eth0", bridge=brg)
except NetworkError, e:
        FAIL(str(e))

try:
    console.runCmd("ifconfig eth0 inet "+ip+" netmask "+mask+" up")

    # Ping dom0
    fails=""
    for size in trysizes:
        out = console.runCmd("hping2 " + dom0ip + " -E /dev/urandom -2 -q -c 20"
             + " --fast -d " + str(size))
        if out["return"]:
            fails += " " + str(size) 
            print out["output"]
except ConsoleError, e:
        FAIL(str(e))

if len(fails):
    FAIL("UDP hping2 to dom0 failed for size" + fails + ".")

