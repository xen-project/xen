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

Net = XmNetwork()

try:
    # read an IP address from the config
    ip   = Net.ip("dom1", "eth0")
    mask = Net.mask("dom1", "eth0")
except NetworkError, e:
    FAIL(str(e))

# Fire up a guest domain w/1 nic
if ENABLE_HVM_SUPPORT:
    brg = "xenbr0"
    config = {"vif" : ['type=ioemu, bridge=%s' % brg]}
else:
    brg = None
    config = {"vif" : ['ip=%s' % ip]}

domain = XmTestDomain(extraConfig=config)
try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))

try:
    # Bring up the "lo" interface.
    console.runCmd("ifconfig lo 127.0.0.1")

    console.runCmd("ifconfig eth0 inet "+ip+" netmask "+mask+" up")

    # First do loopback 
    lofails=""
    for size in trysizes:
        out = console.runCmd("hping2 127.0.0.1 -E /dev/urandom -q -c 20 " 
              + "--fast -d " + str(size))
        if out["return"]:
            lofails += " " + str(size)

    # Next comes eth0
    eth0fails=""
    for size in trysizes:
        out = console.runCmd("hping2 " + ip + " -E /dev/urandom -q -c 20 "
              + "--fast -d "+ str(size))
        if out["return"]:
            eth0fails += " " + str(size) 
except ConsoleError, e:
        FAIL(str(e))
except NetworkError, e:
        FAIL(str(e))


# Tally up failures
failures=""
if len(lofails):
        failures += "TCP hping2 over loopback failed for size" + lofails + ". "
if len(eth0fails):
        failures += "TCP hping2 over eth0 failed for size" + eth0fails + "."
if len(failures):
    FAIL(failures)

