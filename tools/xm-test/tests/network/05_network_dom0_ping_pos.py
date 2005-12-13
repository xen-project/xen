#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author:  <dykman@us.ibm.com>

# Ping tests to dom0 interface
#  - determines dom0 network
#  - creates a single guest domain
#  - sets up a single NIC on same subnet as dom0
#  - conducts ping tests to the dom0 IP address.

# ping -c 1 -s $size $dom0_IP 
#   where $size = 1, 48, 64, 512, 1440, 1500, 1505, 
#                 4096, 4192, 32767, 65507, 65508

pingsizes = [ 1, 48, 64, 512, 1440, 1500, 1505, 4096, 4192, 
                32767, 65507 ]



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
config = {"vif"  : ["ip=%s" % ip]}
domain = XmTestDomain(extraConfig=config)
try:
    domain.start()
except DomainError, e:
    if verbose:
        print "Failed to create test domain because:"
        print e.extra
    FAIL(str(e))


# Attach a console
try:
    console = XmConsole(domain.getName(), historySaveCmds=True)
    # Activate the console
    console.sendInput("bhs")
except ConsoleError, e:
    FAIL(str(e))

try:
    # Add a suitable dom0 IP address 
    dom0ip = Net.ip("dom0", "eth0", todomname=domain.getName(), toeth="eth0")
except NetworkError, e:
        FAIL(str(e))

try:
    console.runCmd("ifconfig eth0 inet "+ip+" netmask "+mask+" up")

    # Ping dom0
    fails=""
    for size in pingsizes:
        out = console.runCmd("ping -q -c 1 -s " + str(size) + " " + dom0ip)
        if out["return"]:
            fails += " " + str(size) 
except ConsoleError, e:
        FAIL(str(e))

if len(fails):
    FAIL("Ping to dom0 failed for size" + fails + ".")

