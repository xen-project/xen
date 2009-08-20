#!/usr/bin/python
#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2009 flonatel GmbH & Co. KG
#============================================================================
#
# Author: Andreas Florath <xen@flonatel.org>
# Loosly based on the original testcase from 
#   Tom Wilkie <tom.wilkie@gmail.com>
#
# This test case creates two guest systems, creates a (very) private
# network between them and attaches the ethernet apropriate.
# Note: in this test case there are some fixed IP and network
# addresses used.  This is not a problem, because those are really
# used only for local communication.
# 

import sys
import time

from XmTestLib import *
from XmTestLib.network_utils import *
from XmTestLib.XenAPIDomain import XmTestAPIDomain

# Some config for this testcase
class TCConfig:
    network_name = "xapi-network-xm-test-03"

    ip_addr_1 = "172.16.77.70"
    ip_addr_2 = "172.16.77.71"
    default_gateway = "172.16.77.72"
    default_netmask = "255.255.255.0"

    @staticmethod
    def remove_network(guest):
        nw = guest.session.xenapi.network.get_all()
        for n in nw:
            name = guest.session.xenapi.network.get_name_label(n)
            if name == TCConfig.network_name:
                guest.session.xenapi.network.destroy(n)


# Create two domains (default XmTestDomain, with our ramdisk)
try:
    guest1 = XmTestAPIDomain()
    console1 = guest1.start()
#    guest1.newDevice(XenNetDevice, "eth0")    
#    guest1_netdev = guest1.getDevice("eth0")
    guest2 = XmTestAPIDomain()
    console2 = guest2.start()
except DomainError, e:
    if verbose:
        print("Failed to create test domain because: %s" % e.extra)
    FAIL(str(e))

# Clean up relicts
TCConfig.remove_network(guest1)

# Create a network
network = guest1.session.xenapi.network.create(
    { "name_label": TCConfig.network_name,
      "name_description": "This is a testing network",
      "default_gateway": TCConfig.default_gateway,
      "default_netmask": TCConfig.default_netmask,
      "other_config": {} } )

# Attach two domains to it
status, msg = network_attach(
    guest1.getName(), console1, bridge=TCConfig.network_name)
if status:
    FAIL(msg)

status, msg = network_attach(
    guest2.getName(), console2, bridge=TCConfig.network_name)
if status:
    FAIL(msg)

# Configure IP addresses on two guests
try:
    run = console1.runCmd(
        "ifconfig eth0 " + TCConfig.ip_addr_1
        + " netmask " + TCConfig.default_netmask + " up")
    run = console2.runCmd(
        "ifconfig eth0 " + TCConfig.ip_addr_2
        + " netmask " + TCConfig.default_netmask + " up")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

# Now ping...
try:
    run = console1.runCmd("ping -c 4 " + TCConfig.ip_addr_2)
    if run['return'] > 0:
        FAIL("Could not ping other host")
    run = console2.runCmd("ping -c 4 " + TCConfig.ip_addr_1)
    if run['return'] > 0:
        FAIL("Could not pint other host")
except ConsoleError, e:
    saveLog(console.getHistory())
    FAIL(str(e))

status, msg = network_detach(guest1.getName(), console1)
status, msg = network_detach(guest2.getName(), console2)

# Clean up
TCConfig.remove_network(guest1)
guest1.closeConsole()
guest1.stop()
guest2.closeConsole()
guest2.stop()

