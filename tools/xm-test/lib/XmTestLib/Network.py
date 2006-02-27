#!/usr/bin/python
"""
 Network.py - Common utilities for network tests

 Copyright (C) International Business Machines Corp., 2005
 Author: Jim Dykman <dykman@us.ibm.com>

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; under version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""
import sys;
import os;
import atexit;
import random;

from Test import *
from Xm import *
from config import *

class NetworkError(Exception):
    def __init__(self, msg):
        self.errMsg = msg

    def __str__(self):
        return str(self.errMsg)

def undo_dom0_alias(eth, ip):
    traceCommand("ip addr del " + ip + " dev " + eth)

def net_from_ip(ip):
    return ip[:ip.rfind(".")] + ".0/24"
    
class XmNetwork:

    def __init__(self):
        # Check for existing zeroconf address. We are using the zeroconf 
        # address range as static IP addresses.... if someone is using 
        # real zeroconf addresses, then we're going to skip tests to 
        # avoid interfering with them.
        rc, out = traceCommand(
                  "ip addr show |grep \"inet 169.254\" | grep -v vif")

        if rc == 0:
            SKIP("Zeroconf address found: " + out)

        # Randomize one octet of the IP addresses we choose, so that
        # multiple machines running network tests don't interfere 
        # with each other. 
        self.subnet = random.randint(1,254)

    def calc_ip_address(self, dom, interface):
        # Generate an IP address from the dom# and eth#:
        #      169.254.(self.subnet).(eth#)*16 + (dom# + 1)
        ethnum = int(interface[len("eth"):])
        if (ethnum > 15):
            raise NetworkError("ethnum > 15 : " + interface)
        domnum = int(dom[len("dom"):])
        if (domnum > 14):
            raise NetworkError("domnum > 14 : " + dom)

        return "169.254."+ str(self.subnet) + "." + str(ethnum*16+domnum+1)

    def ip(self, dom, interface, todomname=None, toeth=None, bridge=None):
        newip = self.calc_ip_address(dom, interface)

        # If the testcase is going to talk to dom0, we need to add an 
        # IP address in the proper subnet
        if dom == "dom0":
	    if ENABLE_HVM_SUPPORT:
	        # HVM uses ioemu which uses a bridge
		if not bridge:
		    SKIP("no bridge supplied")
		else:
		    vifname = bridge
	    else:
                # The domain's vif is a convenient place to add to
                vifname = "vif" + str(domid(todomname)) + "." + toeth[3:]

            # register the exit handler FIRST, just in case
            atexit.register(undo_dom0_alias, vifname, newip)

            # add the alias
            status, output = traceCommand("ip addr add " + newip + 
                                              " dev " + vifname)
            if status:
                SKIP("\"ip addr add\" failed")

	    if ENABLE_HVM_SUPPORT:
	        # We need to add a route to the bridge device
		network = net_from_ip(newip)
		status, output = traceCommand("ip route add " + network + " dev " + vifname + " scope link")

                if status:
		    SKIP("\"ip route add\" failed")

        return newip

    def mask(self, dom, interface):
        return "255.255.255.240"
