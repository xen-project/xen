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

from Test import *
from Xm import *

class NetworkError(Exception):
    def __init__(self, msg):
        self.errMsg = msg

    def __str__(self):
        return str(self.errMsg)

def undo_dom0_alias(eth, ip):
    traceCommand("ip addr del " + ip + " dev " + eth)

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

    def calc_ip_address(self, dom, interface):
        # Generate an IP address from the dom# and eth#:
        #      169.254.(eth#+153).(dom#+10)
        ethnum = int(interface[len("eth"):])
        domnum = int(dom[len("dom"):])
        return "169.254."+ str(ethnum+153) + "." + str(domnum+10)

    def ip(self, dom, interface, todomname=None, toeth=None):
        newip = self.calc_ip_address(dom, interface)

        # If the testcase is going to talk to dom0, we need to add an 
        # IP address in the proper subnet
        if dom == "dom0":
            # The domain's vif is a convenient place to add to
            vifname = "vif" + str(domid(todomname)) + "." + toeth[3:]

            # register the exit handler FIRST, just in case
            atexit.register(undo_dom0_alias, vifname, newip)

            # add the alias
            status, output = traceCommand("ip addr add " + newip + 
                                              " dev " + vifname)
            if status:
                SKIP("\"ip addr add\" failed")
        return newip

    def mask(self, dom, interface):
        return "255.255.255.0"
