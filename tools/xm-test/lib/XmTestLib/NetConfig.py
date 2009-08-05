#!/usr/bin/python
"""
 Copyright (C) International Business Machines Corp., 2005, 2006
 Authors: Dan Smith <danms@us.ibm.com>
          Daniel Stekloff <dsteklof@us.ibm.com>

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

import sys
import commands
import os
import re
import time
import random
from xen.xend.sxp import Parser

from Xm import *
from Test import *
from config import *

class NetworkError(Exception):
    def __init__(self, msg):
        self.errMsg = msg

    def __str__(self):
        return str(self.errMsg)

def getXendNetConfig():
    # Find out what environment we're in: bridge, nat, or route
    xconfig = os.getenv("XEND_CONFIG")
    if not xconfig:
        xconfig = "/etc/xen/xend-config.sxp"

    try:
        configfile = open(xconfig, 'r')
    except:
        return "bridge"
    
    S = configfile.read()
    pin = Parser()
    pin.input(S)
    pin.input_eof()
    val = pin.get_val()
    while val[0] != 'network-script':
        val = pin.get_val()

    # split network command into script name and its parameters
    sub_val = val[1].split()
    if sub_val[0] == "network-bridge":
        netenv = "bridge"
    elif sub_val[0] == "network-route":
        netenv = "route"
    elif sub_val[0] == "network-nat":
        netenv = "nat"
    else:
        raise NetworkError("Failed to get network env from xend config")

    configfile.close()
    return netenv

class NetConfig:

    def __init__(self):
        self.netenv = getXendNetConfig()
        self.used_ips = {}
        self.free_oct_ips = [ 0, 0, 0, 0 ]
        self.total_ips = 0

        if NETWORK_IP_RANGE == 'dhcp':
            self.netmask = NETWORK_IP_RANGE
            self.network = NETWORK_IP_RANGE
            self.max_ip = NETWORK_IP_RANGE
            self.min_ip = NETWORK_IP_RANGE
        else:
            self.netmask = NETMASK
            self.network = NETWORK
            s_ip = ''

            # Get starting ip and max ip from configured ip range
            s_ip = NETWORK_IP_RANGE
            ips = s_ip.split("-")
            self.max_ip = ips[1]
            self.min_ip = ips[0]

            self.__setMaxNumberIPs()

            # Clean out any aliases in the network range for dom0's interface.
            # If an alias exists, a test xendevice add command could fail.
            if NETWORK_IP_RANGE != "dhcp":
                self.__cleanDom0Aliases()

    def __setMaxNumberIPs(self):
        # Count the number of IPs available, to help tests know whether they
        # have enough to run or not
        masko = self.netmask.split('.')
        maxo = self.max_ip.split('.')
        mino = self.min_ip.split('.')
        ips = 0

        # Last octet
        self.free_oct_ips[3] = (int(maxo[3]) - int(mino[3])) + 1

        # 3rd octet
        self.free_oct_ips[2] = (int(maxo[2]) - int(mino[2])) + 1

        # 2nd octet
        self.free_oct_ips[1] = (int(maxo[1]) - int(mino[1])) + 1

        # 1st octet
        self.free_oct_ips[0] = (int(maxo[0]) - int(mino[0])) + 1

        self.total_ips = self.free_oct_ips[3]
        if self.free_oct_ips[2] > 1:
            self.total_ips = (self.total_ips * self.free_oct_ips[2])
        if self.free_oct_ips[1] > 1:
            self.total_ips = (self.total_ips * self.free_oct_ips[1])
        if self.free_oct_ips[0] > 1:
            self.total_ips = (self.total_ips * self.free_oct_ips[0])

    def __cleanDom0Aliases(self):
        # Remove any aliases within the supplied network IP range on dom0
        scmd = 'ip addr show dev %s' % (DOM0_INTF)

        status, output = traceCommand(scmd)
        if status:
            raise NetworkError("Failed to show %s aliases: %d" %
                               (DOM0_INTF, status))

        lines = output.split("\n")
        for line in lines:
            ip = re.search('(\d+\.\d+\.\d+\.\d+)', line)
            if ip and self.isIPInRange(ip.group(1)) == True:
                dcmd = 'ip addr del %s/32 dev %s' % (ip.group(1), DOM0_INTF)
                dstatus, doutput = traceCommand(dcmd)
                if dstatus:
                    raise NetworkError("Failed to remove %s aliases: %d" %
                                       (DOM0_INTF, status))
                
    def getNetEnv(self):
        return self.netenv
 
    def setUsedIP(self, domname, interface, ip):
        self.used_ips['%s:%s' % (domname, interface)] = ip

    def __findFirstOctetIP(self, prefix, min, max):
        for i in range(min, max):
            ip = '%s%s' % (prefix, str(i))
            found = False
            for k in self.used_ips.keys():
                if self.used_ips[k] == ip:
                    found = True
            if found == False:
                return ip

        if found == True:
            return None

    def getFreeIP(self, domname, interface):
        # Get a free IP. It uses the starting ip octets and then the 
        # total number of allowed numbers for that octet. It only
        # calculates ips for the last two octets, we shouldn't need more
        start_octets = self.min_ip.split(".")
        ip = None

        # Only working with ips from last two octets, shouldn't need more
        max = int(start_octets[2]) + self.free_oct_ips[2]
        for i in range(int(start_octets[2]), max):
            prefix = '%s.%s.%s.' % (start_octets[0], start_octets[1], str(i))
            ip = self.__findFirstOctetIP(prefix, int(start_octets[3]), self.free_oct_ips[3])
            if ip:
                break

        if not ip:
            raise NetworkError("Ran out of configured addresses.")

        self.setUsedIP(domname, interface, ip)
        return ip

    def getNetMask(self):
        return self.netmask

    def getNetwork(self):
        return self.network

    def getIP(self, domname, interface):
        # Depending on environment, set an IP. Uses the configured range
        # of IPs, network address, and netmask
        if NETWORK_IP_RANGE == "dhcp":
            return None

        # Make sure domain and interface aren't already assigned an IP
        if self.used_ips.has_key('%s:%s' % (domname, interface)):
            raise NetworkError("Domain %s interface %s is already has IP"
                               % (domname, interface))

        return self.getFreeIP(domname, interface)

    def setIP(self, domname, interface, ip):
        # Make sure domain and interface aren't already assigned an IP
        if self.used_ips.has_key('%s:%s' % (domname, interface)):
            raise NetworkError("Domain %s interface %s is already has IP"
                               % (domname, interface))

        self.setUsedIP(domname, interface, ip)

    def releaseIP(self, domname, interface, ip):
        if self.used_ips.has_key('%s:%s' % (domname, interface)):
            del self.used_ips['%s:%s' % (domname, interface)]

    def getNumberAllowedIPs(self):
        return self.total_ips

    def canRunNetTest(self, ips):
        # Check to see if a test can run, returns true or false. Input is
        # number of ips needed.
        if NETWORK_IP_RANGE == "dhcp":
            return True

        if self.total_ips >= ips:
            return True

        return False

    def isIPInRange(self, ip):
        # Checks to see if supplied ip is in the range of allowed ips
        maxo = self.max_ip.split('.')
        mino = self.min_ip.split('.')
        ipo = ip.split('.')

        if int(ipo[0]) < int(mino[0]):
            return False
        elif int(ipo[0]) > int(maxo[0]):
            return False

        if int(ipo[1]) < int(mino[1]):
            return False
        elif int(ipo[1]) > int(maxo[1]):
            return False

        if int(ipo[2]) < int(mino[2]):
            return False
        elif int(ipo[2]) > int(maxo[2]):
            return False

        if int(ipo[3]) < int(mino[3]):
            return False
        elif int(ipo[3]) > int(maxo[3]):
            return False

        return True
