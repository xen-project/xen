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

from Xm import *
from Test import *
from config import *
from XenDomain import *
from NetConfig import *
from XmTestLib import *
from __init__ import *

class XenNetDevCmd:

    def __init__(self, netDevice, addCmd, removeCmd):
        """Object representing a network device command"""
        self.addcmd = addCmd
        self.removecmd = removeCmd
        self.addhasrun = False
        self.rmvhasrun = False
        self.netdevice = netDevice

    def getAddCmd(self):
        return self.addcmd

    def getRemoveCmd(self):
        return self.removecmd

    def hasAddRun(self):
        return self.addhasrun

    def hasRemoveRun(self):
        self.rmvhasrun

    def runAddCmd(self, runOnDom0=False):
        # Defaults running command on dom0, if console then will run there
        if runOnDom0 == False:
            dom = self.netdevice.getDomain()
            console = dom.getConsole()
            console.runCmd(self.addcmd)
        else:
            status, output = traceCommand(self.addcmd)
            if status:
                raise NetworkError("Device add cmd failed: %s Status: %d"
                                   % (self.addcmd, status))
        self.addhasrun = True

    def runRemoveCmd(self, runOnDom0=False):
        # Defaults running command on dom0, if console then will run there
        if runOnDom0 == False:
            dom = self.netdevice.getDomain()
            console = dom.getConsole()
            console.runCmd(self.removecmd)
        else:
            status, output = traceCommand(self.removecmd)
            if status:
                raise NetworkError("Device remove cmd failed: %s Status: %d"
                                   % (self.removecmd, status))
        self.removehasrun = True

class XenDevice:

    def __init__(self, domain, id, devConfig=None):
        """An object to represent Xen Devices like network and block
        @param domain: Domain the device will be added to
        @param id: Device identifier
        @param devConfig: Initial configuration dictionary for XenDevice
        """
        if config:
            self.config = devConfig
        else:
            self.config = {}

        self.id = id
        self.domain = domain
        self.configNode = None
        # Commands run when domain is started or devices added and removed.
        self.dom0_cmds = []
        self.domU_cmds = []

    def __str__(self):
        """Convert device config to XenConfig node compatible string"""
        confstr = ''
        for k, v in self.config.items():
            if len(confstr) > 0:
                confstr += ', '
            if isinstance(v, int):
                confstr += "%s=%i" % (k, v)
            elif isinstance(v, list) and v:
                confstr += "%s=%s" % (k, v)
            elif isinstance(v, str) and v:
                confstr += "%s=%s" % (k, v)

        return confstr

    def execAddCmds(self):
        # Cmds for when a device is added to the system
        if len(self.dom0_cmds) > 0:
            for i in range(0, len(self.dom0_cmds)):
                if self.dom0_cmds[i].getAddCmd():
                    self.dom0_cmds[i].runAddCmd(runOnDom0=True)

        if len(self.domU_cmds) > 0:
            for i in range(0, len(self.domU_cmds)):
                if self.domU_cmds[i].getAddCmd():
                    self.domU_cmds[i].runAddCmd()

    def execRemoveCmds(self):
        # Cmds for when a device is removed from the system
        if len(self.dom0_cmds) > 0:
            for i in range(0, len(self.dom0_cmds)):
                if (self.dom0_cmds[i].getRemoveCmd() 
                    and self.dom0_cmds[i].hasAddRun() == True):
                    self.dom0_cmds[i].runRemoveCmd(runOnDom0=True)

        if len(self.domU_cmds) > 0:
            for i in range(0, len(self.domU_cmds)):
                if (self.domU_cmds[i].getRemoveCmd()
                    and self.domU_cmds[i].hasAddRun() == True):
                    self.domU_cmds[i].runRemoveCmd()

    def removeDevice(self):
        self.execRemoveCmds()

    def getId(self):
        return self.id

    def getConfigOpt(self):
        return self.configNode

    def getDomain(self):
        return self.domain

class XenNetDevice(XenDevice):

    def __init__(self, domain, id, devConfig=None):
        """An object to represent Xen Network Device
        @param domain: Domain the device is being added to
        @param id: Network device identifier, interface name like eth0
        @param devConfig: Initial dictionary configuration for XenNetDevice
        """
        if devConfig:
            self.config = devConfig
        else:
            self.config = {}

        self.id = id
        self.domain = domain
        self.configNode = "vif"
        self.dom0_cmds = []
        self.domU_cmds = []
        self.network = None
        self.netmask = None
        self.ip = None
        self.dom0_alias_ip = None

        if domain.getDomainType() == "HVM":
            self.config["type"] = "ioemu"
            if not self.config.has_key('bridge'):
                self.config["bridge"] = "xenbr0"

        if self.config.has_key("ip"):
            self.setNetDevIP(ip=self.config["ip"])
        else:
            if NETWORK_IP_RANGE != "dhcp":
                self.setNetDevIP()

    def __del__(self):
        # Make sure we clean up NetConfig's list of ips, so the ip can be
        # reused
        self.releaseNetDevIP()

    def addIfconfigCmd(self, domU=True):
        # Method to add start and remove ifconfig functions
        if domU == True:
            locmd = XenNetDevCmd(self, addCmd="ifconfig lo 127.0.0.1", removeCmd=None)
        ifcmd = []


        # Start or Add cmd
        acmd = 'ifconfig %s inet %s netmask %s up' % (self.id, self.ip, self.netmask)
        rcmd = 'ifconfig %s down' % self.id
        ifcmd = XenNetDevCmd(self, addCmd=acmd, removeCmd=rcmd)

        if domU == True:
            self.domU_cmds.append(locmd) 
            self.domU_cmds.append(ifcmd) 
        else:
            self.dom0_cmds.append(ifcmd) 

    def removeDevice(self):
        self.releaseNetDevIP()

    def addDom0AliasCmd(self, dev="vif0.0"):
        # Method to add start and remove dom0 alias cmds
        acmd = 'ip addr add %s dev %s' % (self.dom0_alias_ip, dev)
        rcmd = 'ip addr del %s dev %s' % (self.dom0_alias_ip, dev) 
        aliascmd = XenNetDevCmd(self, addCmd=acmd, removeCmd=rcmd)

        self.dom0_cmds.append(aliascmd)

    def releaseNetDevIP(self):
        # Must remove start cmds for ip configuration and then release from
        # NetConfig
        self.execRemoveCmds()
        self.dom0_cmds = []
        self.domU_cmds = []
        if self.config.has_key("ip"):
            del self.config["ip"]

        if self.dom0_alias_ip:
                xmtest_netconf.releaseIP("domain0", self.domain.getName(), self.dom0_alias_ip)
        xmtest_netconf.releaseIP(self.domain.getName(), self.id, self.ip)

    def getNetDevIP(self):
        return self.ip

    def getDom0AliasIP(self):
        return self.dom0_alias_ip

    def getNetwork(self):
        return self.network

    def setNetDevIP(self, ip=None):
        # Function to set a new IP for NetDevice.
        if NETWORK_IP_RANGE == "dhcp":
            raise NetworkError("System configured for dhcp, cannot set new ip.")

        if (self.ip and not ip) or ((self.ip and ip) and (self.ip != ip)): 
            self.releaseNetDevIP()

        if not self.netmask:
            self.netmask = xmtest_netconf.getNetMask()

        if not self.network:
            self.network = xmtest_netconf.getNetwork()

        if ip:
            xmtest_netconf.setIP(self.domain.getName(), self.id, ip)
            self.ip = ip
        else:
            self.ip = xmtest_netconf.getIP(self.domain.getName(), self.id)

        self.addIfconfigCmd()
        self.config["ip"] = str(self.ip)

        # Setup an alias for Dom0
        self.dom0_alias_ip = xmtest_netconf.getIP("domain0", self.domain.getName())
        self.addDom0AliasCmd()
