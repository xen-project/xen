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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd
# Copyright (C) 2008 Citrix Systems Inc.
#============================================================================
#
# Based closely on netif.py.
#

"""Support for virtual network interfaces, version 2.
"""

import os
import random
import re
import time

from xen.xend import XendOptions
from xen.xend.server.DevController import DevController
from xen.xend.XendError import VmError
from xen.xend.XendXSPolicyAdmin import XSPolicyAdminInstance
from xen.xend.xenstore.xstransact import xstransact
import xen.util.xsm.xsm as security

from xen.xend.XendLogging import log

xoptions = XendOptions.instance()

def randomMAC():
    """Generate a random MAC address.

    Uses OUI (Organizationally Unique Identifier) 00-16-3E, allocated to
    Xensource, Inc. The OUI list is available at
    http://standards.ieee.org/regauth/oui/oui.txt.

    The remaining 3 fields are random, with the first bit of the first
    random field set 0.

    @return: MAC address string
    """
    mac = [ 0x00, 0x16, 0x3e,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

class NetifController2(DevController):
    def __init__(self, vm):
        DevController.__init__(self, vm)

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        devid = self.allocateDeviceID()

        bridge = config.get('bridge')
        back_mac = config.get('back_mac')
        if not back_mac:
            if bridge:
                back_mac = "fe:ff:ff:ff:ff:ff"
            else:
                back_mac = randomMAC()
        front_mac = config.get('front_mac') or randomMAC()
        front_trust = config.get("trusted") or "0"
        back_trust = config.get("back_trusted") or "1"
        max_bypasses = config.get("max_bypasses") or "5"
        pdev = config.get('pdev')
        front_filter = config.get("front_filter_mac")
        if front_filter == None:
            if back_trust == "0":
                front_filter = "1"
            else:
                front_filter = "0"
        back_filter = config.get("filter_mac")
        if back_filter == None:
            if front_trust == "0":
                back_filter = "1"
            else:
                back_filter = "0"
        back = { 'mac': back_mac, 'remote-mac': front_mac,
                 'handle': "%i" % devid, 'local-trusted': back_trust,
                 'remote-trusted': front_trust, 'filter-mac': back_filter,
                 'max-bypasses': max_bypasses }

        front = { 'mac': front_mac, 'remote-mac': back_mac,
                  'local-trusted': front_trust, 'remote-trusted': back_trust,
                  'filter-mac': front_filter }

        if bridge:
            back['bridge'] = bridge

        if pdev:
            back['pdev'] = pdev
    
        return (devid, back, front)

    def getDeviceConfiguration(self, devid, transaction = None):
        """@see DevController.configuration"""

        if transaction is None:
            read_fn = xstransact.Read
        else:
            read_fn = transaction.read
        def front_read(x):
            return read_fn(frontpath + x)
        def back_read(x):
            return read_fn(backpath + x)
        
        result = DevController.getDeviceConfiguration(self, devid, transaction)

        dev = self.convertToDeviceNumber(devid)
        frontpath = self.frontendPath(dev) + "/"

        backpath = front_read("backend") + "/"

        front_mac = front_read("mac")
        back_mac = back_read("mac")

        front_trusted = back_read("remote-trusted")
        back_trusted = back_read("local-trusted")
        max_bypasses = back_read("max-bypasses")

        bridge = back_read("bridge")

        pdev = back_read("pdev")

        if front_mac:
            result["front_mac"] = front_mac
        if back_mac:
            result["back_mac"] = back_mac
        if front_trusted:
            result["front_trusted"] = front_trusted
        if back_trusted:
            result["back_trusted"] = back_trusted
        if bridge:
            result["bridge"] = bridge
        if pdev:
            result["pdev"] = pdev
        if max_bypasses:
            result["max-bypasses"] = max_bypasses
        return result

    def destroyDevice(self, devid, force):
        dev = self.convertToDeviceNumber(devid)
        self.writeBackend(dev, "online", "0")
        if force:
            self.writeBackend(dev, "shutdown-request", "force")
        else:
            self.writeBackend(dev, "shutdown-request", "normal")
        self.vm._removeVm("device/%s/%d" % (self.deviceClass, dev))
