#!/usr/bin/python
"""
 Copyright (C) International Business Machines Corp., 2005
 Author: Stefan Berger <stefanb@us.ibm.com>

 Based on XenDomain.py by Dan Smith <danms@us.ibm.com>

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
import os
import sys
from XmTestLib import *
from types import DictType
from acm import *


class XenAPIConfig:
    """An object to help create a VM configuration usable via Xen-API"""
    def __init__(self):
        self.opts = {}
        #Array to translate old option to new ones
        self.opttrlate = { 'name' : 'name_label' ,
                           'memory' : [ 'memory_static_max' ,
                                        'memory_static_min' ,
                                        'memory_dynamic_min',
                                        'memory_dynamic_max' ],
                           'kernel' : 'PV_kernel',
                           'ramdisk': 'PV_ramdisk',
                           'root'   : 'PV_args',
                           'extra'  : 'PV_args' }
        if isACMEnabled():
            #A default so every VM can start with ACM enabled
            self.opts["security_label"] = "ACM:xm-test:red"

    def setOpt(self, name, value):
        """Set an option in the config"""
        if name == "memory":
            value <<= 20
        if name == "root":
            value = "root=" + value
        if name in self.opttrlate.keys():
            _name = self.opttrlate[name]
        else:
            _name = name

        if isinstance(_name, list):
            for _n in _name:
                self.opts[_n] = value
        else:
            if not self.opts.get(_name) or \
               not _name in [ "PV_args" ]:
                self.opts[_name] = value
            else:
                self.opts[_name] += " " + value

    def getOpt(self, name):
        """Return the value of a config option"""
        if name in self.opts.keys():
            return self.opts[name]
        else:
            return None

    def setOpts(self, opts):
        """Batch-set options from a dictionary"""
        for k, v in opts.items():
            self.setOpt(k, v)

    def getOpts(self):
        return self.opts


class XenAPIDomain(XenDomain):

    def __init__(self, name=None, config=None):
        if name:
            self.name = name
        else:
            self.name = getUniqueName()

        self.config = config
        self.console = None
        self.netEnv = "bridge"

        self.session = xapi.connect()
        try:
            self.vm_uuid = self.session.xenapi.VM.create(self.config.getOpts())
            addXAPIDomain(self.vm_uuid)
        except:
            raise DomainError("Could not create VM config file for "
                              "managed domain.")

        #Only support PV for now.
        self.type = "PV"

    def start(self, noConsole=False, startpaused=False):
        #start the VM
        session = self.session
        if self.vm_uuid:
            try:
                session.xenapi.VM.start(self.vm_uuid, startpaused)
            except:
                raise DomainError("Could not start domain")
        else:
            raise DomainError("VM has no UUID - does VM config exist?")

        if startpaused:
           return

        if self.getDomainType() == "HVM":
           waitForBoot()

        if self.console and noConsole == True:
            self.closeConsole()

        elif self.console and noConsole == False:
            return self.console

        elif not self.console and noConsole == False:
            return self.getConsole()

    def stop(self):
        if self.vm_uuid:
            self.session.xenapi.VM.hard_shutdown(self.vm_uuid)
        else:
            raise DomainError("VM has no UUID - does VM config exist?")

    def destroy(self):
        #Stop VM first.
        self.stop()
        if self.vm_uuid:
            self.session.xenapi.VM.destroy(self.vm_uuid)
            delXAPIDomain(self.vm_uuid)
        else:
            raise DomainError("VM has no UUID - does VM config exist?")

    def get_uuid(self):
        return self.vm_uuid

    def newDevice(self, Device, *args):
        raise DomainError("No support for newDevice().")

    def removeDevice(self, id):
        raise DomainError("No support for removeDevice().")

    def removeAllDevices(self, id):
        raise DomainError("No support for removeAllDevices().")

    def isRunning(self):
        return isDomainRunning(self.name)

    def getDevice(self, id):
        raise DomainError("No support for getDevice().")


class XmTestAPIDomain(XenAPIDomain):

    """Create a new managed xm-test domain
    @param name: The requested domain name
    @param extraConfig: Additional configuration options
    @param baseConfig: The initial configuration defaults to use
    """
    def __init__(self, name=None, extraConfig=None,
                 baseConfig=arch.configDefaults):
        config = XenAPIConfig()
        config.setOpts(baseConfig)
        if extraConfig:
            config.setOpts(extraConfig)

        if name:
            config.setOpt("name_label", name)
        elif not config.getOpt("name_label"):
            config.setOpt("name_label", getUniqueName())

        XenAPIDomain.__init__(self, config.getOpt("name_label"),
                              config=config)
