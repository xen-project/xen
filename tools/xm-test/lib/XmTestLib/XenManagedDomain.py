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
from xen.util.xmlrpclib2 import ServerProxy
from types import DictType


class XenManagedConfig:
    """An object to help create a VM configuration usable via Xen-API"""
    def __init__(self):
        self.opts = {}
        #Array to translate old option to new ones
        self.opttrlate = { 'name' : 'name_label' ,
                           'memory' : [ 'memory_static_max' ,
                                        'memory_static_min' ,
                                        'memory_dynamic_min',
                                        'memory_dynamic_max' ],
                           'kernel' : 'kernel_kernel',
                           'ramdisk': 'kernel_initrd',
                           'root'   : 'kernel_args'}

    def setOpt(self, name, value):
        """Set an option in the config"""
        if name in self.opttrlate.keys():
            _name = self.opttrlate[name]
        else:
            _name = name

        if isinstance(_name, list):
            for _n in _name:
                self.opts[_n] = value
        else:
            self.opts[_name] = value

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


class XenManagedDomain(XenDomain):

    def __init__(self, name=None, config=None):
        if name:
            self.name = name
        else:
            self.name = getUniqueName()

        self.config = config
        self.console = None
        self.netEnv = "bridge"

        self.server, self.session = xapi._connect()
        server = self.server
        try:
            self.vm_uuid = xapi.execute(server.VM.create, self.session,
                                        self.config.getOpts())
            xapi._VMuuids.append(self.vm_uuid)
        except:
            raise DomainError("Could not create VM config file for "
                              "managed domain.")

        #Only support PV for now.
        self.type = "PV"

    def start(self, noConsole=False, startpaused=False):
        #start the VM
        server = self.server
        if self.vm_uuid:
            try:
                xapi.execute(server.VM.start, self.session, self.vm_uuid,
                             startpaused)
            except:
                raise DomainError("Could not start domain")
        else:
            raise DomainError("VM has not UUID - VM config does not exist?")

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
            server = self.server
            xapi.execute(server.VM.hard_shutdown, self.session, self.vm_uuid)
        else:
            raise DomainError("VM has not UUID - VM config does not exist?")

    def destroy(self):
        #Stop VM first.
        self.stop()
        if self.vm_uuid:
            server = self.server
            xapi.execute(server.VM.destroy, self.session, self.vm_uuid)
            xapi._VMuuids.remove(self.vm_uuid)
        else:
            raise DomainError("VM has not UUID - VM config does not exist?")

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


class XmTestManagedDomain(XenManagedDomain):

    """Create a new managed xm-test domain
    @param name: The requested domain name
    @param extraConfig: Additional configuration options
    @param baseConfig: The initial configuration defaults to use
    """
    def __init__(self, name=None, extraConfig=None,
                 baseConfig=arch.configDefaults):
        config = XenManagedConfig()
        config.setOpts(baseConfig)
        if extraConfig:
            config.setOpts(extraConfig)

        if name:
            config.setOpt("name_label", name)
        elif not config.getOpt("name_label"):
            config.setOpt("name_label", getUniqueName())

        XenManagedDomain.__init__(self, config.getOpt("name_label"),
                                  config=config)
