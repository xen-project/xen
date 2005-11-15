#!/usr/bin/python
"""
 Copyright (C) International Business Machines Corp., 2005
 Author: Dan Smith <danms@us.ibm.com>

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

from Xm import *
from Test import *
from config import *

BLOCK_ROOT_DEV = "hdd1"

def getDefaultKernel():
    dom0Ver = commands.getoutput("uname -r");
    domUVer = dom0Ver.replace("xen0", "xenU");
    
    return "/boot/vmlinuz-" + domUVer;


class DomainError(Exception):
    def __init__(self, msg, extra="", errorcode=0):
        self.msg = msg
        self.extra = extra
        try:
            self.errorcode = int(errorcode)
        except Exception, e:
            self.errorcode = -1
            
    def __str__(self):
        return str(self.msg)

class XenDomain:

    def __init__(self, opts={}, config="/dev/null"):
        """Create a domain object.  Optionally take a 
        dictionary of 'xm' options to use"""

        self.domID = None;
        self.config = config

        if not opts.has_key("name"):
            raise DomainError("Missing `name' option")
        if not opts.has_key("memory"):
            raise DomainError("Missing `memory' option")
        if not opts.has_key("kernel"):
            raise DomainError("Missing `kernel' option")

        self.opts = opts

        self.configVals = None

    def __buildCmdLine(self):
        c = "xm create %s" % self.config

        for k in self.opts.keys():
            c += " %s=%s" % (k, self.opts[k])
        
        return c
        
    def start(self):

        if self.configVals:
            self.__writeConfig("/tmp/xm-test.conf")
            self.config = "/tmp/xm-test.conf"

        commandLine = self.__buildCmdLine()

        ret, output = traceCommand(commandLine);

        try:
            self.domID = int(domid(self.domName));
        except:
            self.domID = -1;

        if ret != 0:
            raise DomainError("Failed to create domain",
                              extra=output,
                              errorcode=ret)

    def stop(self):
        prog = "xm";
        cmd = " shutdown ";

        ret, output = traceCommand(prog + cmd + self.opts["name"]);

        return ret;

    def destroy(self):
        prog = "xm";
        cmd = " destroy ";

        ret, output = traceCommand(prog + cmd + self.opts["name"]);

        return ret;

    def getName(self):
        return self.opts["name"];

    def getId(self):
        return domid(self.getName());

    def configSetVar(self, key, value):
        if not self.configVals:
            self.configVals = {}

        self.configVals[key] = value

    def configAddDisk(self, pdev, vdev, acc):
        if not self.configVals:
            self.configVals = {}

        if not self.configVals.has_key("disk"):
            self.configVals["disk"] = []

        self.configVals["disk"].append("%s,%s,%s" % (pdev,vdev,acc))

    def __writeConfig(self, configFileName):

        conf = file(configFileName, "w")

        for k,v in self.configVals.items():
            print >>conf, "%s = %s" % (k, v)

        conf.close()


class XmTestDomain(XenDomain):

    def __getUniqueName(self):
        #
        # We avoid multiple duplicate names
        # here because they stick around in xend
        # too long
        #
        unixtime = int(time.time())
        test_name = sys.argv[0]
        test_name = re.sub("\.test", "", test_name)
        test_name = re.sub("[\/\.]", "", test_name)
        name = "%s-%i" % (test_name, unixtime)

        return name

    def __randomize(self):
        # Random amount of memory between min and free_memory/2
        freeMem = int(getInfo("free_memory"))
        self.defaults["memory"] = random.randint(self.minSafeMem(),
                                                 freeMem/2)
        
        self.defaults["vcpus"] = random.randint(1, 16)

        self.defaults["nics"] = random.randint(0, 8)

        if verbose:
            print "*** Defaults after randomization:"
            for k in self.defaults.keys():
                print "***  %10s : %s" % (k, self.defaults[k])

    def __prepareBlockRoot(self, rdpath):
        image = os.path.abspath(rdpath + "/initrd.img")
        self.configAddDisk("file:%s" % image, BLOCK_ROOT_DEV, "w")
        self.defaults["root"] = "/dev/%s" % BLOCK_ROOT_DEV
        del self.defaults["ramdisk"]

    def __init__(self, name=None, extraOpts=None, config="/dev/null",
                 random=False):

        rdpath = os.environ.get("RD_PATH")
        if not rdpath:
            rdpath = "../../ramdisk"

        self.opts = {}
        self.configVals = None

        # Defaults
        self.defaults = {"memory"  : 64,
                         "vcpus"   : 1,
                         "nics"    : 0,
                         "kernel"  : getDefaultKernel(),
                         "root"    : "/dev/ram0",
                         "name"    : name or self.__getUniqueName(),
                         "ramdisk" : rdpath + "/initrd.img"
                         }

        self.domID = None;
        self.config = config;

        if random:
            self.__randomize()

        if USE_BLKDEV_FOR_ROOT:
            self.__prepareBlockRoot(rdpath)
        
        # Copy over defaults
        for key in self.defaults.keys():
            self.opts[key] = self.defaults[key]

        # Merge in extra options
        if extraOpts:
            for key in extraOpts.keys():
                self.opts[key] = extraOpts[key]

    def start(self):
        """We know how about how long everyone will need to wait
        for our ramdisk to come up, so we do it here as a convenience"""

#        for i in range(0,5):
#            status, output = traceCommand("xm list")

        XenDomain.start(self)
#        waitForBoot()

    def startNow(self):
        XenDomain.start(self)

    def getMem(self):
        return int(self.opts["memory"])

    def minSafeMem(self):
        return 16

if __name__ == "__main__":

    d = XmTestDomain();

    d.start();
