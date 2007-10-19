#!/usr/bin/python

"""
 OSReport.py - Handles the gathering and xml-formatting of operating
               system environment information.

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

import utils

import posix
import re
import os
import commands
import sys
import arch

class Machine:

    def __parseInfoLine(self, line):
        if ":" in line:
            name, value = line.split(":", 1)
            name  = name.strip()
            value = value.strip()
            
            name = re.sub(" ", "_", name)

            return name, value
        else:
            return None, None

    def __getCpuInfo(self, values):

        processors = 0
        cpuinfo = file("/proc/cpuinfo")

        if not cpuinfo:
            return "Unable to read /proc/cpuinfo"

        lines = cpuinfo.readlines()

        for l in lines:
            name, value = self.__parseInfoLine(l)
            
            if name in values.keys():
                values[name] = value

            if name == "processor":
                processors += 1

        values["dom0procs"] = str(processors)

        return values

    def __getXenInfo(self, values):

        status, output = commands.getstatusoutput("xm info")
        if status != 0:
            self.errors += 1
            return values

        lines = output.split("\n")

        for l in lines:
            name, value = self.__parseInfoLine(l)

            if name in values.keys():
                values[name] = value

        return values

    def __init__(self):

        self.values = {}
        self.errors = 0

        xenValues = {"nr_cpus"          : "Unknown",
                     "nr_nodes"         : "Unknown",
                     "cores_per_socket" : "Unknown",
                     "threads_per_core" : "Unknown",
                     "cpu_mhz"          : "Unknown",
                     "total_memory"     : "Unknown"}

        xen = self.__getXenInfo(xenValues)
        cpu = self.__getCpuInfo(arch.cpuValues)

        for k in xen.keys():
            self.values[k] = xen[k]
            if xen[k] == "Unknown":
                self.errors += 1

        for k in cpu.keys():
            self.values[k] = cpu[k]
            if cpu[k] == "Unknown":
                self.errors += 1

        
    def __str__(self):
        string = "<machine>\n"
        
        for k in self.values.keys():
            string += "  " + utils.tagify(k, self.values[k]) + "\n"

        string += "</machine>\n"

        return string

class OperatingSystem:

    def __redhatStyleRelease(self):
        rFile = None
        
        if os.access("/etc/redhat-release", os.R_OK):
            rFile = file("/etc/redhat-release")
        if os.access("/etc/SuSe-release", os.R_OK):
            rFile = file("/etc/SuSe-release")
        if os.access("/etc/SuSE-release", os.R_OK):
            rFile = file("/etc/SuSE-release")
        if os.access("/etc/mandrake-release", os.R_OK):
            rFile = file("/etc/mandrake-release")

        if not rFile:
            return None, None
        
        rLine = rFile.readline()
        rFile.close()
      
        match = re.match("^([^0-9]+)([0-9\.]+).*$", rLine)
        if match:
            return match.group(1), match.group(2)
        else:
            return None, None

    def __debianStyleRelease(self):
        if os.access("/etc/debian_version", os.R_OK):
            rFile = file("/etc/debian_version")
        else:
            rFile = None

        if not rFile:
            return None, None

        line = rFile.readline()
        return "Debian", line.rstrip("\n");

    def __lsbStyleRelease(self):
        if os.access("/etc/lsb-release", os.R_OK):
            rFile = file("/etc/lsb-release")
        else:
            rFile = None

        if not rFile:
            return None, None

        lines = rFile.readlines()

        vendor  = None
        version = None

        for l in lines:
            match = re.match("^DISTRIB_ID=(.*)$", l)
            if match:
                vendor = match.group(1)
            match = re.match("^DISTRIB_RELEASE=(.*)$", l)
            if match:
                version = match.group(1)

        return vendor, version
                
    def __init__(self):

        self.values = {}
        self.errors = 0

        # Try to resolve the vendor and version information
        # for the distro we're running on
        vendor = None
        version = None
        for r in [self.__redhatStyleRelease, self.__debianStyleRelease, self.__lsbStyleRelease]:
            vendor, version = r()
            if vendor and version:
                break
        
        self.values["vendor"]  = vendor or "Unknown vendor"
        self.values["version"] = version or "Unknown version"

        self.values["name"], nodename, release, version, self.values["arch"] = posix.uname()

        for k in self.values.keys():
            if not self.values[k]:
                self.errors += 1

    def __str__(self):
        string = "<os>\n"

        for k in self.values.keys():
            string += "  " + utils.tagify(k, self.values[k]) + "\n"

        string += "</os>\n"

        return string
        

class OSReport:

    def __init__(self):

        self.reports = {}
        self.reports["os"] = OperatingSystem()
        self.reports["machine"] = Machine()
        self.errors = 0

        for k in self.reports.keys():
            self.errors += self.reports[k].errors
                 
    def __str__(self):

        string = ""

        for k in self.reports.keys():
            string += str(self.reports[k])

        return string

if __name__ == "__main__":
    r = OSReport()

    print str(r)

    sys.exit(r.errors)

    
