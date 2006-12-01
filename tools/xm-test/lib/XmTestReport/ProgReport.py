#!/usr/bin/python

"""
 ProgReport.py - Handles the gathering and xml-formatting of supporting
                 program information

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

import commands
import re
import distutils.sysconfig
import sys

from xmtest import XM_TEST_VERSION

class Prog:

    def __init__(self, name, version):
        self.vars = {}
        self.vars["name"] = name
        self.vars["version"] = version

    def __str__(self):
        string = "<prog>\n"

        for k in self.vars.keys():
            string += "  " + utils.tagify(k, self.vars[k]) + "\n"

        string += "</prog>\n"

        return string

class UnknownProg(Prog):

    def __init__(self, name):
        Prog.__init__(self, name, "Unknown Version")
        
class ProgFactory:

    def getXen(self):
        status, output = commands.getstatusoutput("xm info")
        if status != 0:
            return UnknownProg("xen")
        
        for l in output.split("\n"):
            match = re.match("^([a-z_]+)[ ]*: (.*)$", l)
            if match and match.group(1) == "xen_changeset":
                return Prog("xen", match.group(2))

        return UnknownProg("xen")

    def getXmTest(self):
        return Prog("xm-test", XM_TEST_VERSION)

    def getPython(self):
        return Prog("python", distutils.sysconfig.get_python_version())

    def getXenCaps(self):
        s, o = commands.getstatusoutput("xm info")
        if s != 0:
            return UnknownProg("xen_caps")

        for l in o.split("\n"):
            match = re.match("^xen_caps[ \t]*: (.*)$", l)
            if match:
                return Prog("xen_caps", match.group(1))

class ProgReport:

    def __init__(self):

        self.progs = []
        self.errors = 0

        f = ProgFactory()

        self.progs.append(f.getXen())
        self.progs.append(f.getXmTest())
        self.progs.append(f.getPython())
        self.progs.append(f.getXenCaps())

        for p in self.progs:
            if isinstance(p, UnknownProg):
                self.errors += 1

    def __str__(self):
        string = "<progs>\n"

        for p in self.progs:
            string += str(p)

        string += "</progs>\n"

        return string

if __name__ == "__main__":
    r = ProgReport()

    print str(r)

    sys.exit(r.errors)
