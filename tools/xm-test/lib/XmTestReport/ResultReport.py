#!/usr/bin/python

"""
 ResultReport.py - Handles the gathering and xml-formatting of xm-test
                   results

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

import re

class Test:

    def __init__(self, name, state, seq):
        self.vars = {}
        self.vars["name"] = name
        self.vars["state"] = state
        self.vars["log"] = "NO LOG SUPPLIED"
        self.vars["seq"] = str(seq)

    def setLog(self, log):
        self.vars["log"] = log

    def __str__(self):
        string = "<test>\n"

        for k in self.vars.keys():
            string += "  " + utils.tagify(k, self.vars[k]) + "\n"

        string += "</test>\n"

        return string

class TestGroup:

    def __init__(self, name):
        self.name = name
        self.tests = []

    def addTest(self, test):
        self.tests.append(test)

    def __str__(self):
        string  = "<group>\n"
        string += "  <name>%s</name>\n" % self.name

        for t in self.tests:
            string += str(t)

        string += "</group>\n"

        return string

class ResultSet:

    def __init__(self):
        self.groups = []

    def addGroup(self, group):
        self.groups.append(group)

    def __str__(self):
        string = "<results>\n"

        for g in self.groups:
            string += str(g)

        string += "</results>\n"

        return string

class ResultParser:

    def __init__(self):
        self.groups = {}
        self.resultSet = None

    def __isImportant(self, line):

        if re.search("^[Mm]ak(e|ing)", line):
            return False
        if re.search("^===", line):
            return False
        if re.search("^All [0-9]+ tests", line):
            return False
        if re.search("^[0-9]+ of [0-9]+ tests", line):
            return False
        if re.search("^cp [0-9]+_", line):
            return False
        if re.search("^chmod \+x [0-9]+_", line):
            return False
        
        return True

    def parse(self, fileName):
        output = file(fileName);
        contents = output.read()

        lines = contents.split("\n")

        sequence = 0
        currentLog = ""
        for l in lines:
            match = re.match("^(PASS|FAIL|XPASS|XFAIL|SKIP): ([0-9]+)_([^_]+)_([^\.]+)\.test$", l)
            if match:
                # End of current test; build object
                testStatus = match.group(1)
                testNumber = match.group(2)
                testGroup  = match.group(3)
                testName   = match.group(4)

                if not testGroup in self.groups.keys():
                    self.groups[testGroup] = TestGroup(testGroup)

                test = Test("%s_%s" % (testNumber, testName), testStatus,
                            sequence)
                sequence += 1
                test.setLog(currentLog)
                self.groups[testGroup].addTest(test)

                currentLog = ""

            else:
                if self.__isImportant(l):
                    currentLog += l + "\n"

        self.resultSet = ResultSet()

        for g in self.groups:
            self.resultSet.addGroup(self.groups[g])

        return self.resultSet

if __name__ == "__main__":

    import sys

    r = ResultParser()

    print str(r.parse(sys.argv[1]))
