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


##
## These are miscellaneous utility functions that query xm
##

import commands
import re
import os
import time

from Test import *;

class XmError(Exception):
    def __init__(self, msg, trace="", status=0):
        self.msg = msg
        self.trace = trace
        try:
            self.status = int(status)
        except Exception, e:
            self.status = -1

        def __str__(self):
            return trace
    
def domid(name):
    status, output = traceCommand("xm domid " + name);

    if status != 0 or "Traceback" in output:
        return -1
    if output == "None":
        return -1
    try:
        return int(output)
    except:
        raise XmError("xm domid failed", trace=output, status=status)


def domname(id):
    status, output = traceCommand("xm domname " + str(id));
    return output;

def isDomainRunning(domain):
    id = domid(domain);
    if id == -1:
        return False;
    else:
        return True;

def getRunningDomains():
    status, output = traceCommand("xm list");
    if status != 0 or "Traceback" in output:
        raise XmError("xm failed", trace=output, status=status)
    
    lines = output.splitlines();
    domains = [];
    for l in lines[1:]:
        elms = l.split(" ", 1);
        domains.append(elms[0]);
    return domains;

def destroyDomU(name):
    status, output = traceCommand("xm destroy " + name, logOutput=False);
    return status;

def destroyAllDomUs():
    if verbose:
        print "*** Cleaning all running domU's"

    attempt = 0
    trying = True

    while trying:
        try:
            attempt += 1
            domainList = getRunningDomains()
            trying = False
        except XmError, e:
            if attempt >= 10:
                FAIL("XM-TEST: xm list not responding")
            time.sleep(1)
            print e.trace
            print "!!! Trying again to get a clean domain list..."

    for d in domainList:
        if not d == "Domain-0":
            destroyDomU(d);

    if verbose:
        print "*** Finished cleaning domUs"

def getDomMem(domain):
    status, output = traceCommand("xm list")
    if status != 0:
        if verbose:
            print "xm list failed with %i" % status
        return None

    lines = re.split("\n", output)
    for line in lines:
        fields = re.sub(" +", " ", line).split()
        if domain.isdigit():
            if fields[1] == domain:
                return int(fields[2])
        else:
            if fields[0] == domain:
                return int(fields[2])
    if verbose:
        print "Did not find domain " + str(domain)
    return None

def getDomInfo(domain, key, opts=None):
    if opts:
        cmd = "xm list %s" % opts
    else:
        cmd = "xm list"
        
    status, output = traceCommand(cmd)

    if status != 0:
        if verbose:
            print "xm list failed with %i" % status
        return None

    lines = output.split("\n")

    # Get the key values from the first line headers
    cleanHeader = re.sub("\([^\)]+\)", "", lines[0])
    colHeaders = re.split(" +", cleanHeader)

    doms = {}

    for line in lines[1:]:
        domValues = {}
        values = re.split(" +", line)
        i = 1
        for value in values[1:]:
            domValues[colHeaders[i]] = value
            i += 1
        doms[values[0]] = domValues


    if doms.has_key(domain) and doms[domain].has_key(key):
        return doms[domain].get(key)

    return ""

def getVcpuInfo(domain):

    status, output = traceCommand("xm vcpu-list %s" % domain)

    lines = output.split("\n")

    vcpus = {}

    for line in lines[1:]:
        cols = re.split(" +", line)
        if cols[3] == '-':
            vcpus[int(cols[2])] = None
        else:
            vcpus[int(cols[2])] = int(cols[3])

    return vcpus

def getInfo(key):

    info = {}

    status, output = traceCommand("xm info")
    lines = output.split("\n")
    for line in lines:
        match = re.match("^([A-z_]+)[^:]*: (.*)$", line)
        if match:
            info[match.group(1)] = match.group(2)

    if info.has_key(key):
        return info[key]
    else:
        return ""

def restartXend():
    if verbose:
        print "*** Restarting xend ..."

    if os.access("/etc/init.d/xend", os.X_OK):
        status, output = traceCommand("/etc/init.d/xend stop")
        time.sleep(1)
        status, output = traceCommand("/etc/init.d/xend start")

        return status

    else:
        status, output = traceCommand("xend stop")
        time.sleep(1)
        status, output = traceCommand("xend start")

        return status

def smpConcurrencyLevel():
    nr_cpus = int(getInfo("nr_cpus"))

    return nr_cpus

if __name__ == "__main__":
    if isDomainRunning("0"):
        print "Domain-0 is running; I must be working!"
    else:
        print "Domain-0 is not running; I may be broken!"

    mem = getDomMem("Domain-0")
    if not mem:
        print "Failed to get memory for Domain-0!"
    else:
        print "Domain-0 mem: %i" % mem

    cpu = getDomInfo("Domain-0", "CPU")
    state = getDomInfo("Domain-0", "State")

    print "Domain-0 CPU: " + cpu
    print "Domain-0 state: " + state
    
    v = getVcpuInfo("Domain-0")
    for key in v.keys():
        print "VCPU%i is on CPU %i" % (key, v[key])
