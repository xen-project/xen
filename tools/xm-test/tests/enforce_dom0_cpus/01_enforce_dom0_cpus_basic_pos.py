#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Authors: Dan Smith <danms@us.ibm.com>
#          Ryan Harper <ryanh@us.ibm.com>

# 1) Make sure we have a multi cpu system
# 2) clone standard config (/etc/xen/xend-config.sxp) 
# 3) modify clone with enforce_dom0_cpus=X
# 4) restart xend with modified config
# 5) check /proc/cpuinfo for cpu count
# 6) check xm list -v to see that only 1 cpu is online for dom0
# 7) Restart xend with default config

import sys
import re
import time
import os

# what value should dom0_cpus be enforced?
enforce_dom0_cpus=1

from XmTestLib import *

check_status = 1
max_tries = 10

# 1) Make sure we have a multi cpu system

if smpConcurrencyLevel() <= 1:
    print "*** NOTE: This machine does not have more than one physical"
    print "          or logical cpu.  The vcpu-disable test cannot be run!"
    SKIP("Host not capable of running test")
    
# 2) clone standard config (/etc/xen/xend-config.sxp) 
# 3) modify clone with enforce_dom0_cpus=1
old_config="/etc/xen/xend-config.sxp"
new_config ="/tmp/xend-config.sxp"
cmd = "sed -e 's,dom0-cpus 0,dom0-cpus %s,' %s > %s" % (enforce_dom0_cpus,
                                                        old_config,
                                                        new_config)
status, output = traceCommand(cmd)
if check_status and status != 0:
    FAIL("\"%s\" returned invalid %i != 0" %(cmd,status))


# 4) restart xend with new config
os.putenv("XEND_CONFIG", "/tmp/xend-config.sxp")
status = restartXend()
if check_status and status != 0:
    ns, no = restartXend()
    if ns != 0:
        FAIL("Restarting xend isn't working: something is WAY broken")
    else:
        FAIL("\"%s\" returned invalid %i != 0" %(cmd,status))

# 5) check /proc/cpuinfo for cpu count
cmd = "grep \"^processor\" /proc/cpuinfo | wc -l"
status, output = traceCommand(cmd)
if check_status and status != 0:
    os.unsetenv("XEND_CONFIG")
    restartXend()
    FAIL("\"%s\" returned invalid %i != 0" %(cmd,status))

if output != str(enforce_dom0_cpus):
    os.unsetenv("XEND_CONFIG")
    restartXend()
    FAIL("/proc/cpuinfo says xend didn't enforce dom0_cpus (%s != %s)" %(output, enforce_dom0_cpus))

# 7) count number of online cpus and see that it matches enforce value
dom0vcpus = getVcpuInfo("Domain-0")
num_online = len(filter(lambda x: x >= 0, dom0vcpus.values()))
if num_online != enforce_dom0_cpus:
    os.unsetenv("XEND_CONFIG")
    restartXend()
    FAIL("xm says xend didn't enforce dom0_cpus (%s != %s)" %(num_online, enforce_dom0_cpus))

# restore dead processors 
for (k,v) in zip(dom0vcpus.keys(),dom0vcpus.values()):
    if v == -1:
        status, output = traceCommand("xm vcpu-enable 0 %s"%(k))
        if check_status and status != 0:
            os.unsetenv("XEND_CONFIG")
            restartXend()
            FAIL("\"%s\" returned invalid %i != 0" %(cmd,status))

# Restart xend with default config
os.unsetenv("XEND_CONFIG")
restartXend()

