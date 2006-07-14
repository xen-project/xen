#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Authors: Dan Smith <danms@us.ibm.com>
#          Ryan Harper <ryanh@us.ibm.com>

# 1) Make sure we have a multi cpu system and dom0 has at 
#    least 2 vcpus online.
# 2) clone standard config (/etc/xen/xend-config.sxp) 
# 3) modify clone with enforce_dom0_cpus=X
# 4) restart xend with modified config
# 5) check /proc/cpuinfo for cpu count
# 6) check xm info 'VCPUs' field to see that only 'enforce_dom0_cpus' 
#    number of cpus are online in dom0
# 7) Restore initial dom0 vcpu state
# 8) Restart xend with default config

import sys
import re
import time
import os

# what value should dom0_cpus enforce?
enforce_dom0_cpus=1

from XmTestLib import *

check_status = 1
max_tries = 10

def reset_vcpu_count():
    status, output = traceCommand("xm vcpu-set 0 %s"%(dom0_online_vcpus))
    if status != 0:
        print "WARNING!!! Unable to set vcpus back to %s, please set manually"\
            %(dom0_online_vcpus)

# 1) Make sure we have a multi cpu system and dom0 has at least 2 vcpus online.

if smpConcurrencyLevel() <= 1:
    print "*** NOTE: This machine does not have more than one physical"
    print "          or logical cpu.  The vcpu-disable test cannot be run!"
    SKIP("Host not capable of running test")

# count number of online vcpus in dom0
dom0_online_vcpus = int(getDomInfo("Domain-0", "VCPUs"))
if dom0_online_vcpus <= 1:
    print "*** NOTE: DOM0 needs at least 2 VCPUs online to run this test"
    print "          Please enable additional vcpus if possible via xm vcpu-set"
    SKIP("Host state not capable of running test")
    
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
os.unsetenv("XEND_CONFIG")
if check_status and status != 0:
    ns, no = restartXend()
    if ns != 0:
        FAIL("Restarting xend isn't working: something is WAY broken")
    else:
        FAIL("\"%s\" returned invalid %i != 0" %(cmd,status))

# 5) check /proc/cpuinfo for cpu count

# It takes some time for the CPU count to change, on multi-proc systems, so check the number of procs in a loop for 30 seconds. 
#Sleep inside the loop for a second each time.
timeout = 30
starttime = time.time()
while timeout + starttime > time.time():
# Check /proc/cpuinfo
    cmd = "grep \"^processor\" /proc/cpuinfo | wc -l"
    status, output = traceCommand(cmd)
    if check_status and status != 0:
        reset_vcpu_count()
        restartXend()
        FAIL("\"%s\" returned invalid %i != 0" %(cmd,status))
# Has it succeeded? If so, we can leave the loop
    if output == str(enforce_dom0_cpus):
        break
# Sleep for 1 second before trying again
    time.sleep(1)
if output != str(enforce_dom0_cpus):
    reset_vcpu_count()
    restartXend()
    FAIL("/proc/cpuinfo says xend didn't enforce dom0_cpus (%s != %s)"%(output, 
                                                             enforce_dom0_cpus))

# 6) count number of online cpus and see that it matches enforce value
num_online = int(getDomInfo("Domain-0", "VCPUs"))
if num_online != enforce_dom0_cpus:
    reset_vcpu_count()
    restartXend()
    FAIL("xm says xend didn't enforce dom0_cpus (%s != %s)" %(num_online, 
                                                             enforce_dom0_cpus))

# 7) restore dead processors 
reset_vcpu_count()

# check restore worked
# Since this also takes time, we will do it in a loop with a 30 second timeout.
timeout=30
starttime=time.time()
while timeout + starttime > time.time(): 
    num_online = int(getDomInfo("Domain-0", "VCPUs"))
    if num_online == dom0_online_vcpus:
        break
    time.sleep(1)
if num_online != dom0_online_vcpus:
    restartXend()
    FAIL("failed to restore dom0's VCPUs")


# 8) Restart xend with default config
restartXend()

