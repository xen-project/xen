#!/usr/bin/python

import sys
import re
import time

from XmTestLib import *
from pools import *


checkRequirements()

#
# create Pool-1 with 1 CPU and start a VM
#
createStdPool()
name = "TestDomPool-1"
domain = XmTestDomain(extraConfig={'pool' : 'Pool-1'}, name=name)
try:
    domain.start(noConsole=True)
except DomainError, ex:
    FAIL(str(e))

cmd = "xm list --pool=Pool-1"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))
if not re.search(name, output):
    FAIL("%s; missing '%s' in Pool-1" % (cmd,name))

domain.stop()
waitForDomain(name)
destroyPool("Pool-1", True)



#
# create Pool-1 with 1 CPU, add a second CPU
# start a VM (with vpcu=3) add a third CPU
# remove 2 CPUs from pool
# create Pool-1 with 1 CPU and start a VM
#
pool_names = ['Pool-1', 'Pool-2']
createStdPool({'name' : pool_names[0], 'cpus' : '"1"'})
name = "TestDomPool-1"
cmd = "xm pool-cpu-add Pool-1 2"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))

domain = XmTestDomain(extraConfig={ 'pool' : 'Pool-1'}, name=name)
try:
    domain.start(noConsole=True)
except DomainError, ex:
    FAIL(str(e))

cmd = "xm pool-cpu-add Pool-1 3"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))

cmd = "xm pool-cpu-remove Pool-1 2"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))
cmd = "xm pool-cpu-remove Pool-1 3"

status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))


createStdPool({'name' : pool_names[1]})
name2 = "TestDomPool-2"
domain2 = XmTestDomain(extraConfig={ 'pool' : 'Pool-2'}, name=name2)
try:
    domain2.start(noConsole=True)
except DomainError, ex:
    FAIL(str(e))

domain2.stop()
domain.stop()

waitForDomain(name)
waitForDomain(name2)

for pool in pool_names:
    destroyPool(pool, True)



#
# Create 2 pools with 1 cpu per pool.
# Create three domains in each pool, with 1,2,3 VCPUs
# Switch a thrid cpu between the pools.
#
pool_names = ['Pool-1', 'Pool-2']
domains = {}
cpu=3

for pool in pool_names:
    createStdPool({'name' : pool})
    for dom_nr in range(3):
        name = "TestDom%s-%s" % (pool, dom_nr)
        domains[name] = XmTestDomain(extraConfig={'pool' : pool},
            name=name)
        try:
            domains[name].start(noConsole=True)
        except DomainError, ex:
            FAIL(str(ex))

cmd_add_1 = "xm pool-cpu-add Pool-1 %s" % cpu
cmd_rem_1 = "xm pool-cpu-remove Pool-1 %s" % cpu
cmd_add_2 = "xm pool-cpu-add Pool-2 %s" % cpu
cmd_rem_2 = "xm pool-cpu-remove Pool-2 %s" % cpu

for i in range(25):
    traceCommand(cmd_add_1)
    traceCommand(cmd_rem_1)
    traceCommand(cmd_add_2)
    traceCommand(cmd_rem_2)

destroyAllDomUs()
for pool in pool_names:
    destroyPool(pool, True)

