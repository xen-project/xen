#!/usr/bin/python

import sys
import re
import time

from XmTestLib import *
from pools import *



#
# Check requirements of test case
# - min 2 free cpus (not assigned to a pool)
#
if int(getInfo("free_cpus")) < 2:
    SKIP("Need at least 2 free cpus")



#
# Create 2 pools with one cpu per pool.
#
createStdPool({'name' : 'Pool-1'})
createStdPool({'name' : 'Pool-2'})



#
# Create a domain with vcpus=1 in Pool-0.
# Migrate it to one of the created pools afterwards to the other pool
#
name = "TestDomPool-1"
domain = XmTestDomain(extraConfig={'pool' : 'Pool-0'}, name=name)
try:
    domain.start(noConsole=True)
except DomainError, ex:
    FAIL(str(e))
if not domInPool(name, 'Pool-0'):
    FAIL("missing '%s' in Pool-0" % name)

if not migrateToPool(name, 'Pool-1'):
    FAIL("missing '%s' in Pool-1" % name)
if not migrateToPool(name, 'Pool-2'):
    FAIL("missing '%s' in Pool-2" % name)



#
# Create a domain in Pool-0.
# Migrate it to one of the created pools afterwards to the other pool
#
name = "TestDomPool-2"
domain = XmTestDomain(extraConfig={'pool' : 'Pool-0'}, name=name)
try:
    domain.start(noConsole=True)
except DomainError, ex:
    FAIL(str(e))
if not domInPool(name, 'Pool-0'):
    FAIL("missing '%s' in Pool-0" % name)

if not migrateToPool(name, 'Pool-1'):
    FAIL("missing '%s' in Pool-1" % name)
if not migrateToPool(name, 'Pool-2'):
    FAIL("missing '%s' in Pool-2" % name)



#
# Migrate other domains between pools
#
for cnt in range(10):
    for pool in ['Pool-0', 'Pool-1', 'Pool-2']:
        for domain in getRunningDomains():
            if domain != 'Domain-0':
                if not migrateToPool(domain, pool):
                    FAIL("missing '%s' in %s" % (domain, pool))


#
# Cleanup
#
cleanupPoolsDomains()

