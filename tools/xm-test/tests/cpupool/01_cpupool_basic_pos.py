#!/usr/bin/python

import sys
import re
import time

from XmTestLib import *


#
# Check output of xm info. It must include field 'free_cpus'
# The value must be between 0 - nr_cpus
#
free_cpus = getInfo("free_cpus")
if free_cpus == "":
    FAIL("Missing 'free_cpus' entry in xm info output")
if int(free_cpus) not in range(int(getInfo("nr_cpus")) + 1):
    FAIL("Wrong value of 'free_cpus' (%s)" % int(free_cpus))


#
# Check output of xm list -l. It must contain the key 'pool_name'
# If XM_USES_API is set, output must also contain 'cpu_pool'.
#
status, output = traceCommand("xm list -l Domain-0")
if status != 0 or "Traceback" in output:
    raise XmError("xm failed", trace=output, status=status)
if not re.search("pool_name Pool-0", output):
    FAIL("Missing or wrong attribute 'pool_name' in output of 'xm list -l'")
if os.getenv("XM_USES_API"):
    if not re.search("cpu_pool (.+)", output):
        FAIL("Missing or wrong attribute 'cpu_pool' in output of 'xm list -l'")

#
# Test pool selection option of xm list.
#
status, output = traceCommand("xm list --pool=Pool-0")
if status != 0 or "Traceback" in output:
    raise XmError("xm failed", trace=output, status=status)
if not re.search("Domain-0 +0 +", output):
    FAIL("Missing 'Domain-0' in Pool-0")

status, output = traceCommand("xm list --pool=Dummy-Pool")
if status != 0 or "Traceback" in output:
    raise XmError("xm failed", trace=output, status=status)
if len(output.splitlines()) != 1:
    FAIL("Wrong pool selection; output must be empty")


#
# Create a Domain without pool specification.
# Default pool is Pool-0
#
name = "TestDomPool-1"
domain = XmTestDomain(name=name)
try:
    domain.start(noConsole=True)
except DomainError, ex:
    FAIL(str(e))

if not isDomainRunning(name):
    FAIL("Couldn't start domain without pool specification")

status, output = traceCommand("xm list -l %s" % name)
if status != 0 or "Traceback" in output:
    raise XmError("xm failed", trace=output, status=status)
if not re.search("pool_name Pool-0", output):
    FAIL("Missing or wrong attribute 'pool_name' in output of 'xm list -l %s'" % name)

destroyAllDomUs()


