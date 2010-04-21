#!/usr/bin/python

# Description:
# Verify commands pool-new and pool-delete.
#
import sys
import re
import time

from XmTestLib import *
from pools import *

checkRequirements()

#
# Check output of xm pool-list (of Pool-0)
#
status, output = traceCommand("xm pool-list Pool-0")
if status != 0:
    FAIL("xm pool-list failed, rc %s" % status)
lines = output.splitlines()
if len(lines) != 2:
    FAIL("Wrong output of xm pool-list Pool-0 (%s)" % lines)
if not re.search("Pool-0 +[0-9]+ +credit +y +[0-9]", lines[1]):
    FAIL("Wrong output of xm pool-list Pool-0 (%s)" % lines)

#
# Check output of xm pool-list -l (of Pool-0)
#
status, output = traceCommand("xm pool-list Pool-0 -l")
if status != 0:
    FAIL("xm pool-list failed, rc %s" % status)
if not re.search("name_label Pool-0", output):
    FAIL("Wrong output of xm pool-list Pool-0 -l; missing 'name_label'")
if not re.search("started_VMs 00000000-0000-0000-0000-000000000000", output):
    FAIL("Wrong output of xm pool-list Pool-0 -l; missing 'started_VMs'")
if not re.search("started_VM_names Domain-0", output):
    FAIL("Wrong output of xm pool-list Pool-0 -l; missing 'started_VMi_names'")


#
# Create a pool from pool1.cfg
#
cmd = "xm pool-new pool1.cfg name=Pool-1"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))

status, output = traceCommand("xm pool-list")
if status != 0:
    FAIL("xm pool-list failed, rc %s" % status)
if not re.search("Pool-1 +1 +credit", output):
    FAIL("Missing or wrong pool definition for 'Pool-1'")


#
# check persistence of pool; restart xend
#
restartXend()

status, output = traceCommand("xm pool-list")
if status != 0:
    FAIL("xm pool-list failed, rc %s" % status)
if not re.search("Pool-1 +1 +credit", output):
    FAIL("Missing or wrong pool definition for 'Pool-1'")


#
# Delete pool
#
deletePool("Pool-1")
status, output = traceCommand("xm pool-list")
if status != 0:
    FAIL("xm pool-list failed, rc %s" % status)
if re.search("Pool-1 +1 +credit", output):
    FAIL("'Pool-1' not deleted")


#
# create / start / check / destroy / delete a managed pool
#
cmd = "xm pool-new pool1.cfg"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))

cmd = "xm pool-start Pool-1"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))

cmd = "xm pool-list -l Pool-1"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))
if not re.search("host_CPU_numbers +[0-9]", output):
    FAIL("'Pool-1' not activated")

restartXend()

cmd = "xm pool-list -l Pool-1"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))
if not re.search("host_CPU_numbers +[0-9]", output):
    FAIL("'Pool-1' not activated")

destroyPool("Pool-1")
deletePool("Pool-1")

cmd = "xm pool-list Pool-1"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))
if re.search("Pool-1 +1 +credit", output):
    FAIL("'Pool-1' not deleted")


#
# create / check / destroy a unmanaged pool
#
cmd = "xm pool-create pool1.cfg"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))

cmd = "xm pool-list -l Pool-1"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))
if not re.search("host_CPU_numbers +[0-9]", output):
    FAIL("'Pool-1' not activated")

restartXend()

cmd = "xm pool-list -l Pool-1"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))
if not re.search("host_CPU_numbers +[0-9]", output):
    FAIL("'Pool-1' not activated")

destroyPool("Pool-1", True)

cmd = "xm pool-list"
status, output = traceCommand(cmd)
if status != 0:
    FAIL("%s failed, rc %s" % (cmd,status))
if re.search("Pool-1", output):
    FAIL("'Pool-1' not deleted")


