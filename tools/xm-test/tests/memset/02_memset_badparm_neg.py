#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Woody Marvel <marvel@us.ibm.com>
##
## Description:
## Test xm mem-set output and status
## Negative Tests:
## 1) Test xm mem_set (no parm)
## 2) Test xm list (non existent parm)
## 3) Test xm list (non existent domain)
##
##
## Author: Woody Marvel		marvel@us.ibm.com
##

import re 

from XmTestLib import * 

if ENABLE_HVM_SUPPORT:
    SKIP("Mem-set not supported for HVM domains")

# destroy no parm input - negative test
status, output = traceCommand("xm mem-set")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm mem-set returned invalid %i == 0" % status)
elif where == -1:
    FAIL("xm mem-set failed to report error for missing arg")

# destroy non existent parm input - negative test
status, output = traceCommand("xm mem-set -x")
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm mem-set returned invalid %i == 0" % status)
elif where == -1:
    FAIL("xm mem-set failed to report error for bad arg")

# destroy non existent domain - negative test
status, output = traceCommand("xm mem-set 6666")
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm mem-set returned invalid %i == 0" % status)
elif where == -1:
    FAIL("xm mem-set failed to report error for invalid domid")

# destroy non existent domain and memory - negative test
status, output = traceCommand("xm mem-set 6666 64")
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm mem-set returned invalid %i == -1" % status)
elif where == -1:
    FAIL("xm mem-set failed to report error for invalid domid")

