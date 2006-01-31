#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

# Check to make sure an invalid sysrq is handled appropriately

import re

from XmTestLib import *

if ENABLE_HVM_SUPPORT:
    SKIP("Sysrq not supported for HVM domains")

status, output = traceCommand("xm sysrq does_not_exist s");

if status == 0:
    if verbose:
        print "Bad SysRq output: " + output;
    FAIL("Bad SysRq didn't report error: %i == 0" % status);
