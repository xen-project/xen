#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

import time
import re

from XmTestLib import *

status, output = traceCommand("xm reboot NOT-EXIST" )

eyecatcher = "Error"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm reboot returned invalid %i == 0" % status )
elif where == -1:
    FAIL("xm reboot failed to report error for non-existent domain" )
