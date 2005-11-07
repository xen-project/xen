#!/usr/bin/python
                                                                                                               
# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>
# Negative Test: attempt removal from non-existent domain
                                                                                                               
import re
                                                                                                               
from XmTestLib import *
                                                                                                               
status, output = traceCommand("xm block-detach 9999 769")
eyecatcher = "Error:"
where = output.find(eyecatcher)
if status == 0:
    FAIL("xm block-detach returned invalid %i != 0" % status)
elif where < 0:
    FAIL("xm block-detach failed to report error for non-existent domain")
