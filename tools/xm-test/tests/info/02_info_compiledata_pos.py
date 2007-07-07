#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

import re;

from XmTestLib import *

status, output = traceCommand("xm info")

output = re.sub(" +", " ", output)

lines = output.split("\n")

map = {}

for line in lines:
    pieces = line.split(" : ", 1)

    if len(pieces) > 1:
        map[pieces[0]] = pieces[1]

for field in ["cores_per_socket", "threads_per_core", "cpu_mhz",
              "total_memory", "free_memory", "xen_major", "xen_minor",
              "xen_pagesize"]:
    val = map[field]
    if not val.isdigit():
        FAIL("Numeric field %s not all-numbers: %s" % (field, val))

# Check cc_compiler
if not re.match("gcc version", map["cc_compiler"]):
    FAIL("Bad cc_compiler field: %s" % map["cc_compiler"])

# Check cc_compile_by
if not re.match("[A-z0-9_]+", map["cc_compile_by"]):
    FAIL("Bad cc_compile_by field: %s" % map["cc_compile_by"])

# Check cc_compile_domain
# --- What should it look like?


