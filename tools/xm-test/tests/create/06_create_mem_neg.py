#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Li Ge <lge@us.ibm.com>

# Test Description:
# Negative Tests:
# Test 1: Test for creating domain with mem=0. Verify fail
# Test 2: Test for creating domain with mem>sys_mem. Verify fail

import sys
import re
import time

from XmTestLib import *

rdpath = os.environ.get("RD_PATH")
if not rdpath:
    rdpath = "../ramdisk"

# Test 1: create a domain with mem=0
config1 = {"memory": 0}
domain1=XmTestDomain(extraConfig=config1)

try:
    domain1.start(noConsole=True)
    eyecatcher1 = "Created"
except DomainError, e:
    eyecatcher1 = "Fail"

if eyecatcher1 != "Fail":
    domain1.stop()
    FAIL("xm create let me create a domain with 0 memory")


# Test 2: create a domain with mem>sys_mem

mem = int(getInfo("total_memory"))
extreme_mem = mem + 100

config2 = {"memory": extreme_mem}
domain2=XmTestDomain(extraConfig=config2)

try:
    domain2.start(noConsole=True)
    eyecatcher2 = "Created"
except DomainError, e:
    eyecatcher2 = "Fail"

if eyecatcher2 != "Fail":
    domain2.stop()
    FAIL("xm create let me create a domain with mem > sys_mem")

