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
opts1 =  {
            "name"    : "default",
            "memory"  : 0,
            "kernel"  : getDefaultKernel(),
            "root"    : "/dev/ram0",
            "ramdisk" : rdpath + "/initrd.img",
            }

domain1=XenDomain(opts1)

try:
    domain1.start()
    eyecatcher1 = "Created"
except DomainError, e:
    eyecatcher1 = "Fail"

if eyecatcher1 != "Fail":
	domain1.stop()
        FAIL("xm create let me create a domain with 0 memory")


# Test 2: create a domain with mem>sys_mem

mem = int(getInfo("total_memory"))
extreme_mem = str(mem + 100)

opts2=  {
            "name"    : "default",
            "memory"  : extreme_mem,
            "kernel"  : getDefaultKernel(),
            "root"    : "/dev/ram0",
            "ramdisk" : rdpath + "/initrd.img",
            }

domain2=XenDomain(opts2)

try:
    domain2.start()
    eyecatcher2 = "Created"
except DomainError, e:
    eyecatcher2 = "Fail"

if eyecatcher2 != "Fail":
        domain2.stop()
        FAIL("xm create let me create a domain with mem > sys_mem")

