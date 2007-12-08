#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

from XmTestLib import *
from XmTestLib.acm import *

testpolicy = "xm-test"
vmconfigfile = "/tmp/xm-test.conf"

if not isACMEnabled():
    SKIP("Not running this test since ACM not enabled.")

setCurrentPolicy(testpolicy)
ACMSetPolicy()
