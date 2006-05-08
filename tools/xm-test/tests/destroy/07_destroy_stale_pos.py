#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>

#
# 10 start a domain
# 20 destroy it
# 30 try next xm command
# 40 goto 10

from XmTestLib import *

import re

def test_mem_set(name):
    status, output = traceCommand("xm mem-set %s 32" % name, logOutput=True)

    if status == 0:
        FAIL("mem-set worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("mem-set failed to report error after destroy!")

def test_pause(name):
    status, output = traceCommand("xm pause %s" % name, logOutput=True)

    if status == 0:
        FAIL("pause worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("pause failed to report error after destroy!")

def test_unpause(name):
    status, output = traceCommand("xm unpause %s" % name, logOutput=True)

    if status == 0:
        FAIL("unpause worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("unpause failed to report error after destroy!")

def test_reboot(name):
    status, output = traceCommand("xm reboot %s" % name, logOutput=True)

    if status == 0:
        FAIL("reboot worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("reboot failed to report error after destroy!")

def test_save(name):
    status, output = traceCommand("xm save %s /tmp/foo" % name, logOutput=True)

    if status == 0:
        FAIL("save worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("save failed to report error after destroy!")

def test_block_list(name):
    status, output = traceCommand("xm block-list %s" % name, logOutput=True)

    if status == 0:
        FAIL("block-list worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("block-list failed to report error after destroy!")

def test_shutdown(name):
    status, output = traceCommand("xm shutdown %s" % name, logOutput=True)

    if status == 0:
        FAIL("shutdown worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("shutdown failed to report error after destroy!")

def test_domname(name):
    status, output = traceCommand("xm domname %s" % name)

    if status == 0:
        FAIL("domname worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("domname failed to report error after destroy!")

def test_domid(name):
    status, output = traceCommand("xm domid %s" % name)

    if status == 0:
        FAIL("domid worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("domid failed to report error after destroy!")

def test_destroy(name):
    status, output = traceCommand("xm destroy %s" % name)

    if status == 0:
        FAIL("destroy worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("destroy failed to report error after destroy!")

def test_sysrq(name):
    status, output = traceCommand("xm sysrq %s s" % name)

    if status == 0:
        FAIL("sysrq worked after domain destroy!")
    if not re.search("[Ee]rror", output):
        FAIL("sysrq failed to report error after destroy!")

def runTests(tests):
    for test in tests:
        domain = XmTestDomain()

        # Create a domain

        try:
            console = domain.start()
        except DomainError, e:
            FAIL(str(e))

        try:
            console.runCmd("ls")
        except ConsoleError, e:
            FAIL(str(e))

        # Destroy it
                
        domain.destroy()
        
        # Run test
        
        test(domain.getName())

tests = [test_mem_set, test_pause, test_unpause, test_reboot, test_save,
         test_block_list, test_shutdown, test_domid, test_domname]

if verbose:
    print "Running stale tests"
runTests(tests)
