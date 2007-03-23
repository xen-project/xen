#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

from XmTestLib import *

def count_eth(console):
    try:
        run = console.runCmd("ifconfig -a | grep eth")
    except ConsoleError, e:
        FAIL(str(e))
    return len(run['output'].splitlines())

def get_state(domain_name, number):
    s, o = traceCommand("xm network-list %s | awk '/^%d/ {print $5}'" %
                        (domain_name, number))
    print o
    
    if s != 0:
        FAIL("network-list failed")
    if o == "":
        return 0
    else:
        return int(o)

def network_attach(domain_name, console):
    eths_before = count_eth(console)
    status, output = traceCommand("xm network-attach %s" % domain_name)
    if status != 0:
        return -1, "xm network-attach returned invalid %i != 0" % status

    eths_after = count_eth(console)
    if (eths_after != (eths_before+1)):
        return -2, "Network device is not actually connected to domU"

    return 0, None 

def network_detach(domain_name, console, num=0):
    eths_before = count_eth(console)
    status, output = traceCommand("xm network-detach %s %d" % (domain_name, num))
    if status != 0:
        return -1, "xm network-detach returned invalid %i != 0" % status

    for i in range(10):
        if get_state(domain_name, num) == 0:
            break
        time.sleep(1)
    else:
        FAIL("network-detach failed: device did not disappear")

    eths_after = count_eth(console)
    if eths_after != (eths_before-1):
        return -2, "Network device was not actually disconnected from domU"

    return 0, None
