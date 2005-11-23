#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Author: Murillo F. Bernardes <mfb@br.ibm.com>

from XmTestLib import *

def count_eth(console):
    try:
        run = console.runCmd("ifconfig -a | grep eth")
    except ConsoleError, e:
        FAIL(str(e))
    return = len(run['output'].splitlines())

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
        return -1, "xm network-attach returned invalid %i != 0" % status

    eths_after = count_eth(console)
    if eths_after != (eths_before-1):
    	return -2, "Network device was not actually disconnected from domU"

    return 0, None
