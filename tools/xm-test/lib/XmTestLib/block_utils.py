#!/usr/bin/python

# Copyright (c) 2006 XenSource Inc.
# Author: Ewan Mellor <ewan@xensource.com>

import time

from XmTestLib import *

import xen.util.blkif


__all__ = [ "block_attach", "block_detach" ]


def get_state(domain, devname):
    (path, number) = xen.util.blkif.blkdev_name_to_number(devname)
    s, o = traceCommand("xm block-list %s | awk '/^%d/ {print $4}'" %
                        (domain.getName(), number))
    if s != 0:
        FAIL("block-list failed")
    if o == "":
        return 0
    else:
        return int(o)


def block_attach(domain, phy, virt):
    status, output = traceCommand("xm block-attach %s %s %s w" %
                                  (domain.getName(), phy, virt))
    if status != 0:
        FAIL("xm block-attach returned invalid %i != 0" % status)

    for i in range(10):
        if get_state(domain, virt) == 4:
            break
        time.sleep(1)
    else:
        FAIL("block-attach failed: device did not switch to Connected state")


def block_detach(domain, virt):
    status, output = traceCommand("xm block-detach %s %s" %
                                  (domain.getName(), virt))
    if status != 0:
        FAIL("xm block-detach returned invalid %i != 0" % status)

    for i in range(10):
        if get_state(domain, virt) == 0:
            break
        time.sleep(1)
    else:
        FAIL("block-detach failed: device did not disappear")
