#!/usr/bin/env python

#
# Wrapper script for creating a virtual disk.
#
# Usage: vd_refresh.py id [new-expiry]
#

import sys, XenoUtil

if len(sys.argv) > 1:
        id = sys.argv[1]
else:
    print "Usage: " + sys.argv[0] + """ ID [expiry-new]
    Refreshes a Virtual Disk expiry time.  An expiry time
    can be specified in seconds from now (0 means never expire) - the default
    is for disks to never expire."""
    sys.exit(1)

if len(sys.argv) > 2:
    expiry_time = int(sys.argv[2])
else:
    print "No expiry time specified - using default\n"
    expiry_time = 0

print "Refreshing a virtual disk"
print "Id: " + sys.argv[1]
print "Expiry time (seconds from now): " + sys.argv[2]

ret = XenoUtil.vd_refresh(id, expiry_time)

