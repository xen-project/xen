#!/usr/bin/env python

#
# Wrapper script for formatting a device to host Xen virtual disk extents
#
# Usage: vd_format.py device [extent_size]
#

import sys, XenoUtil

if len(sys.argv) > 1:
    device = sys.argv[1]
else:
    print "Usage: " + sys.argv[0] + """ device [extent_size]
     Formats a device to host Xen virtual disk extents.  The extent size can
     optionally be specified in megabytes (default 64MB)."""
    sys.exit(1)

if len(sys.argv) > 2:
    extent_size = int(sys.argv[2])
else:
    print """No extent size specified - using default size
    (for really small devices, the default size of 64MB might not work)"""
    extent_size = 64

print "Formatting for virtual disks"
print "Device: " + sys.argv[1]
print "Extent size: " + str(extent_size) + "MB"

ret = XenoUtil.vd_format(device, extent_size)

if ret:
    print >> sys.stderr, "An error occurred formatting the device"
    sys.exit(ret)
