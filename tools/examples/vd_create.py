#!/usr/bin/env python

#
# Wrapper script for creating a virtual disk.
#
# Usage: vd_create.py size [expiry]
#

import XenoUtil, sys

if len(sys.argv) > 1:
    size = int(sys.argv[1])
else:
    print "Usage: " + sys.argv[0] + """ size [expiry]
    Allocates a Virtual Disk out of the free space pool.  An expiry time
    can be specified in seconds from now (0 means never expire) - the default
    is for disks to never expire."""
    sys.exit(1)

if len(sys.argv) > 2:
    expiry_time = int(sys.argv[2])
else:
    print "No expiry time specified - using default\n"
    expiry_time = 0

print "Creating a virtual disk"
print "Size: %d" % size
print "Expiry time (seconds from now): %d" % expiry_time

ret = XenoUtil.vd_create(size, expiry_time)

if ret < 0:
    print >> sys.stderr, "An error occurred creating the the disk"
    sys.exit(ret)
else:
    print "Virtual disk allocated, with ID: " + ret
