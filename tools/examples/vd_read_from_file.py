#!/usr/bin/env python

#
# vd_read_from_file.py filename
#
# Reads a virtual disk in from a file and allocates a VD (prints out its ID)
#

import XenoUtil, sys

if len(sys.argv) < 2:
    print "Usage: " + sys.argv[0] + """ filename [expiry]
    Reads in a virtual disk form a file and allocates a VD.
    Can optionally set the expiry time in seconds from now
    (default - don't expire)
    """
    sys.exit()

if len(sys.argv) > 2:
    expiry = int(sys.argv[2])
else:
    expiry = 0

ret = XenoUtil.vd_read_from_file(sys.argv[1], expiry)

if ret < 0:
    print "Operation failed"
else:
    print "File " + sys.argv[1] + " read into virtual disk ID " + ret
