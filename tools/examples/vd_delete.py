#!/usr/bin/env python

#
# Wrapper script for deleting a virtual disk.
#
# Usage: vd_create.py id
#

import sys, XenoUtil

if len(sys.argv) > 1:
        id = sys.argv[1]
else:
    print "Usage: " + sys.argv[0] + """ id
    Deletes a virtual disk."""
    sys.exit(1)

print "Deleting a virtual disk with ID: " + id

ret = XenoUtil.vd_delete(id)

if ret:
    print "Deletion failed: invalid ID, or disk already expired / deleted"
