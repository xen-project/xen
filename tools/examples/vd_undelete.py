#!/usr/bin/env python

#
# vd_undelete.py vdisk_id [ new_expiry ]
#
# Undeletes a VD and, optionally, sets a new expiry time or disables
# expiry if the time value is zero (default)
#

import XenoUtil, sys

if len(sys.argv) < 2:
    print >>sys.stderr, "Usage: " + sys.argv[0] + """ vdisk_id [ new_expiry ]
    vdisk_id   - the identifier of the deleted VD
    new_expiry - optionally the new expiry time in seconds from now (0
                 for never expire - which is the default)

    VDs can currently only be undeleted if it is safe to do so,
    i.e. if none of their space has been reallocated.
 """

vdisk_id = sys.argv[1]

if len(sys.argv) == 3:
    expiry = int(sys.argv[2])
else:
    expiry = 0

if XenoUtil.vd_undelete(vdisk_id, expiry):
    print "Undelete operation failed for virtual disk: " + vdisk_id
else:
    print "Undelete operation succeeded for virtual disk: " + vdisk_id
