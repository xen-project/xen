#!/usr/bin/env python

#
# vd_to_file.py filename [-m]
#
# Writes a virtual disk out to a file.  Optionally, the "-m" (move)
# flag causes the virtual disk to be deallocated once its data is
# read out.

import XenoUtil, sys

def usage():
    print "Usage: " + sys.argv[0] + """ vdisk_id filename [-m]
    Writes a virtual disk out to a file.  Optionally, the "-m" (move)
    flag causes the virtual disk to be deallocated once its data is
    read out.
    """
    sys.exit()

if not 3 <= len(sys.argv) <= 4:
    usage()

if len(sys.argv) == 4:
    if sys.argv[3] != "-m":
        usage()
    else:
        print "Doing move to file..."
        if XenoUtil.vd_mv_to_file(sys.argv[1],sys.argv[2]):
            print "Failed"    
else:
    print "Doing copy to file..."
    if XenoUtil.vd_cp_to_file(sys.argv[1], sys.argv[2]):
        print "Failed"
    
