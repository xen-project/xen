#!/usr/bin/env python

# Used to map a VBD into a domain's device space.  Useful for populating a new
# VBD with data from DOM0 before starting a new domain using it, for instance.

import Xc, XenoUtil, sys

XenoUtil.VBD_EXPERT_LEVEL = 0 # sets the allowed level of potentially unsafe mappings

def usage():
    print >>sys.stderr,"""Usage: add_vdisk_to_dom.py uname target-dev target-dom [perms]
        uname        - the uname of the source device, e.g. vd:2341 or phy:hda3
        target-dev   - the device node to map the VBD to
        target-dom   - domain to add the new VBD to
        perms        - optionally specify 'r', or 'rw' (default is 'r')
        """
    sys.exit(1)    

xc = Xc.new()

if not 4 <= len(sys.argv) <= 5:
    print len(sys.argv)
    usage()
    
writeable = 0

if len(sys.argv) == 5:
    if sys.argv[4] == 'rw':
        writeable = 1;
    else:
        if sys.argv[4] != 'r':
            usage()

segments = XenoUtil.lookup_disk_uname(sys.argv[1])

if XenoUtil.vd_extents_validate(segments,writeable) < 0:
    print "That mapping is too unsafe for the current VBD expertise level"
    sys.exit(1)

virt_dev = XenoUtil.blkdev_name_to_number(sys.argv[2])

target_dom = int(sys.argv[3])

xc.vbd_create(target_dom,virt_dev,writeable)

if xc.vbd_setextents( target_dom, virt_dev, segments ):
    print "Error populating VBD vbd=%d\n" % virt_dev
    sys.exit(1)


print "Added " + sys.argv[1] + " to domain " + sys.argv[3] + " as device " + sys.argv[2]
