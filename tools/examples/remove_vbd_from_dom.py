#!/usr/bin/env python

# Used to map a VBD into a domain's device space.  Useful for populating a new
# VBD with data from DOM0 before starting a new domain using it, for instance.

# Usage: add_vdisk_to_dom.py uname target-dev-name target-dom-number
#        uname             - the uname of the device, e.g. vd:2341 or phy:hda3
#        target-dev-name   - the device node to map the VBD to
#        target-dom-number - domain to add the new VBD to

import Xc, XenoUtil, sys

xc = Xc.new()

if len(sys.argv) != 3:
    print >>sys.stderr,"""Usage: add_vdisk_to_dom.py target-dev target-dom
        target-dev   - the device node the VBD is mapped to
        target-dom   - domain to remove the VBD from"""
    sys.exit(1)

virt_dev = XenoUtil.blkdev_name_to_number(sys.argv[1])

target_dom = int(sys.argv[2])

if not xc.vbd_destroy(target_dom,virt_dev):
    print "Removed " + sys.argv[1] + " from domain " + sys.argv[2]
else:
    print "Failed"
    sys.exit(1)
