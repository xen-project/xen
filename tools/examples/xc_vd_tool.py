#!/usr/bin/env python

import XenoUtil, sys, re, string

def usage():

    print >>sys.stderr,"""
Usage: %s command <params>

  initialise [dev] [[ext_size]] - init. a physcial partition to store vd's
  create [size] [[expiry]]      - allocate a vd of specified size (and expiry)
  enlarge [vdid] [extra_size]   - enlarge a specified vd by some amount
  delete [vdid]                 - delete a vd
  import [filename] [[expiry]]  - create a vd and populate w/ image from file
  export [vdid] [filename]      - copy vd's contents to a file
  setexpiry [vdid] [[expiry]]   - update the expiry time for a vd
  list                          - list all the unexpired virtual disks  
  undelete [vdid] [[expiry]]    - attempts to recover an expired vd
  freespace                     - print out the amount of space in free pool

notes:
  vdid      - the virtual disk's identity string
  size      - measured in MB
  expiry    - is the expiry time of the virtual disk in seconds from now
               (0 = don't expire) 
  device    - physical partition to 'format' to hold vd's. e.g. hda4
  ext_size  - extent size (default 64MB)
""" % sys.argv[0]  

if len(sys.argv) < 2: 
    usage()
    sys.exit(-1)

rc=''
src=''
expiry_time = 0
cmd = sys.argv[1]

if cmd == 'initialise':

    dev = sys.argv[2]

    if len(sys.argv) > 3:
	extent_size = int(sys.argv[3])
    else:
	print """No extent size specified - using default size of 64MB"""
	extent_size = 64

    print "Formatting for virtual disks"
    print "Device: " + dev
    print "Extent size: " + str(extent_size) + "MB"

    rc = XenoUtil.vd_format(dev, extent_size)

elif cmd == 'create':
 
    size = int(sys.argv[2])
    
    if len(sys.argv) > 3:
	expiry_time = int(sys.argv[3])

    print "Creating a virtual disk"
    print "Size: %d" % size
    print "Expiry time (seconds from now): %d" % expiry_time

    src = XenoUtil.vd_create(size, expiry_time)

elif cmd == 'enlarge':

    id = sys.argv[2]

    extra_size = int(sys.argv[3])

    rc = XenoUtil.vd_enlarge(id, extra_size)

elif cmd == 'delete':

    id = sys.argv[2]

    print "Deleting a virtual disk with ID: " + id

    rc = XenoUtil.vd_delete(id)

elif cmd == 'import':

    file = sys.argv[2]
    
    if len(sys.argv) > 3:
	expiry_time = int(sys.argv[3])

    print "Allocate new virtual disk and populate from file : %s" % file

    print XenoUtil.vd_read_from_file(file, expiry_time)

elif cmd == 'export':

    id = sys.argv[2]
    file = sys.argv[3]

    print "Dump contents of virtual disk to file : %s" % file

    rc = XenoUtil.vd_cp_to_file(id, file )

elif cmd == 'setexpiry':

    id = sys.argv[2]

    if len(sys.argv) > 3:
	expiry_time = int(sys.argv[3])

    print "Refreshing a virtual disk"
    print "Id: " + id
    print "Expiry time (seconds from now [or 0]): " + expiry_time

    rc = XenoUtil.vd_refresh(id, expiry_time)

elif cmd == 'list':

    for vbd in XenoUtil.vd_list():
        print """ID: %s
Expires: %s
Expiry time: %s
Size (MB): %d
""" % (vbd['vdisk_id'], vbd['expires'],
       str(vbd['expiry_time']), vbd['size'] / 2048)

elif cmd == 'freespace':

    print XenoUtil.vd_freespace()

elif cmd == 'undelete':

    id = sys.argv[2]

    if len(sys.argv) > 3:
	expiry_time = int(sys.argv[3])
   
    if XenoUtil.vd_undelete(id, expiry_time):
	print "Undelete operation failed for virtual disk: " + id
    else:
	print "Undelete operation succeeded for virtual disk: " + id

else:
    usage()
    sys.exit(-1)


if src != '':  
    print "Returned virtual disk id is : %s" % src

if rc != '':
    print "return code %d" % rc



