#!/usr/bin/env python

#
# Example script for creating and building a new Linux guest OS for Xen.
#

import Xc, XenoUtil, sys, os

# Variable declaration. Set these up properly later on, as needed.
nfsserv = nfspath = root_partn = usr_partn = ""

# STEP 1. Specify kernel image file.
image = "FULL_PATH_TO_IMAGE"

# STEP 2. Specify IP address, netmask and gateway for the new domain.
ipaddr  = "ADDRESS"
netmask = XenoUtil.get_current_ipmask()
gateway = XenoUtil.get_current_ipgw()

# STEP 3a. Specify NFS server and path to rootfs (only needed for network boot)
nfsserv = "ADDRESS"
nfspath = "FULL_PATH_TO_ROOT_DIR"

# STEP 3b. Specify root (and possibly /usr) on local disc (if not NFS booting)
#root_partn = "/dev/sda2"
#usr_partn  = "/dev/sda6"

# STEP 4. Check that the following cmdline setup is to your taste.
cmdline = "ip="+ipaddr+":"+nfsserv+":"+gateway+":"+netmask+"::eth0:off"
if root_partn:
    # Boot from local disc. May specify a separate /usr.
    cmdline = cmdline + " root="+root_partn+" ro"
    if usr_partn:
        " usr="+usr_partn
elif nfsserv:
    # NFS boot
    cmdline = cmdline + " root=/dev/nfs"
    cmdline = cmdline + " nfsroot="+nfspath

if root_partn:
    root_info = XenoUtil.lookup_blkdev_partn_info(root_partn)
    if not root_info:
        print "Could not obtain info on partition '" + root_partn + "'"
        sys.exit()

if usr_partn:
    usr_info = XenoUtil.lookup_blkdev_partn_info(usr_partn)
    if not usr_info:
        print "Could not obtain info on partition '" + usr_partn + "'"
        sys.exit()

if not os.path.isfile( image ):
    print "Image file '" + image + "' does not exist"
    sys.exit()

xc = Xc.new()

id = xc.domain_create()
if id <= 0:
    print "Error creating domain"
    sys.exit()

if xc.linux_build( dom=id, image=image, cmdline=cmdline ):
    print "Error building Linux guest OS"
    xc.domain_destroy ( dom=id )
    sys.exit()

if root_partn:
    if xc.vbd_create( dom=id, vbd=root_info[0], writeable=1 ):
        print "Error creating root VBD"
        xc.domain_destroy ( dom=id )
        sys.exit()
    if xc.vbd_add_extent( dom=id,
                          vbd=root_info[0],
                          device=root_info[1],
                          start_sector=root_info[2],
                          nr_sectors=root_info[3] ):
        print "Error populating root VBD"
        xc.domain_destroy ( dom=id )
        sys.exit()

if usr_partn:
    if xc.vbd_create( dom=id, vbd=usr_info[0], writeable=0 ):
        print "Error creating usr VBD"
        xc.domain_destroy ( dom=id )
        sys.exit()
    if xc.vbd_add_extent( dom=id,
                          vbd=usr_info[0],
                          device=usr_info[1],
                          start_sector=usr_info[2],
                          nr_sectors=usr_info[3] ):
        print "Error populating usr VBD"
        xc.domain_destroy ( dom=id )
        sys.exit()

XenoUtil.setup_vfr_rules_for_vif( id, 0, ipaddr )

if xc.domain_start( dom=id ):
    print "Error starting domain"
    xc.domain_destroy ( dom=id )
    sys.exit()
