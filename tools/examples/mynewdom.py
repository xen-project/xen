#!/usr/bin/env python

# Example script for creating and building a new Linux guest OS for
# Xen.  THIS IS VERY SITE SPECIFIC, but shows an example configuration
# using multiple root partitions with a common /usr.  e.g. Domain1
# uses root /dev/sda8, usr /dev/sda6, and the next sequential IP address.

import Xc, XenoUtil, sys, os, socket, re

# Variable declaration. Set these up properly later on, as needed.
nfsserv = nfspath = root_partn = usr_partn = ""
shost = re.search( '([a-zA-Z]+)[-.]', socket.gethostname() ).group(1)

# STEP 1. Specify kernel image file.
image = "/usr/groups/srgboot/%s/xenolinux.gz" % shost

# STEP 2. How many megabytes of memory for the new domain?
memory_megabytes = 64

# STEP 3. A handy name for your new domain.
domain_name = "My new domain"

# Allocate new domain ad get its domain id
xc = Xc.new()
id = xc.domain_create( mem_kb=memory_megabytes*1024, name=domain_name )
if id <= 0:
    print "Error creating domain"
    sys.exit()

# Set the CPU, or leave to round robin allocation
#xc.domain_pincpu( dom=id, cpu=1 )

# STEP 4. Specify IP address, netmask and gateway for the new domain.
ipaddr  = XenoUtil.add_offset_to_ip(XenoUtil.get_current_ipaddr(),id)
netmask = XenoUtil.get_current_ipmask()
gateway = XenoUtil.get_current_ipgw()

# STEP 5a. Specify NFS server and path to rootfs (only needed for network boot)
#nfsserv = "ADDRESS"
#nfspath = "FULL_PATH_TO_ROOT_DIR"

# STEP 5b. Specify root partition on local disc (if not NFS booting)
root_partn = "/dev/sda%d" % (7+id)
# (NB. The following is only needed for a separate shared read-only /usr)
usr_partn  = "/dev/sda6"

# STEP 6. Check that the following cmdline setup is to your taste.
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
