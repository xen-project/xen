#!/usr/bin/env python

#
# Example script for creating and building a new Linux guest OS for Xen.
# It takes an optional parameter that specifies offsets to be added to the
# ip address and root partition numbers, enabling multiple domains to be
# started from the one script.
#
# Edit as required...
#

import Xc, XenoUtil, string, sys, os, time, socket

# initialize a few variables that might come in handy
thishostname = socket.gethostname()
guestid = 0
if len(sys.argv) >= 2:
    guestid = string.atoi(sys.argv[1])
    print "Offset to add to guest's IP etc : %d\n" % guestid
 
##### This section of the code establishes various settings to be used 
##### for this guest virtual machine

# STEP 1. Specify kernel image file. Can be gzip'ed.
image = "../../../install/boot/xenolinux.gz"

# STEP 2. How many megabytes of memory for the new domain?
memory_megabytes = 64

# STEP 3. A handy name for your new domain.
domain_name = "This is VM %d" % guestid

# STEP 4. Specify IP address(es), netmask and gateway for the new
# domain.  You need to configure IP addrs within the domain just as
# you do normally.  This is just to let Xen know about them so it can
# route packets appropriately. 

#ipaddr = ["111.222.333.444","222.333.444.555"]
ipaddr  = [XenoUtil.add_offset_to_ip(XenoUtil.get_current_ipaddr(),guestid)]
netmask = XenoUtil.get_current_ipmask()
gateway = XenoUtil.get_current_ipgw()
nfsserv = '169.254.1.0'  # You need to set this if you're using NFS root

# STEP 5. Identify any physcial partitions or virtual disks you want the
# domain to have access to, and what you want them accessible as
# e.g. vbds = [ ('phy:sda1','sda1', 'w'),
#	 ('phy:sda4','sda%d' % (3+guestid), 'r'), 
#	 ('vd:as73gd784dh','hda1','w') ]

vbds = [ ('phy:sda%d'%(7+guestid),'sda1','w' ), 
	 ('phy:sda6','sda6','r'),
	 ('phy:cdrom','hdd','r') ]

# STEP 5b. Set the VBD expertise level.  Most people should leave this
# on 0, at least to begin with - this script can detect most dangerous
# disk sharing between domains and with this set to zero it will only
# allow read only sharing.
vbd_expert = 0

# STEP 6. Build the command line for the new domain. Edit as req'd.
# You only need the ip= line if you're NFS booting or the root file system
# doesn't set it later e.g. in ifcfg-eth0 or via DHCP
# You can use 'extrabit' to set the runlevel and custom environment
# variables used by custom rc scripts (e.g. DOMID=, usr= )

ipbit = "ip="+ipaddr[0]+":"+nfsserv+":"+gateway+":"+netmask+"::eth0:off"
rootbit = "root=/dev/sda1 ro"
#rootbit = "root=/dev/nfs nfsroot=/full/path/to/root/directory"
extrabit = "4 DOMID=%d usr=/dev/sda6" % guestid 
cmdline = ipbit +" "+ rootbit +" "+ extrabit

# STEP 7. Set according to whether you want the script to watch the domain 
# and auto-restart it should it die or exit.

auto_restart = False
#auto_restart = True


##### Print some debug info just incase things don't work out...
##### 

print "Domain image          : ", image
print "Domain memory         : ", memory_megabytes
print "Domain IP address(es) : ", ipaddr 
print "Domain block devices  : ", vbds
print 'Domain cmdline        : "%s"' % cmdline


##### Code beyond this point is actually used to manage the mechanics of
##### starting (and watching if necessary) guest virtual machines.

# Obtain an instance of the Xen control interface
xc = Xc.new()

# This function creates, builds and starts a domain, using the values
# in the global variables, set above.  It is used in the subsequent
# code for starting the new domain and rebooting it if appropriate.
def make_domain():
    """Create, build and start a domain.
    Returns: [int] the ID of the new domain.
    """

    # set up access to the global variables declared above
    global image, memory_megabytes, domain_name, ipaddr, netmask
    global vbds, cmdline, xc, vbd_expert
    	
    if not os.path.isfile( image ):
        print "Image file '" + image + "' does not exist"
        sys.exit()

    id = xc.domain_create( mem_kb=memory_megabytes*1024, name=domain_name )
    print "Created new domain with id = " + str(id)
    if id <= 0:
        print "Error creating domain"
        sys.exit()

    ret = xc.linux_build( dom=id, image=image, cmdline=cmdline )
    if ret < 0:
        print "Error building Linux guest OS: "
        print "Return code from linux_build = " + str(ret)
        xc.domain_destroy ( dom=id )
        sys.exit()

    # setup the virtual block devices

    # set the expertise level appropriately
    XenoUtil.VBD_EXPERT_MODE = vbd_expert
    
    for ( uname, virt_name, rw ) in vbds:
	virt_dev = XenoUtil.blkdev_name_to_number( virt_name )

	segments = XenoUtil.lookup_disk_uname( uname )
	if not segments:
	    print "Error looking up %s\n" % uname
	    xc.domain_destroy ( dom=id )
	    sys.exit()

        # check that setting up this VBD won't violate the sharing
        # allowed by the current VBD expertise level
        if XenoUtil.vd_extents_validate(segments, rw=='w') < 0:
            xc.domain_destroy( dom = id )
            sys.exit()
            
	if xc.vbd_create( dom=id, vbd=virt_dev, writeable= rw=='w' ):
	    print "Error creating VBD vbd=%d writeable=%d\n" % (virt_dev,rw)
	    xc.domain_destroy ( dom=id )
	    sys.exit()

        if xc.vbd_setextents( dom=id,
                              vbd=virt_dev,
                              extents=segments):
            print "Error populating VBD vbd=%d\n" % virt_dev
            xc.domain_destroy ( dom=id )
            sys.exit()

    # setup virtual firewall rules for all aliases
    for ip in ipaddr:
	XenoUtil.setup_vfr_rules_for_vif( id, 0, ip )

    if xc.domain_start( dom=id ) < 0:
        print "Error starting domain"
        xc.domain_destroy ( dom=id )
        sys.exit()

    return id
# end of make_domain()



# The starting / monitoring of the domain actually happens here...

# start the domain and record its ID number
current_id = make_domain()

# if the auto_restart flag is set then keep polling to see if the domain is
# alive - restart if it is not by calling make_domain() again (it's necessary
# to update the id variable, since the new domain may have a new ID)

while auto_restart:
    time.sleep(1)
    if not xc.domain_getinfo(current_id):
        print "The virtual machine has terminated, restarting in a new domain"
        current_id = make_domain()
