#!/usr/bin/env python

import string, sys, os, time, socket, getopt, signal, syslog
import Xc, xenctl.utils, xenctl.console_client, re

config_dir  = '/etc/xc/'
config_file = xc_config_file = config_dir + 'defaults'

def main_usage ():
    print >>sys.stderr,"""
Usage: %s <args>

This tool is used to create and start new domains. It reads defaults
from a file written in Python, having allowed variables to be set and
passed into the file. Further command line arguments allow the
defaults to be overridden. The defaults for each parameter are listed
in [] brackets. Arguments are as follows:

Arguments to control the parsing of the defaults file:
 -f config_file   -- Use the specified defaults script. 
                     Default: ['%s']
 -L state_file    -- Load virtual machine memory state from state_file
 -D foo=bar       -- Set variable foo=bar before parsing config
                     E.g. '-D vmid=3;ip=1.2.3.4'
 -h               -- Print extended help message, including all arguments
 -n               -- Dry run only, don't actually create domain
 -q               -- Quiet - write output only to the system log
""" % (sys.argv[0], xc_config_file)

def extra_usage ():
    print >>sys.stderr,"""
Arguments to override current config read from '%s':
 -c               -- Turn into console terminal after domain is created
 -k image         -- Path to kernel image ['%s']
 -r ramdisk       -- Path to ramdisk (or empty) ['%s']
 -b builder_fn    -- Function to use to build domain ['%s']
 -m mem_size      -- Initial memory allocation in MB [%dMB]
 -N domain_name   -- Set textual name of domain ['%s']
 -a auto_restart  -- Restart domain on exit, yes/no ['%d']
 -e vbd_expert    -- Saftey catch to avoid some disk accidents ['%d'] 
 -d udisk,dev,rw  -- Add disk, partition, or virtual disk to domain. E.g. to 
                     make partion sda4 available to the domain as hda1 with 
                     read-write access: '-d phy:sda4,hda1,rw' To add 
                     multiple disks use multiple -d flags or seperate with ';'
                     Default: ['%s']
 -i vfr_ipaddr    -- Add IP address to the list which Xen will route to
                     the domain. Use multiple times to add more IP addrs.
		     Default: ['%s']

Args to override the kernel command line, which is concatenated from these:
 -I cmdline_ip    -- Override 'ip=ipaddr:nfsserv:gateway:netmask::eth0:off'
                     Default: ['%s']
 -R cmdline_root  -- Override root device parameters.
                     Default: ['%s']
 -E cmdline_extra -- Override extra kernel args and rc script env vars.
                     Default: ['%s']

""" % (config_file,
       image, ramdisk, builder_fn, mem_size, domain_name, auto_restart,
       vbd_expert, 
       printvbds( vbd_list ), 
       reduce ( (lambda a,b: a+':'+b), vfr_ipaddr,'' )[1:],
       cmdline_ip, cmdline_root, cmdline_extra)

def config_usage (): pass

def answer ( s ):
    s = string.lower(s)
    if s == 'yes' or s == 'true' or s == '1': return 1
    return 0

def printvbds ( v ):
    s=''
    for (a,b,c) in v:
	s = s + '; %s,%s,%s' % (a,b,c)
    return s[2:]

def output(string):
    global quiet
    syslog.syslog(string)
    if not quiet:
        print string
    return

bail=False; dryrun=False; extrahelp=False; quiet = False
image=''; ramdisk=''; builder_fn=''; restore=0; state_file=''
mem_size=0; domain_name=''; vfr_ipaddr=[];
vbd_expert=0; auto_restart=False;
vbd_list = []; cmdline_ip = ''; cmdline_root=''; cmdline_extra=''
pci_device_list = []; console_port = -1
auto_console = False

##### Determine location of defaults file
#####

try:
    opts, args = getopt.getopt(sys.argv[1:], "h?nqcf:D:k:r:b:m:N:a:e:d:i:I:R:E:L:" )

    for opt in opts:
	if opt[0] == '-f': config_file= opt[1]
	if opt[0] == '-h' or opt[0] == '-?' : bail=True; extrahelp=True
	if opt[0] == '-n': dryrun=True
	if opt[0] == '-D': 
	    for o in string.split( opt[1], ';' ):
		(l,r) = string.split( o, '=' )
		exec "%s='%s'" % (l,r)
        if opt[0] == '-q': quiet = True
        if opt[0] == '-L': restore = True; state_file = opt[1]


except getopt.GetoptError:
    bail=True


try:
    os.stat( config_file )
except:
    try:
	d = config_dir + config_file
	os.stat( d )
	config_file = d
    except:
	print >> sys.stderr, "Unable to open config file '%s'" % config_file
	bail = True


##### Parse the config file
#####

if not quiet:
    print "Parsing config file '%s'" % config_file

try:
    execfile ( config_file )
except (AssertionError,IOError):
    print >>sys.stderr,"Exiting %s" % sys.argv[0]
    bail = True

##### Print out config if necessary 
##### 

if bail:
    main_usage()
    config_usage()
    if extrahelp: extra_usage()
    sys.exit(1)

##### Parse any command line overrides 
##### 

x_vbd_list = []
x_vfr_ipaddr  = []

for opt in opts:
    if opt[0] == '-k': image = opt[1]
    if opt[0] == '-r': ramdisk = opt[1]
    if opt[0] == '-b': builder_fn = opt[1]  
    if opt[0] == '-m': mem_size = int(opt[1])
    if opt[0] == '-N': domain_name = opt[1]
    if opt[0] == '-a': auto_restart = answer(opt[1])
    if opt[0] == '-e': vbd_expert = answer(opt[1])
    if opt[0] == '-I': cmdline_ip = opt[1]
    if opt[0] == '-R': cmdline_root = opt[1]
    if opt[0] == '-E': cmdline_extra = opt[1]
    if opt[0] == '-i': x_vfr_ipaddr.append(opt[1])
    if opt[0] == '-c': auto_console = True
    if opt[0] == '-d':
	try:
	    vv = string.split(opt[1],';')	    
	    for v in vv:
		(udisk,dev,mode) = string.split(v,',')
		x_vbd_list.append( (udisk,dev,mode) )
	except:
	    print >>sys.stderr, "Invalid block device specification : %s" % opt[1]
	    sys.exit(1)

if x_vbd_list: vbd_list = x_vbd_list
if x_vfr_ipaddr: vfr_ipaddr = x_vfr_ipaddr

cmdline = cmdline_ip +' '+ cmdline_root +' '+ cmdline_extra

syslog.openlog('xc_dom_create.py %s' % config_file, 0, syslog.LOG_DAEMON)

##### Print some debug info just in case things don't work out...
##### 

output('VM image           : "%s"' % image)
output('VM ramdisk         : "%s"' % ramdisk)
output('VM memory (MB)     : "%d"' % mem_size)
output('VM IP address(es)  : "%s"'
                % reduce((lambda a,b: a+'; '+b),vfr_ipaddr,'' )[2:])
output('VM block device(s) : "%s"' % printvbds( vbd_list ))
output('VM cmdline         : "%s"' % cmdline)

if dryrun:
    sys.exit(1)

##### HACK HACK HACK
##### Until everyone moves to the new I/O world, and a more robust domain
##### controller (xend), we use this little trick to discover whether we
##### are in a testing environment for new I/O stuff.
new_io_world = True
for line in os.popen('cat /proc/interrupts').readlines():
    if re.search('blkdev', line):
        new_io_world = False

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
    global image, ramdisk, mem_size, domain_name, vfr_ipaddr, netmask
    global vbd_list, cmdline, xc, vbd_expert, builder_fn
    	
    if not os.path.isfile( image ):
        print "Image file '" + image + "' does not exist"
        sys.exit()

    if ramdisk and not os.path.isfile( ramdisk ):
        print "Ramdisk file '" + ramdisk + "' does not exist"
        sys.exit()

    id = xc.domain_create( mem_kb=mem_size*1024, name=domain_name )
    if id <= 0:
	print "Error creating domain"
	sys.exit()

    cmsg = 'new_control_interface(dom='+str(id)+', console_port='+str(console_port)+')'

    cons_response = xenctl.utils.xend_control_message(cmsg)

    if not cons_response['success']:
	print "Error creating initial event channel"
	print "Error type: " + cons_response['error_type']
	if cons_response['error_type'] == 'exception':
	    print "Exception type: " + cons_response['exception_type']
	    print "Exception value: " + cons_response['exception_value']
	xc.domain_destroy ( dom=id )
	sys.exit()

    # will the domain have IO privileges?
    if pci_device_list != []: io_priv = True
    else:                     io_priv = False

    if restore:
        ret = eval('xc.%s_restore ( dom=id, state_file=state_file, progress=1)' % (builder_fn) )
        if ret < 0:
            print "Error restoring domain"
            print "Return code = " + str(ret)
            xc.domain_destroy ( dom=id )
            sys.exit()
    else:

        ret = eval('xc.%s_build ( dom=id, image=image, ramdisk=ramdisk, cmdline=cmdline, control_evtchn=cons_response["remote_port"], io_priv=%d )' % (builder_fn, io_priv) )
        if ret < 0:
            print "Error building Linux guest OS: "
            print "Return code = " + str(ret)
            xc.domain_destroy ( dom=id )
            sys.exit()

    # setup the virtual block devices

    # set the expertise level appropriately
    xenctl.utils.VBD_EXPERT_MODE = vbd_expert

    if new_io_world:
        cmsg = 'new_block_interface(dom='+str(id)+')'
        xend_response = xenctl.utils.xend_control_message(cmsg)
        if not xend_response['success']:
            print "Error creating block interface"
            print "Error type: " + xend_response['error_type']
            if xend_response['error_type'] == 'exception':
                print "Exception type: " + xend_response['exception_type']
                print "Exception val:  " + xend_response['exception_value']
            xc.domain_destroy ( dom=id )
            sys.exit()
    
    for ( uname, virt_name, rw ) in vbd_list:
	virt_dev = xenctl.utils.blkdev_name_to_number( virt_name )

	segments = xenctl.utils.lookup_disk_uname( uname )
	if not segments:
	    print "Error looking up %s\n" % uname
	    xc.domain_destroy ( dom=id )
	    sys.exit()

        if new_io_world:
            if len(segments) > 1:
                print "New I/O world cannot deal with multi-extent vdisks"
                xc.domain_destroy ( dom=id )
                sys.exit()
            seg = segments[0]
            cmsg = 'new_block_device(dom=' + str(id) + \
                   ',handle=0,vdev=' + str(virt_dev) + \
                   ',pdev=' + str(seg['device']) + \
                   ',start_sect=' + str(seg['start_sector']) + \
                   ',nr_sect=' + str(seg['nr_sectors']) + \
                   ',readonly=' + str(not re.match('w',rw)) + ')'
            xend_response = xenctl.utils.xend_control_message(cmsg)
            if not xend_response['success']:
                print "Error creating virtual block device"
                print "Error type: " + xend_response['error_type']
                if xend_response['error_type'] == 'exception':
                    print "Exception type: " + xend_response['exception_type']
                    print "Exception val:  " + xend_response['exception_value']
                xc.domain_destroy ( dom=id )
                sys.exit()
        else:
            # check that setting up this VBD won't violate the sharing
            # allowed by the current VBD expertise level
            if xenctl.utils.vd_extents_validate(segments,
                                                rw=='w' or rw=='rw') < 0:
                xc.domain_destroy( dom = id )
                sys.exit()
            
            if xc.vbd_create( dom=id, vbd=virt_dev,
                              writeable= rw=='w' or rw=='rw' ):
                print "Error creating VBD %d (writeable=%d)\n" % (virt_dev,rw)
                xc.domain_destroy ( dom=id )
                sys.exit()
	
            if xc.vbd_setextents( dom=id,
                                  vbd=virt_dev,
                                  extents=segments):
                print "Error populating VBD vbd=%d\n" % virt_dev
                xc.domain_destroy ( dom=id )
                sys.exit()

    if not new_io_world:
        # setup virtual firewall rules for all aliases
        for ip in vfr_ipaddr:
            xenctl.utils.setup_vfr_rules_for_vif( id, 0, ip )

    if new_io_world:
        # check for physical device access
        for (pci_bus, pci_dev, pci_func) in pci_device_list:
            if xc.physdev_pci_access_modify(
                dom=id, bus=pci_bus, dev=pci_dev,
                func=pci_func, enable=1 ) < 0:
                print "Non-fatal error enabling PCI device access."
            else:
                print "Enabled PCI access (%d:%d:%d)." % \
                      (pci_bus,pci_dev,pci_func)
		
    if restore:
	# send an unsolicited ARP reply for all non link-local IPs
	gw=xenctl.utils.get_current_ipgw()
	if gw == '': gw='255.255.255.255'
	nlb=open('/proc/sys/net/ipv4/ip_nonlocal_bind','r').read()[0]=='1'
	if not nlb: print >>open('/proc/sys/net/ipv4/ip_nonlocal_bind','w'), '1'
	for ip in vfr_ipaddr:
	    if not xenctl.utils.check_subnet(ip,'169.254.0.0','255.255.0.0'):
		print     '/usr/sbin/arping -A -b -I eth0 -c 1 -s %s %s' % (ip,gw)
		os.system('/usr/sbin/arping -A -b -I eth0 -c 1 -s %s %s' % (ip,gw))
	if not nlb: print >>open('/proc/sys/net/ipv4/ip_nonlocal_bind','w'), '0'

    if xc.domain_start( dom=id ) < 0:
        print "Error starting domain"
        xc.domain_destroy ( dom=id )
        sys.exit()

    return (id, cons_response['console_port'])
# end of make_domain()

def mkpidfile():
    global current_id
    if not os.path.isdir('/var/run/xendomains/'):
        os.mkdir('/var/run/xendomains/')

    fd = open('/var/run/xendomains/%d.pid' % current_id, 'w')
    print >> fd, str(os.getpid())
    fd.close()
    return

def rmpidfile():
    global current_id
    os.unlink('/var/run/xendomains/%d.pid' % current_id)

def death_handler(dummy1,dummy2):
    global current_id
    os.unlink('/var/run/xendomains/%d.pid' % current_id)
    output('Auto-restart daemon: daemon PID = %d for domain %d is now exiting'
              % (os.getpid(),current_id))
    sys.exit(0)
    return

# The starting / monitoring of the domain actually happens here...

# start the domain and record its ID number
(current_id, current_port) = make_domain()
output("VM started in domain %d. Console I/O available on TCP port %d." % (current_id,current_port))

if auto_console:
    xenctl.console_client.connect('127.0.0.1',int(current_port))

# if the auto_restart flag is set then keep polling to see if the domain is
# alive - restart if it is not by calling make_domain() again (it's necessary
# to update the id variable, since the new domain may have a new ID)

if auto_restart:
    # turn ourselves into a background daemon
    try:
	pid = os.fork()
	if pid > 0:
	    sys.exit(0)
	os.setsid()
	pid = os.fork()
	if pid > 0:
            output('Auto-restart daemon PID = %d' % pid)
	    sys.exit(0)
        signal.signal(signal.SIGTERM,death_handler)
    except OSError:
	print >> sys.stderr, 'Problem starting auto-restart daemon'
	sys.exit(1)

    mkpidfile()

    while True:
	time.sleep(1)
        info = xc.domain_getinfo(current_id, 1)
	if info == [] or info[0]['dom'] != current_id:
	    output("Auto-restart daemon: Domain %d has terminated, restarting VM in new domain"
                                     % current_id)
            rmpidfile()
	    (current_id, current_port) = make_domain()
            mkpidfile()
	    output("Auto-restart daemon: VM restarted in domain %d. Console on port %d." % (current_id,current_port))
