#!/usr/bin/env python

import string
import sys
import os
import os.path
import time
import socket
import getopt
import signal
import syslog

import xenctl.console_client

from xenmgr import sxp
from xenmgr import PrettyPrint
from xenmgr.XendClient import server

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
                     Prints the config, suitable for -F.
 -q               -- Quiet - write output only to the system log
 -F domain_config -- Build domain using the config in the file.
                     Suitable files can be made using '-n' to output a config.
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
 -e vbd_expert    -- Safety catch to avoid some disk accidents ['%s'] 
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
image=''; ramdisk=''; builder_fn='linux'; restore=0; state_file=''
mem_size=0; domain_name=''; vfr_ipaddr=[];
vbd_expert='rr'; auto_restart=False;
vbd_list = []; cmdline_ip = ''; cmdline_root=''; cmdline_extra=''
pci_device_list = []; console_port = -1
auto_console = False
config_from_file = False

##### Determine location of defaults file
#####

try:
    opts, args = getopt.getopt(sys.argv[1:], "h?nqcf:F:D:k:r:b:m:N:a:e:d:i:I:R:E:L:" )

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
        if opt[0] == '-F': config_from_file = True; domain_config = opt[1]


except getopt.GetoptError:
    bail=True

if not config_from_file:
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

if not config_from_file:
    if not quiet:
        print "Parsing config file '%s'" % config_file

    try:
        execfile ( config_file )
    except (AssertionError,IOError):
        print >>sys.stderr,"Exiting %s" % sys.argv[0]
        bail = True

##### Print out config if necessary 
##### 

def bailout():
    global extrahelp
    main_usage()
    config_usage()
    if extrahelp: extra_usage()
    sys.exit(1)

if bail:
    bailout()

##### Parse any command line overrides 
##### 

x_vbd_list = []
x_vfr_ipaddr  = []

for opt in opts:
    if opt[0] == '-k': image = opt[1]
    if opt[0] == '-r': ramdisk = opt[1]
    if opt[0] == '-b': builder_fn = opt[1]  
    if opt[0] == '-m': mem_size = int(opt[1])
    if opt[0] == '-C': cpu = int(opt[1])
    if opt[0] == '-N': domain_name = opt[1]
    if opt[0] == '-a': auto_restart = answer(opt[1])
    if opt[0] == '-e': vbd_expert = opt[1]
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

syslog.openlog('xc_dom_create.py %s' % config_file, 0, syslog.LOG_DAEMON)

def strip(pre, s):
    if s.startswith(pre):
        return s[len(pre):]
    else:
        return s

def make_domain_config():
    global builder_fn, image, ramdisk, mem_size, domain_name
    global cpu
    global cmdline, cmdline_ip, cmdline_root
    global vfr_ipaddr, vbd_list, vbd_expert
    
    config = ['config',
              ['name', domain_name ],
              ['memory', mem_size ],
              ]
    if cpu:
        config.append(['cpu', cpu])
    
    config_image = [ builder_fn ]
    config_image.append([ 'kernel', os.path.abspath(image) ])
    if ramdisk:
        config_image.append([ 'ramdisk', os.path.abspath(ramdisk) ])
    if cmdline_ip:
        cmdline_ip = strip("ip=", cmdline_ip)
        config_image.append(['ip', cmdline_ip])
    if cmdline_root:
        cmdline_root = strip("root=", cmdline_root)
        config_image.append(['root', cmdline_root])
    if cmdline_extra:
        config_image.append(['args', cmdline_extra])
    config.append(['image', config_image ])
    	
    config_devs = []
    for (uname, dev, mode) in vbd_list:
        config_vbd = ['vbd',
                      ['uname', uname],
                      ['dev', dev ],
                      ['mode', mode ] ]
        if vbd_expert != 'rr':
            config_vbd.append(['sharing', vbd_expert])
        config_devs.append(['device', config_vbd])

    for (bus, dev, func) in pci_device_list:
        config_pci = ['pci',
                      ['bus', bus ],
                      ['dev', dev ],
                      ['func', func] ]
        config_devs.append(['device', config_pci])

    # Add one vif with unspecified MAC.
    config_devs.append(['device', ['vif']])

    config += config_devs
    
    config_vfr = ['vfr']
    idx = 0 # No way of saying which IP is for which vif?
    for ip in vfr_ipaddr:
        config_vfr.append(['vif', ['id', idx], ['ip', ip]])

    config.append(config_vfr)
    return config

def parse_config_file(domain_file):
    config = None
    fin = None
    try:
        fin = file(domain_file, "rb")
        config = sxp.parse(fin)
        if len(config) >= 1:
            config = config[0]
        else:
            raise StandardError("Invalid configuration")
    except StandardError, ex:
        print >> sys.stderr, "Error :", ex
        sys.exit(1)
    #finally:
    if fin: fin.close()
    return config

# This function creates, builds and starts a domain, using the values
# in the global variables, set above.  It is used in the subsequent
# code for starting the new domain and rebooting it if appropriate.
def make_domain(config):
    """Create, build and start a domain.
    Returns: [int] the ID of the new domain.
    """
    global restore

    if restore:
        dominfo = server.xend_domain_restore(state_file, config)
    else:
        dominfo = server.xend_domain_create(config)

    dom = int(sxp.child_value(dominfo, 'id'))
    console_info = sxp.child(dominfo, 'console')
    if console_info:
        console_port = int(sxp.child_value(console_info, 'port'))
    else:
        console_port = None
    
    if server.xend_domain_start(dom) < 0:
        print "Error starting domain"
        server.xend_domain_halt(dom)
        sys.exit()

    return (dom, console_port)

PID_DIR = '/var/run/xendomains/'

def pidfile(dom):
    return PID_DIR + '%d.pid' % dom

def mkpidfile():
    global current_id
    if not os.path.isdir(PID_DIR):
        os.mkdir(PID_DIR)

    fd = open(pidfile(current_id), 'w')
    print >> fd, str(os.getpid())
    fd.close()
    return

def rmpidfile():
    global current_id
    os.unlink(pidfile(current_id))

def death_handler(dummy1,dummy2):
    global current_id
    os.unlink(pidfile(current_id))
    output('Auto-restart daemon: daemon PID = %d for domain %d is now exiting'
              % (os.getpid(), current_id))
    sys.exit(0)
    return

#============================================================================
# The starting / monitoring of the domain actually happens here...

if config_from_file:
    config = parse_config_file(domain_config)
else:
    config = make_domain_config()

if dryrun:
    print "# %s" % ' '.join(sys.argv)
    PrettyPrint.prettyprint(config)
    sys.exit(0)
elif quiet:
    pass
else:
    PrettyPrint.prettyprint(config)

# start the domain and record its ID number
(current_id, current_port) = make_domain(config)

def start_msg(prefix, dom, port):
    output(prefix + "VM started in domain %d" % dom)
    if port:
        output(prefix + "Console I/O available on TCP port %d." % port)

start_msg('', current_id, current_port)

if current_port and auto_console:
    xenctl.console_client.connect('127.0.0.1', current_port)

# if the auto_restart flag is set then keep polling to see if the domain is
# alive - restart if it is not by calling make_domain() again (it's necessary
# to update the id variable, since the new domain may have a new ID)

#todo: Replace this - get xend to watch them.
if auto_restart:
    ARD = "Auto-restart daemon: "
    # turn ourselves into a background daemon
    try:
	pid = os.fork()
	if pid > 0:
	    sys.exit(0)
	os.setsid()
	pid = os.fork()
	if pid > 0:
            output(ARD + 'PID = %d' % pid)
	    sys.exit(0)
        signal.signal(signal.SIGTERM,death_handler)
    except OSError:
	print >> sys.stderr, ARD+'Startup failed'
	sys.exit(1)

    mkpidfile()

    while True:
	time.sleep(1)
        # todo: use new interface
        info = xc.domain_getinfo(current_id, 1)
	if info == [] or info[0]['dom'] != current_id:
	    output(ARD + "Domain %d terminated, restarting VM in new domain"
                                     % current_id)
            rmpidfile()
	    (current_id, current_port) = make_domain()
            mkpidfile()
            start_msg(ARD, current_id, current_port)
