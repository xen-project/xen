#!/usr/bin/env python

# usage: xc_dom_control [command] <params>
#
# this script isn't very smart, but it'll do for now.
#

def usage ():
    print >>sys.stderr, """
Usage: %s [command] <params>

  stop      [dom]        -- pause a domain
  start     [dom]        -- un-pause a domain
  shutdown  [dom]        -- request a domain to shutdown
  destroy   [dom]        -- immediately terminate a domain
  pincpu    [dom] [cpu]  -- pin a domain to the specified CPU
  save      [dom] [file] -- suspend a domain's memory to file
  restore   [file]       -- resume a domain from a file
  list                   -- print info about all domains
  listvbds               -- print info about all virtual block devs
  cpu_bvtset [dom] [mcuadv] [warp] [warpl] [warpu]
                         -- set scheduling parameters for domain
  cpu_bvtslice [slice]   -- default scheduler slice
  vif_stats [dom] [vif]  -- get stats for a given network vif
  vif_addip [dom] [vif] [ip]  -- add an IP address to a given vif
  vif_setsched [dom] [vif] [bytes] [usecs] -- rate limit vif bandwidth
  vif_getsched [dom] [vif] -- print vif's scheduling parameters
  vbd_add [dom] [uname] [dev] [mode] -- make disk/partition uname available to 
                            domain as dev e.g. 'vbd_add phy:sda3 hda1 rw'
  vbd_remove [dom] [dev] -- remove disk or partition attached as 'dev' 
""" % sys.argv[0]

import Xc, sys, re, string

if len(sys.argv) < 2:
    usage()
    sys.exit(-1)

cmd = sys.argv[1]


xc = Xc.new()
rc = ''

if len( sys.argv ) > 2 and re.match('\d+$', sys.argv[2]):
    dom = string.atoi(sys.argv[2])

if cmd == 'stop':
    rc = xc.domain_stop( dom=dom )

elif cmd == 'start':
    rc = xc.domain_start( dom=dom )    

elif cmd == 'shutdown':
    rc = xc.domain_destroy( dom=dom, force=0 )    

elif cmd == 'destroy':
    rc = xc.domain_destroy( dom=dom, force=1 )    

elif cmd == 'pincpu':

    if len(sys.argv) < 4:
        usage()
        sys.exit(-1)

    cpu = int(sys.argv[3])
    orig_state = xc.domain_getinfo(first_dom=dom, max_doms=1)[0]['stopped']

    while xc.domain_getinfo(first_dom=dom, max_doms=1)[0]['stopped'] != 1:
	xc.domain_stop( dom=dom )
	time.sleep(0.1)

    rc = xc.domain_pincpu( dom, cpu )

    if orig_state == 0:
	xc.domain_start( dom=dom )

elif cmd == 'list':
    for i in xc.domain_getinfo(): print i

elif cmd == 'listvbds':
    for i in xc.vbd_probe(): print i

elif cmd == 'save':
    if len(sys.argv) < 4:
        usage()
        sys.exit(-1)

    file = sys.argv[3]
        
    rc = xc.linux_save( dom=dom, state_file=file, progress=1)

elif cmd == 'restore':
    if len(sys.argv) < 3:
        usage()
        sys.exit(-1)
        
    file = sys.argv[2]
    rc = xc.linux_restore( state_file=file, progress=1 )

elif cmd == 'cpu_bvtslice':
    if len(sys.argv) < 3:
        usage()
        sys.exit(-1)

    slice = dom # first int argument is in "dom" (!)

    rc = xc.bvtsched_global_set(ctx_allow=slice)

elif cmd == 'cpu_bvtset':
    if len(sys.argv) < 7:
        usage()
        sys.exit(-1)

    mcuadv = int(sys.argv[3])
    warp   = int(sys.argv[4])
    warpl  = int(sys.argv[5])
    warpu  = int(sys.argv[6])

    rc = xc.bvtsched_domain_set(dom=dom, mcuadv=mcuadv, warp=warp,
                                warpl=warpl, warpu=warpu)
elif cmd == 'vif_stats':
    if len(sys.argv) < 4:
        usage()
        sys.exit(-1)

    vif = int(sys.argv[3])

    print xc.vif_stats_get(dom=dom, vif=vif)

elif cmd == 'vif_addip':
    if len(sys.argv) < 5:
        usage()
        sys.exit(-1)

    vif = int(sys.argv[3])
    ip  = sys.argv[4]

    # XXX This function should be moved to Xc once we sort out the VFR
    import XenoUtil
    XenoUtil.setup_vfr_rules_for_vif( dom, vif, ip )

elif cmd == 'vif_setsched':
    if len(sys.argv) < 6:
        usage()
        sys.exit(-1)

    vif = int(sys.argv[3])
    credit_bytes = int(sys.argv[4])
    credit_usecs = int(sys.argv[5])

    rc = xc.xc_vif_scheduler_set(dom=dom, vif=vif, 
				 credit_bytes=credit_bytes, 
				 credit_usecs=credit_usecs)

elif cmd == 'vif_getsched':
    if len(sys.argv) < 4:
        usage()
        sys.exit(-1)

    vif = int(sys.argv[3])

    print xc.vif_scheduler_get(dom=dom, vif=vif)


elif cmd == 'vbd_add':

    XenoUtil.VBD_EXPERT_LEVEL = 0 # sets the allowed level of potentially unsafe mappings

    if len(sys.argv) < 6:
	usage()
	sys.exit(1)

    uname = sys.argv[3]
    dev = sys.argv[4]
    mode = sys.argv[5]

    writeable = 0
    if mode == 'rw' or mode == 'w':
	writeable = 1;

    segments = XenoUtil.lookup_disk_uname(uname)

    if XenoUtil.vd_extents_validate(segments,writeable) < 0:
	print "That mapping is too unsafe for the current VBD expertise level"
	sys.exit(1)

    virt_dev = XenoUtil.blkdev_name_to_number(dev)

    xc.vbd_create(dom,virt_dev,writeable)

    if xc.vbd_setextents( dom, virt_dev, segments ):
	print "Error populating VBD vbd=%d\n" % virt_dev
	sys.exit(1)

    print "Added disk/partition %s to domain %d as device %s (%x)" % (uname, dom, dev, virt_dev)

elif cmd == 'vbd_remove':

    if len(sys.argv) < 4:
	usage()
	sys.exit(1)

    dev = sys.argv[3]
    virt_dev = XenoUtil.blkdev_name_to_number(dev)

    if not xc.vbd_destroy(dom,virt_dev):
	print "Removed disk/partition attached as device %s (%x) in domain %d" % (dev, virt_dev, dom)
    else:
	print "Failed"
	sys.exit(1)


else:
    usage()
    sys.exit(-1)

if rc != '':
    print "return code %d" % rc
