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
  shutdown  [dom] [[-w]] -- request a domain to shutdown (can specify 'all')
                            (optionally wait for complete shutdown)
  destroy   [dom]        -- immediately terminate a domain
  pincpu    [dom] [cpu]  -- pin a domain to the specified CPU
  suspend   [dom] [file] -- write domain's memory to a file and terminate
			    (resume by re-running xc_dom_create with -L option)
  unwatch   [dom]        -- kill the auto-restart daemon for a domain
  list                   -- print info about all domains
  listvbds               -- print info about all virtual block devs
  cpu_bvtset [dom] [mcuadv] [warp] [warpl] [warpu]
                         -- set BVT scheduling parameters for domain
  cpu_bvtslice [slice]   -- set default BVT scheduler slice
  cpu_atropos_set [dom] [period] [slice] [latency] [xtratime]
                         -- set Atropos scheduling parameters for domain
  cpu_rrobin_slice [slice] -- set Round Robin scheduler slice
  vif_stats [dom] [vif]  -- get stats for a given network vif
  vif_addip [dom] [vif] [ip]  -- add an IP address to a given vif
  vif_setsched [dom] [vif] [bytes] [usecs] -- rate limit vif bandwidth
  vif_getsched [dom] [vif] -- print vif's scheduling parameters
  vbd_add [dom] [uname] [dev] [mode] -- make disk/partition uname available to 
                            domain as dev e.g. 'vbd_add 2 phy:sda3 hda1 w'
  vbd_remove [dom] [dev] -- remove disk or partition attached as 'dev' 
""" % sys.argv[0]

import Xc, sys, re, string, time, os, signal

if len(sys.argv) < 2:
    usage()
    sys.exit(-1)

cmd = sys.argv[1]


xc = Xc.new()
rc = ''
dom = None


if len( sys.argv ) > 2 and re.match('\d+$', sys.argv[2]):
    dom = long(sys.argv[2])

if cmd == 'stop':
    rc = xc.domain_stop( dom=dom )

elif cmd == 'start':
    rc = xc.domain_start( dom=dom )    

elif cmd == 'shutdown':
    list = []
    if dom != None:
        rc = xc.domain_destroy( dom=dom, force=0 )
        list.append(dom)
    elif sys.argv[2] == 'all':
        for i in xc.domain_getinfo():
            if i['dom'] != 0: # don't shutdown dom0!
                ret = xc.domain_destroy( dom=i['dom'], force=0 )
                if ret !=0: rc = ret
                else: list.append(i['dom'])

    if len(sys.argv) == 4 and sys.argv[3] == "-w":
        # wait for all domains we shut down to terminate
        for dom in list:
            while True:
                info = xc.domain_getinfo(dom,1)
                if not ( info != [] and info[0]['dom'] == dom ): break
                time.sleep(1)

elif cmd == 'destroy':
    rc = xc.domain_destroy( dom=dom, force=1 )    

elif cmd == 'pincpu':

    if len(sys.argv) < 4:
        usage()
        sys.exit(-1)

    cpu = int(sys.argv[3])
    
    rc = xc.domain_pincpu( dom, cpu )

elif cmd == 'list':
    print 'Dom  Name             Mem(kb)  CPU  State  Time(ms)'
    for domain in xc.domain_getinfo():

	run = (domain['running'] and 'r') or '-'		# domain['running'] ? run='r' : run='-'
	stop = (domain['stopped'] and 's') or '-'		# domain['stopped'] ? stop='s': stop='-'

        domain['state'] = run + stop
        domain['cpu_time'] = domain['cpu_time']/1e6

        print "%(dom)-4d %(name)-16s %(mem_kb)7d %(cpu)3d %(state)5s %(cpu_time)8d" % domain

elif cmd == 'unwatch':

    # the auto-restart daemon's pid file
    watcher = '/var/run/xendomains/%d.pid' % dom

    if os.path.isfile(watcher):
        fd = open(watcher,'r')
        pid = int(fd.readline())
        os.kill(pid, signal.SIGTERM)

elif cmd == 'listvbds':
    print 'Dom   Dev   Perm   Size(MB)'
    
    for vbd in xc.vbd_probe():
        vbd['size_mb'] = vbd['nr_sectors'] / 2048
        vbd['perm'] = (vbd['writeable'] and 'w') or 'r'
        print '%(dom)-4d  %(vbd)04x  %(perm)-1s      %(size_mb)d' % vbd

elif cmd == 'suspend':
    if len(sys.argv) < 4:
        usage()
        sys.exit(-1)

    file = sys.argv[3]

    # the auto-restart daemon's pid file
    watcher = '/var/run/xendomains/%d.pid' % dom

    if os.path.isfile(watcher):
        fd = open(watcher,'r')
        pid = int(fd.readline())
        os.kill(pid, signal.SIGTERM)

    xc.domain_stop( dom=dom )
    
    while not xc.domain_getinfo( first_dom=dom, max_doms=1 )[0]['stopped']:
	print "Sleep..."
	time.sleep(0.001);

    rc = xc.linux_save( dom=dom, state_file=file, progress=1)
    if rc == 0 : xc.domain_destroy( dom=dom, force=1 )
    else: xc.domain_start( dom=dom )  # sensible for production use

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
    import xenctl.utils
    xenctl.utils.setup_vfr_rules_for_vif( dom, vif, ip )

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
    import xenctl.utils
    
    xenctl.utils.VBD_EXPERT_LEVEL = 0 # sets the allowed level of potentially unsafe mappings

    if len(sys.argv) < 6:
	usage()
	sys.exit(1)

    uname = sys.argv[3]
    dev = sys.argv[4]
    mode = sys.argv[5]

    writeable = 0
    if mode == 'rw' or mode == 'w':
	writeable = 1;

    segments = xenctl.utils.lookup_disk_uname(uname)

    if not segments:
        print "Lookup Failed"
        sys.exit(1)

    if xenctl.utils.vd_extents_validate(segments,writeable) < 0:
	print "That mapping is too unsafe for the current VBD expertise level"
	sys.exit(1)

    virt_dev = xenctl.utils.blkdev_name_to_number(dev)

    xc.vbd_create(dom,virt_dev,writeable)

    if xc.vbd_setextents( dom, virt_dev, segments ):
	print "Error populating VBD vbd=%d\n" % virt_dev
	sys.exit(1)

    print "Added disk/partition %s to domain %d as device %s (%x)" % (uname, dom, dev, virt_dev)

elif cmd == 'vbd_remove':
    import xenctl.utils

    if len(sys.argv) < 4:
	usage()
	sys.exit(1)

    dev = sys.argv[3]
    virt_dev = xenctl.utils.blkdev_name_to_number(dev)

    if not xc.vbd_destroy(dom,virt_dev):
	print "Removed disk/partition attached as device %s (%x) in domain %d" % (dev, virt_dev, dom)
    else:
	print "Failed"
	sys.exit(1)

elif cmd == 'cpu_atropos_set': # args: dom period slice latency xtratime
    if len(sys.argv) < 6:
        usage()
        sys.exit(1)

    (period, slice, latency, xtratime) = map(lambda x: int(x), sys.argv[3:7])
    
    rc = xc.atropos_domain_set(dom, period, slice, latency, xtratime)

elif cmd == 'cpu_rrobin_slice':
    rc = xc.rrobin_global_set(slice=int(sys.argv[2]))

else:
    usage()
    sys.exit(-1)

if rc != '':
    print "return code %d" % rc
