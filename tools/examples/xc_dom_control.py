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
    dom = int(sys.argv[2])

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

	run   = (domain['running'] and 'r') or '-'
        block = (domain['blocked'] and 'b') or '-'
	stop  = (domain['stopped'] and 's') or '-'
	susp  = (domain['suspended'] and 'S') or '-'
	crash = (domain['crashed'] and 'c') or '-'

        domain['state'] = run + block + stop + susp + crash
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

    rc = xc.linux_save( dom=dom, state_file=file, progress=1)

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
