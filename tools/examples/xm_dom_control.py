#!/usr/bin/env python

import sys
import re
import string
import time
import os
import os.path
import signal

from xenmgr import sxp
from xenmgr.XendClient import server

# usage: xc_dom_control [command] <params>
#
# this script isn't very smart, but it'll do for now.
#

def usage (rc=0):
    if rc:
        out = sys.stderr
    else:
        out = sys.stdout
    print >> out, """
Usage: %s [command] <params>

  help                   -- print usage
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
    if rc: sys.exit(rc)

if len(sys.argv) < 2: usage(1)
cmd = sys.argv[1]

#todo: replace all uses of xc with the new api.
import Xc; xc = Xc.new()

rc = ''
dom = None


def auto_restart_pid_file(dom):
    # The auto-restart daemon's pid file.
    return '/var/run/xendomains/%d.pid' % dom

def auto_restart_pid(dom):
    watcher = auto_restart_pid_file(dom)
    if os.path.isfile(watcher):
        fd = open(watcher,'r')
        pid = int(fd.readline())
    else:
        pid = None
    return pid
 
def auto_restart_kill(dom):
    #todo: replace this - tell xend not to restart any more.
    # Kill a domain's auto restart daemon.
    pid = auto_restart_pid(dom)
    if pid:
        os.kill(pid, signal.SIGTERM)


if len( sys.argv ) > 2 and re.match('\d+$', sys.argv[2]):
    dom = long(sys.argv[2])

if cmd == "help":
    usage()
    
elif cmd == 'stop':
    rc = server.xend_domain_stop(dom)

elif cmd == 'start':
    rc = server.xend_domain_start(dom)    

elif cmd == 'shutdown':
    doms = []
    shutdown = []
    if dom != None:
        doms = [ dom ]
    elif sys.argv[2] == 'all':
        doms = server.xend_domains()
        doms.remove('0')
    for d in doms:
        ret = server.xend_domain_shutdown(d)
        if ret == 0:
            shutdown.append(d)
        else:
            rc = ret

    wait = (len(sys.argv) == 4 and sys.argv[3] == "-w")
    if wait:
        # wait for all domains we shut down to terminate
        for dom in shutdown:
            while True:
                info = server.xend_domain(dom)
                if not info: break
                time.sleep(1)

elif cmd == 'destroy':
    rc = server.xend_domain_halt(dom)    

elif cmd == 'pincpu':
    if len(sys.argv) < 4: usage(1)
    cpu = int(sys.argv[3])
    rc = server.xend_domain_pincpu(dom, cpu)

elif cmd == 'list':
    print 'Dom  Name             Mem(MB)  CPU  State  Time(s)'
    for dom in server.xend_domains():
        info = server.xend_domain(dom)
        d = {}
        d['dom'] = int(dom)
        d['name'] = sxp.child_value(info, 'name', '??')
        d['mem'] = int(sxp.child_value(info, 'memory', '0'))
        d['cpu'] = int(sxp.child_value(info, 'cpu', '0'))
        d['state'] = sxp.child_value(info, 'state', '??')
        d['cpu_time'] = float(sxp.child_value(info, 'cpu_time', '0')
        print ("%(dom)-4d %(name)-16s %(mem)7d %(cpu)3d %(state)5s %(cpu_time)8.2f"
               % d)

elif cmd == 'unwatch':
    auto_restart_kill(dom)

elif cmd == 'listvbds':
    print 'Dom   Dev   Mode   Size(MB)'
    for dom in server.xend_domains():
        for vbd in server.xend_domain_vbds(dom):
            info = server.xend_domain_vbd(vbd)
            v['vbd'] = vbd
            v['size'] = int(sxp.get_child_value(info, 'size', '0'))
            v['mode'] = sxp.get_child_value(info, 'mode', '??')
            vbd['size_mb'] = vbd['nr_sectors'] / 2048
            print ('%(dom)-4d  %(vbd)04x  %(mode)-2s      %(size)d' % v)

elif cmd == 'suspend':
    if len(sys.argv) < 4: usage(1)
    file = os.path.abspath(sys.argv[3])
    auto_restart_kill(dom)
    rc = server.xend_domain_save(dom, file, progress=1)

elif cmd == 'cpu_bvtslice':
    if len(sys.argv) < 3: usage(1)
    slice = sys.argv[2]
    rc = server.xend_node_cpu_bvt_slice_set(slice)

elif cmd == 'cpu_bvtset':
    if len(sys.argv) < 7: usage(1)
    (mcuadv, warp, warpl, warpu) = map(int, sys.argv[3:7])
    
    rc = server.xend_domain_cpu_bvt_set(dom, mcuadv, warp, warpl, warpu)
    
elif cmd == 'vif_stats':
    if len(sys.argv) < 4: usage(1)
    vif = int(sys.argv[3])

    print server.xend_domain_vif_stats(dom, vif)

elif cmd == 'vif_addip':
    if len(sys.argv) < 5: usage(1)
    vif = int(sys.argv[3])
    ip  = sys.argv[4]
    rc = server.xend_domain_vif_addip(dom, vif, ip)

elif cmd == 'vif_setsched':
    if len(sys.argv) < 6: usage(1)
    (vif, bytes, usecs) = map(int, sys.argv[3:6])
    rc = server.xend_domain_vif_scheduler_set(dom, vif, bytes, usecs)

elif cmd == 'vif_getsched':
    if len(sys.argv) < 4: usage(1)
    vif = int(sys.argv[3])
    print server.xend_domain_vif_scheduler_get(dom, vif)

elif cmd == 'vbd_add':
    if len(sys.argv) < 6: usage(1)
    uname = sys.argv[3]
    dev = sys.argv[4]
    mode = sys.argv[5]
    try:
        vbd = server.xend_domain_vbd_add(dom, uname, dev, mode)
    except StandardError, ex:
        print "Error:", ex
        sys.exit(1)
    print "Added disk/partition %s to domain %d as device %s (%x)" % (uname, dom, dev, vbd)

elif cmd == 'vbd_remove':
    if len(sys.argv) < 4: usage(1)
    dev = sys.argv[3]
    vbd = server.xend_domain_vbd_remove(dom, dev)
    if vbd < 0:
	print "Failed"
	sys.exit(1)
    else:
	print "Removed disk/partition attached as device %s (%x) in domain %d" % (dev, vbd, dom)

elif cmd == 'cpu_atropos_set': # args: dom period slice latency xtratime
    if len(sys.argv) < 6: usage(1)
    (period, slice, latency, xtratime) = map(int, sys.argv[3:7])
    rc = server.xend_domain_cpu_atropos_set(
        dom, period, slice, latency, xtratime)

elif cmd == 'cpu_rrobin_slice':
    if len(sys.argv) < 3: usage(1)
    slice = int(sys.argv[2])
    rc = server.xend_node_rrobin_set(slice=slice)

else:
    usage(1)

if rc != '':
    print "return code %d" % rc
