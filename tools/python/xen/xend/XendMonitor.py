#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2007 XenSource Ltd.
#============================================================================

from xen.lowlevel.xc import xc
import time
import threading
import os
import re

"""Monitoring thread to keep track of Xend statistics. """

VBD_SYSFS_PATH = '/sys/devices/xen-backend/'
VBD_WR_PATH = VBD_SYSFS_PATH + '%s/statistics/wr_sect'
VBD_RD_PATH = VBD_SYSFS_PATH + '%s/statistics/rd_sect'
VBD_DOMAIN_RE = r'vbd-(?P<domid>\d+)-(?P<devid>\d+)$'

NET_PROCFS_PATH = '/proc/net/dev'
PROC_NET_DEV_RE = r'(?P<rx_bytes>\d+)\s+' \
                  r'(?P<rx_packets>\d+)\s+' \
                  r'(?P<rx_errs>\d+)\s+' \
                  r'(?P<rx_drop>\d+)\s+' \
                  r'(?P<rx_fifo>\d+)\s+' \
                  r'(?P<rx_frame>\d+)\s+' \
                  r'(?P<rx_compressed>\d+)\s+' \
                  r'(?P<rx_multicast>\d+)\s+' \
                  r'(?P<tx_bytes>\d+)\s+' \
                  r'(?P<tx_packets>\d+)\s+' \
                  r'(?P<tx_errs>\d+)\s+' \
                  r'(?P<tx_drop>\d+)\s+' \
                  r'(?P<tx_fifo>\d+)\s+' \
                  r'(?P<tx_collisions>\d+)\s+' \
                  r'(?P<tx_carrier>\d+)\s+' \
                  r'(?P<tx_compressed>\d+)\s*$'


VIF_DOMAIN_RE = re.compile(r'vif(?P<domid>\d+)\.(?P<iface>\d+):\s*' +
                           PROC_NET_DEV_RE)
PIF_RE = re.compile(r'^\s*(?P<iface>peth\d+):\s*' + PROC_NET_DEV_RE)

# Interval to poll xc, sysfs and proc
POLL_INTERVAL = 2.0
SECTOR_SIZE = 512
class XendMonitor(threading.Thread):
    """Monitors VCPU, VBD, VIF and PIF statistics for Xen API.

    Polls sysfs and procfs for statistics on VBDs and VIFs respectively.
    
    @ivar domain_vcpus_util: Utilisation for VCPUs indexed by domain
    @type domain_vcpus_util: {domid: {vcpuid: float, vcpuid: float}}
    @ivar domain_vifs_util: Bytes per second for VIFs indexed by domain
    @type domain_vifs_util: {domid: {vifid: (rx_bps, tx_bps)}}
    @ivar domain_vifs_stat: Total amount of bytes used for VIFs indexed by domain
    @type domain_vifs_stat: {domid: {vbdid: (rx, tx)}}
    @ivar domain_vbds_util: Blocks per second for VBDs index by domain.
    @type domain_vbds_util: {domid: {vbdid: (rd_reqps, wr_reqps)}}    
    
    """
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.xc = xc()

        self.lock = threading.Lock()
        
        # tracks the last polled statistics
        self._domain_vcpus = {}
        self._domain_vifs = {}
        self._domain_vbds = {}
        self.pifs = {}

        # instantaneous statistics
        self._domain_vcpus_util = {}
        self._domain_vifs_util = {}
        self._domain_vifs_stat = {}
        self._domain_vbds_util = {}
        self.pifs_util = {}

    def get_domain_vcpus_util(self):
        self.lock.acquire()
        try:
            return self._domain_vcpus_util
        finally:
            self.lock.release()

    def get_domain_vbds_util(self):
        self.lock.acquire()
        try:
            return self._domain_vbds_util
        finally:
            self.lock.release()                        

    def get_domain_vifs_util(self):
        self.lock.acquire()
        try:
            return self._domain_vifs_util
        finally:
            self.lock.release()

    def get_domain_vifs_stat(self):
        self.lock.acquire()
        try:
            return self._domain_vifs_stat
        finally:
            self.lock.release()

    def get_pifs_util(self):
        self.lock.acquire()
        try:
            return self.pifs_util
        finally:
            self.lock.release()        

    def _get_vif_stats(self):
        stats = {}

        if not os.path.exists(NET_PROCFS_PATH):
            return stats

        usage_at = time.time()        
        for line in open(NET_PROCFS_PATH):
            is_vif = re.search(VIF_DOMAIN_RE, line.strip())
            if not is_vif:
                continue
            
            domid = int(is_vif.group('domid'))
            vifid = int(is_vif.group('iface'))
            rx_bytes = int(is_vif.group('rx_bytes'))
            tx_bytes = int(is_vif.group('tx_bytes'))
            if not domid in stats:
                stats[domid] = {}
                
            stats[domid][vifid] = (usage_at, rx_bytes, tx_bytes)

        return stats

    def _get_pif_stats(self):
        stats = {}

        if not os.path.exists(NET_PROCFS_PATH):
            return stats
        
        usage_at = time.time()        
        for line in open(NET_PROCFS_PATH):
            is_pif = re.search(PIF_RE, line.strip())
            if not is_pif:
                continue
            
            pifname = is_pif.group('iface')
            rx_bytes = int(is_pif.group('rx_bytes'))
            tx_bytes = int(is_pif.group('tx_bytes'))
            stats[pifname] = (usage_at, rx_bytes, tx_bytes)

        return stats    

    def _get_vbd_stats(self):
        stats = {}

        if not os.path.exists(VBD_SYSFS_PATH):
            return stats
        
        for vbd_path in os.listdir(VBD_SYSFS_PATH):
            is_vbd = re.search(VBD_DOMAIN_RE, vbd_path)
            if not is_vbd:
                continue

            domid = int(is_vbd.group('domid'))
            vbdid = int(is_vbd.group('devid'))
            rd_stat_path = VBD_RD_PATH % vbd_path
            wr_stat_path = VBD_WR_PATH % vbd_path
            
            if not os.path.exists(rd_stat_path) or \
                   not os.path.exists(wr_stat_path):
                continue

            
            try:
                usage_at = time.time()
                rd_stat = int(open(rd_stat_path).readline().strip())
                wr_stat = int(open(wr_stat_path).readline().strip())
                rd_stat *= SECTOR_SIZE
                wr_stat *= SECTOR_SIZE
                if domid not in stats:
                    stats[domid] = {}

                stats[domid][vbdid] = (usage_at, rd_stat, wr_stat)
                
            except (IOError, ValueError):
                continue

        return stats

    def _get_cpu_stats(self):
        stats = {}
        for domain in self.xc.domain_getinfo():
            domid = domain['domid']
            vcpu_count = domain['online_vcpus']
            stats[domid] = {}
            for i in range(vcpu_count):
                vcpu_info = self.xc.vcpu_getinfo(domid, i)
                usage = vcpu_info['cpu_time']
                usage_at = time.time()
                stats[domid][i] = (usage_at, usage)

        return stats
            

    def run(self):

        # loop every second for stats
        while True:
            self.lock.acquire()
            try:
                active_domids = []
                # Calculate utilisation for VCPUs
                
                for domid, cputimes in self._get_cpu_stats().items():
                    active_domids.append(domid)
                    if domid not in self._domain_vcpus:
                        # if not initialised, save current stats
                        # and skip utilisation calculation
                        self._domain_vcpus[domid] = cputimes
                        self._domain_vcpus_util[domid] = {}
                        continue

                    for vcpu, (usage_at, usage) in cputimes.items():
                        if vcpu not in self._domain_vcpus[domid]:
                            continue
                    
                        prv_usage_at, prv_usage = \
                                   self._domain_vcpus[domid][vcpu]
                        interval_s = (usage_at - prv_usage_at) * 1000000000
                        if interval_s > 0:
                            util = (usage - prv_usage) / interval_s
                            self._domain_vcpus_util[domid][vcpu] = util

                    self._domain_vcpus[domid] = cputimes

                # Calculate utilisation for VBDs
                
                for domid, vbds in self._get_vbd_stats().items():
                    if domid not in self._domain_vbds:
                        self._domain_vbds[domid] = vbds
                        self._domain_vbds_util[domid] = {}
                        continue
                
                    for devid, (usage_at, rd, wr) in vbds.items():
                        if devid not in self._domain_vbds[domid]:
                            continue
                    
                        prv_at, prv_rd, prv_wr  = \
                                self._domain_vbds[domid][devid]
                        interval = usage_at - prv_at
                        rd_util = (rd - prv_rd)/interval
                        wr_util = (wr - prv_wr)/interval
                        self._domain_vbds_util[domid][devid] = \
                                 (rd_util, wr_util)
                        
                    self._domain_vbds[domid] = vbds
                

                # Calculate utilisation for VIFs

                for domid, vifs in self._get_vif_stats().items():
                
                    if domid not in self._domain_vifs:
                        self._domain_vifs[domid] = vifs
                        self._domain_vifs_util[domid] = {}
                        self._domain_vifs_stat[domid] = {}
                        continue
                
                    for devid, (usage_at, rx, tx) in vifs.items():
                        if devid not in self._domain_vifs[domid]:
                            continue
                    
                        prv_at, prv_rx, prv_tx  = \
                                self._domain_vifs[domid][devid]
                        interval = usage_at - prv_at
                        rx_util = (rx - prv_rx)/interval
                        tx_util = (tx - prv_tx)/interval

                        # note these are flipped around because
                        # we are measuring the host interface,
                        # not the guest interface
                        self._domain_vifs_util[domid][devid] = \
                             (tx_util, rx_util)
                        self._domain_vifs_stat[domid][devid] = \
                             (float(tx), float(rx))
                        
                    self._domain_vifs[domid] = vifs

                # Calculate utilisation for PIFs

                for pifname, stats in self._get_pif_stats().items():
                    if pifname not in self.pifs:
                        self.pifs[pifname] = stats
                        continue

                    usage_at, rx, tx = stats
                    prv_at, prv_rx, prv_tx  = self.pifs[pifname]
                    interval = usage_at - prv_at
                    rx_util = (rx - prv_rx)/interval
                    tx_util = (tx - prv_tx)/interval

                    self.pifs_util[pifname] = (rx_util, tx_util)
                    self.pifs[pifname] = stats

                for domid in self._domain_vcpus_util.keys():
                    if domid not in active_domids:
                        del self._domain_vcpus_util[domid]
                        del self._domain_vcpus[domid]
                for domid in self._domain_vifs_util.keys():
                    if domid not in active_domids:
                        del self._domain_vifs_util[domid]
                        del self._domain_vifs[domid]
                        del self._domain_vifs_stat[domid]
                for domid in self._domain_vbds_util.keys():
                    if domid not in active_domids:
                        del self._domain_vbds_util[domid]
                        del self._domain_vbds[domid]

            finally:
                self.lock.release()

            # Sleep a while before next poll
            time.sleep(POLL_INTERVAL)

