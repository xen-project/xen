# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for domain operations.
 Nothing here is persistent (across reboots).
 Needs to be persistent for one uptime.
"""
import sys

from twisted.internet import defer

import Xc; xc = Xc.new()
import xenctl.ip

import sxp
import XendRoot
xroot = XendRoot.instance()
import XendDB
import XendDomainInfo
import XendConsole
import EventServer

from xenmgr.server import SrvConsoleServer
xend = SrvConsoleServer.instance()

eserver = EventServer.instance()

__all__ = [ "XendDomain" ]
        
class XendDomain:
    """Index of all domains. Singleton.
    """
    
    dbpath = "domain"
    domain = {}
    
    def __init__(self):
        self.xconsole = XendConsole.instance()
        # Table of domain info indexed by domain id.
        self.db = XendDB.XendDB(self.dbpath)
        #self.domain = {}
        self.domain_db = self.db.fetchall("")
        if xroot.get_rebooted():
            print 'XendDomain> rebooted: removing all domain info'
            self.rm_all()
        self.initial_refresh()

    def rm_all(self):
        """Remove all domain info. Used after reboot.
        """
        for (k, v) in self.domain_db.items():
            self._delete_domain(k, notify=0)
            
    def initial_refresh(self):
        """Refresh initial domain info from domain_db.
        """
        print "initial_refresh>"
        for d in self.domain_db.values(): print 'db dom=', d
        domlist = xc.domain_getinfo()
        for d in domlist: print 'xc dom=', d
        doms = {}
        for d in domlist:
            domid = str(d['dom'])
            doms[domid] = d
        dlist = []
        for config in self.domain_db.values():
            domid = str(sxp.child_value(config, 'id'))
            print "dom=", domid, "config=", config
            if domid in doms:
                print "dom=", domid, "new"
                deferred = self._new_domain(config, doms[domid])
                dlist.append(deferred)
            else:
                print "dom=", domid, "del"
                self._delete_domain(domid)
        deferred = defer.DeferredList(dlist, fireOnOneErrback=1)
        def cbok(val):
            print "doms:"
            for d in self.domain.values(): print 'dom', d
            print "refresh..."
            self.refresh()
            print "doms:"
            for d in self.domain.values(): print 'dom', d
        deferred.addCallback(cbok)

    def sync(self):
        """Sync domain db to disk.
        """
        self.db.saveall("", self.domain_db)

    def sync_domain(self, dom):
        """Sync info for a domain to disk.

        dom	domain id (string)
        """
        self.db.save(dom, self.domain_db[dom])

    def close(self):
        pass

    def _new_domain(self, savedinfo, info):
        """Create a domain entry from saved info.
        """
##         console = None
##         kernel = None
##         id = sxp.child_value(info, 'id')
##         dom = int(id)
##         name = sxp.child_value(info, 'name')
##         memory = int(sxp.child_value(info, 'memory'))
##         consoleinfo = sxp.child(info, 'console')
##         if consoleinfo:
##             consoleid = sxp.child_value(consoleinfo, 'id')
##             console = self.xconsole.console_get(consoleid)
##         if dom and console is None:
##             # Try to connect a console.
##             console = self.xconsole.console_create(dom)
##         config = sxp.child(info, 'config')
##         if config:
##             image = sxp.child(info, 'image')
##             if image:
##                 image = sxp.child0(image)
##                 kernel = sxp.child_value(image, 'kernel')
##         dominfo = XendDomainInfo.XendDomainInfo(
##             config, dom, name, memory, kernel, console)
        config = sxp.child_value(savedinfo, 'config')
        deferred = XendDomainInfo.vm_recreate(config, info)
        def fn(dominfo):
            self.domain[dominfo.id] = dominfo
        deferred.addCallback(fn)
        return deferred

    def _add_domain(self, id, info, notify=1):
        self.domain[id] = info
        self.domain_db[id] = info.sxpr()
        self.sync_domain(id)
        if notify: eserver.inject('xend.domain.created', id)

    def _delete_domain(self, id, notify=1):
        if id in self.domain:
            self.domain[id].died()
            if notify: eserver.inject('xend.domain.died', id)
            del self.domain[id]
        if id in self.domain_db:
            del self.domain_db[id]
            self.db.delete(id)

    def refresh(self):
        """Refresh domain list from Xen.
        """
        domlist = xc.domain_getinfo()
        # Index the domlist by id.
        # Add entries for any domains we don't know about.
        doms = {}
        for d in domlist:
            id = str(d['dom'])
            doms[id] = d
            if id not in self.domain:
                config = None
                #image = None
                #newinfo = XendDomainInfo.XendDomainInfo(
                #    config, d['dom'], d['name'], d['mem_kb']/1024, image=image, info=d)
                deferred = XendDomainInfo.vm_recreate(config, d)
                def fn(dominfo):
                    self._add_domain(dominfo.id, dominfo)
                deferred.addCallback(fn)
        # Remove entries for domains that no longer exist.
        for d in self.domain.values():
            dominfo = doms.get(d.id)
            if dominfo:
                d.update(dominfo)
            else:
                self._delete_domain(d.id)

    def refresh_domain(self, id):
        dom = int(id)
        dominfo = xc.domain_getinfo(dom, 1)
        if dominfo == [] or dominfo[0]['dom'] != dom:
            try:
                self._delete_domain(id)
            except:
                pass
        else:
            d = self.domain.get(id)
            if d:
                d.update(dominfo[0])

    def domain_ls(self):
        # List domains.
        # Update info from kernel first.
        self.refresh()
        return self.domain.keys()

    def domains(self):
        self.refresh()
        return self.domain.values()
    
    def domain_create(self, config):
        # Create domain, log it.
        deferred = XendDomainInfo.vm_create(config)
        def fn(dominfo):
            self._add_domain(dominfo.id, dominfo)
            return dominfo
        deferred.addCallback(fn)
        return deferred
    
    def domain_get(self, id):
        id = str(id)
        self.refresh_domain(id)
        return self.domain[id]
    
    def domain_unpause(self, id):
        """(Re)start domain running.
        """
        dom = int(id)
        eserver.inject('xend.domain.unpause', id)
        return xc.domain_unpause(dom=dom)
    
    def domain_pause(self, id):
        """Pause domain execution.
        """
        dom = int(id)
        eserver.inject('xend.domain.pause', id)
        return xc.domain_pause(dom=dom)
    
    def domain_shutdown(self, id, reason='poweroff'):
        """Shutdown domain (nicely).
        """
        dom = int(id)
        if dom <= 0:
            return 0
        eserver.inject('xend.domain.shutdown', [id, reason])
        val = xend.domain_shutdown(dom, reason)
        self.refresh()
        return val
    
    def domain_destroy(self, id):
        """Terminate domain immediately.
        """
        dom = int(id)
        if dom <= 0:
            return 0
        eserver.inject('xend.domain.destroy', id)
        val = xc.domain_destroy(dom=dom)
        self.refresh()
        return val       

    def domain_migrate(self, id, dst):
        """Start domain migration.
        """
        # Need a cancel too?
        pass
    
    def domain_save(self, id, dst, progress=0):
        """Save domain state to file, destroy domain.
        """
        dom = int(id)
        self.domain_pause(id)
        eserver.inject('xend.domain.save', id)
        rc = xc.linux_save(dom=dom, state_file=dst, progress=progress)
        if rc == 0:
            self.domain_destroy(id)
        return rc
    
    def domain_restore(self, src, config, progress=0):
        """Restore domain from file.
        """
        dominfo = XendDomainInfo.dom_restore(dom, config)
        self._add_domain(dominfo.id, dominfo)
        return dominfo
    
    #============================================================================
    # Backward compatibility stuff from here on.

    def domain_pincpu(self, dom, cpu):
        dom = int(dom)
        return xc.domain_pincpu(dom, cpu)

    def domain_cpu_bvt_set(self, dom, mcuadv, warp, warpl, warpu):
        dom = int(dom)
        return xc.bvtsched_domain_set(dom=dom, mcuadv=mcuadv,
                                      warp=warp, warpl=warpl, warpu=warpu)

    def domain_cpu_bvt_get(self, dom):
        dom = int(dom)
        return xc.bvtsched_domain_get(dom)
    
    def domain_cpu_atropos_set(self, dom, period, slice, latency, xtratime):
        dom = int(dom)
        return xc.atropos_domain_set(dom, period, slice, latency, xtratime)

    def domain_cpu_atropos_get(self, dom):
        dom = int(dom)
        return xc.atropos_domain_get(dom)

    def domain_vif_ls(self, dom):
        dominfo = self.domain_get(dom)
        if not dominfo: return None
        devs = dominfo.get_devices('vif')
        return range(0, len(devs))

    def domain_vif_get(self, dom, vif):
        dominfo = self.domain_get(dom)
        if not dominfo: return None
        return dominfo.get_device_by_index(vif)

    def domain_vif_ip_add(self, dom, vif, ip):
        dom = int(dom)
        return xenctl.ip.setup_vfr_rules_for_vif(dom, vif, ip)

    def domain_vbd_ls(self, dom):
        dominfo = self.domain_get(dom)
        if not dominfo: return []
        devs = dominfo.get_devices('vbd')
        return [ sxp.child_value(v, 'dev') for v in devs ]

    def domain_vbd_get(self, dom, vbd):
        dominfo = self.domain_get(dom)
        if not dominfo: return None
        devs = dominfo.get_devices('vbd')
        for v in devs:
            if sxp.child_value(v, 'dev') == vbd:
                return v
        return None

    def domain_shadow_control(self, dom, op):
        dom = int(dom)
        return xc.shadow_control(dom, op)

    #============================================================================

def instance():
    global inst
    try:
        inst
    except:
        inst = XendDomain()
    return inst
