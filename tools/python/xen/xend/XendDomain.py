# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for domain operations.
 Nothing here is persistent (across reboots).
 Needs to be persistent for one uptime.
"""
import sys
import traceback

from twisted.internet import defer
#defer.Deferred.debug = 1
from twisted.internet import reactor

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()

import sxp
import XendRoot
xroot = XendRoot.instance()
import XendDB
import XendDomainInfo
import XendMigrate
import EventServer
from XendError import XendError
from XendLogging import log


from xen.xend.server import SrvDaemon
xend = SrvDaemon.instance()

eserver = EventServer.instance()

__all__ = [ "XendDomain" ]
        
class XendDomain:
    """Index of all domains. Singleton.
    """

    """Path to domain database."""
    dbpath = "domain"

    """Table of domain info indexed by domain id."""
    domain_by_id = {}
    domain_by_name = {}
    
    """Table of domains to restart, indexed by domain id."""
    restarts_by_id = {}
    restarts_by_name = {}

    """Table of delayed calls."""
    schedule = {}
    
    def __init__(self):
        # Hack alert. Python does not support mutual imports, but XendDomainInfo
        # needs access to the XendDomain instance to look up domains. Attempting
        # to import XendDomain from XendDomainInfo causes unbounded recursion.
        # So we stuff the XendDomain instance (self) into xroot's components.
        xroot.add_component("xen.xend.XendDomain", self)
        # Table of domain info indexed by domain id.
        self.db = XendDB.XendDB(self.dbpath)
        self.domain_db = self.db.fetchall("")
        if xroot.get_rebooted():
            log.info('XendDomain> rebooted: removing all domain info')
            self.rm_all()
        eserver.subscribe('xend.virq', self.onVirq)
        self.initial_refresh()

    def onVirq(self, event, val):
        """Event handler for virq.
        """
        self.reap()

    def schedule_later(self, _delay, _name, _fn, *args):
        """Schedule a function to be called later (if not already scheduled).

        @param _delay: delay in seconds
        @param _name:  schedule name
        @param _fn:    function
        @param args:   arguments
        """
        if self.schedule.get(_name): return
        self.schedule[_name] = reactor.callLater(_delay, _fn, *args)
        
    def schedule_cancel(self, name):
        """Cancel a scheduled function call.
        
        @param name: schedule name to cancel
        """
        callid = self.schedule.get(name)
        if not callid:
            return
        if callid.active():
            callid.cancel()
        del self.schedule[name]

    def reap_schedule(self, delay=0):
        """Schedule reap to be called later.

        @param delay: delay in seconds
        """
        self.schedule_later(delay, 'reap', self.reap)

    def reap_cancel(self):
        """Cancel any scheduled reap.
        """
        self.schedule_cancel('reap')

    def refresh_schedule(self, delay=0):
        """Schedule refresh to be called later.
        
        @param delay: delay in seconds
        """
        self.schedule_later(delay, 'refresh', self.refresh)

    def refresh_cancel(self):
        """Cancel any scheduled refresh.
        """
        self.schedule_cancel('refresh')

    def domain_restarts_schedule(self, delay=0):
        """Schedule domain_restarts to be called later.
        
        @param delay: delay in seconds
        """
        self.schedule_later(delay, 'domain_restarts', self.domain_restarts)
        
    def domain_restarts_cancel(self):
        """Cancel any scheduled call of domain_restarts.
        """
        self.schedule_cancel('domain_restarts')
        
    def rm_all(self):
        """Remove all domain info. Used after reboot.
        """
        for (k, v) in self.domain_db.items():
            self._delete_domain(k, notify=0)
            
    def initial_refresh(self):
        """Refresh initial domain info from domain_db.
        """
            
        def cb_all_ok(val):
            self.refresh()

        domlist = xc.domain_getinfo()
        doms = {}
        for d in domlist:
            domid = str(d['dom'])
            doms[domid] = d
        dlist = []
        for config in self.domain_db.values():
            domid = str(sxp.child_value(config, 'id'))
            if domid in doms:
                d_dom = self._new_domain(config, doms[domid])
                dlist.append(d_dom)
            else:
                self._delete_domain(domid)
        d_all = defer.DeferredList(dlist, fireOnOneErrback=1)
        d_all.addCallback(cb_all_ok)

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

        @param savedinfo: saved info from the db
        @param info:      domain info from xen
        @return: deferred
        """
        def cbok(dominfo):
            self.domain_by_id[dominfo.id] = dominfo
            self.domain_by_name[dominfo.name] = dominfo
            if dominfo.restart_pending():
                self.domain_restart_add(dominfo)
        
        deferred = XendDomainInfo.vm_recreate(savedinfo, info)
        deferred.addCallback(cbok)
        return deferred

    def _add_domain(self, info, notify=1):
        """Add a domain entry to the tables.

        @param info:   domain info object
        @param notify: send a domain created event if true
        """
        self.domain_by_id[info.id] = info
        self.domain_db[info.id] = info.sxpr()
        for k, d in self.domain_by_name.items():
            if k != d.name:
                del self.domain_by_name[k]
        if info.name:
            self.domain_by_name[info.name] = info
        self.sync_domain(info.id)
        if notify: eserver.inject('xend.domain.created', [info.name, info.id])

    def _delete_domain(self, id, notify=1):
        """Remove a domain from the tables.

        @param id:     domain id
        @param notify: send a domain died event if true
        """
        for info in self.domain_by_name.values():
            if info.id == id:
                del self.domain_by_name[info.name]
        if id in self.domain_by_id:
            info = self.domain_by_id[id]
            del self.domain_by_id[id]
            if notify: eserver.inject('xend.domain.died', [info.name, info.id])
        if id in self.domain_db:
            del self.domain_db[id]
            self.db.delete(id)

    def reap(self):
        """Look for domains that have crashed or stopped.
        Tidy them up.
        """
        self.reap_cancel()
        domlist = xc.domain_getinfo()
        casualties = []
        for d in domlist:
            dead = 0
            dead = dead or (d['crashed'] or d['shutdown'])
            dead = dead or (d['dying'] and
                            not(d['running'] or d['paused'] or d['blocked']))
            if dead:
                casualties.append(d)
        destroyed = 0
        for d in casualties:
            id = str(d['dom'])
            log.debug('XendDomain>reap> domain died id=%s', id)
            if d['shutdown']:
                reason = XendDomainInfo.shutdown_reason(d['shutdown_reason'])
                log.debug('XendDomain>reap> shutdown id=%s reason=%s', id, reason)
                dominfo = self.domain_by_id.get(id)
                name = (dominfo and dominfo.name) or '??'
                if reason in ['suspend']:
                    if dominfo.is_terminated():
                        log.debug('XendDomain>reap> Suspended domain died id=%s', id)
                    else:
                        eserver.inject('xend.domain.suspended', [name, id])
                        continue
                if reason in ['poweroff', 'reboot']:
                    eserver.inject('xend.domain.exit', [name, id, reason])
                    self.domain_restart_schedule(id, reason)
            else:
               eserver.inject('xend.domain.exit', [name, id, 'crash']) 
            destroyed += 1
            self.final_domain_destroy(id)
        if self.domain_restarts_exist():
            self.domain_restarts_schedule()
        if destroyed:
            self.refresh_schedule(delay=1)

    def refresh(self):
        """Refresh domain list from Xen.
        """
        self.refresh_cancel()
        domlist = xc.domain_getinfo()
        # Index the domlist by id.
        # Add entries for any domains we don't know about.
        doms = {}
        for d in domlist:
            id = str(d['dom'])
            doms[id] = d
            if id not in self.domain_by_id:
                savedinfo = None
                deferred = XendDomainInfo.vm_recreate(savedinfo, d)
                def cbok(dominfo):
                    self._add_domain(dominfo)
                deferred.addCallback(cbok)
        # Remove entries for domains that no longer exist.
        for d in self.domain_by_id.values():
            info = doms.get(d.id)
            if info:
                d.update(info)
            else:
                self._delete_domain(d.id)
        self.reap_schedule(delay=1)

    def update_domain(self, id):
        """Update the saved info for a domain.

        @param id: domain id
        """
        dominfo = self.domain_by_id.get(id)
        if dominfo:
            self.domain_db[id] = dominfo.sxpr()
            self.sync_domain(id)

    def refresh_domain(self, id):
        """Refresh information for a single domain.

        @param id: domain id
        """
        dom = int(id)
        dominfo = xc.domain_getinfo(dom, 1)
        if dominfo == [] or dominfo[0]['dom'] != dom:
            try:
                self._delete_domain(id)
            except:
                log.exception('refresh_domain> error')
                raise
                pass
        else:
            d = self.domain_by_id.get(id)
            if d:
                d.update(dominfo[0])

    def domain_ls(self):
        """Get list of domain names.

        @return: domain names
        """
        self.refresh()
        return self.domain_by_name.keys()

    def domain_ls_ids(self):
        """Get list of domain ids.

        @return: domain names
        """
        self.refresh()
        return self.domain_by_id.keys()

    def domains(self):
        """Get list of domain objects.

        @return: domain objects
        """
        self.refresh()
        return self.domain_by_id.values()
    
    def domain_create(self, config):
        """Create a domain from a configuration.

        @param config: configuration
        @return: deferred
        """
        def cbok(dominfo):
            self._add_domain(dominfo)
            return dominfo
        deferred = XendDomainInfo.vm_create(config)
        deferred.addCallback(cbok)
        return deferred

    def domain_setname(self, dom, name):
        """Set the name of a domain.
        For internal use only.

        @param dom: domain id
        @param name: domain name
        """
        return xc.domain_setname(dom=dom, name=name)

    def domain_restart(self, dominfo):
        """Restart a domain.

        @param dominfo: domain object
        @return: deferred
        """
        def cbok(dominfo):
            self._add_domain(dominfo)
            return dominfo
        log.info("Restarting domain: id=%s name=%s", dominfo.id, dominfo.name)
        deferred = dominfo.restart()
        deferred.addCallback(cbok)
        return deferred        

    def domain_configure(self, id, vmconfig):
        """Configure an existing domain. This is intended for internal
        use by domain restore and migrate.

        @param id:       domain id
        @param vmconfig: vm configuration
        @return: deferred
        """
        config = sxp.child_value(vmconfig, 'config')
        dominfo = self.domain_lookup(id)
        log.debug('domain_configure> id=%s config=%s', str(id), str(config))
        if dominfo.config:
            raise XendError("Domain already configured: " + dominfo.id)
        def cbok(dominfo):
            self._add_domain(dominfo)
            return dominfo
        deferred = dominfo.dom_construct(dominfo.dom, config)
        deferred.addCallback(cbok)
        return deferred
    
    def domain_restore(self, src, progress=0):
        """Restore a domain from file.

        @param src:      source file
        @param progress: output progress if true
        @return: deferred
        """
        
        def cbok(dominfo):
            self._add_domain(dominfo)
            return dominfo
        deferred = XendDomainInfo.vm_restore(src, progress=progress)
        deferred.addCallback(cbok)
        return deferred
    
    def domain_get(self, id):
        """Get up-to-date info about a domain.

        @param id: domain id
        @return: domain object (or None)
        """
        id = str(id)
        self.refresh_domain(id)
        return self.domain_by_id.get(id)

    def domain_lookup(self, name):
        name = str(name)
        dominfo = self.domain_by_name.get(name) or self.domain_by_id.get(name)
        if dominfo:
            return dominfo
        raise XendError('invalid domain:' + name)

    def domain_exists(self, name):
        name = str(name)
        return self.domain_by_name.get(name) or self.domain_by_id.get(name)

    def domain_unpause(self, id):
        """Unpause domain execution.

        @param id: domain id
        """
        dominfo = self.domain_lookup(id)
        eserver.inject('xend.domain.unpause', [dominfo.name, dominfo.id])
        try:
            return xc.domain_unpause(dom=dominfo.dom)
        except Exception, ex:
            raise XendError(str(ex))
    
    def domain_pause(self, id):
        """Pause domain execution.

        @param id: domain id
        """
        dominfo = self.domain_lookup(id)
        eserver.inject('xend.domain.pause', [dominfo.name, dominfo.id])
        try:
            return xc.domain_pause(dom=dominfo.dom)
        except Exception, ex:
            raise XendError(str(ex))
    
    def domain_shutdown(self, id, reason='poweroff'):
        """Shutdown domain (nicely).
         - poweroff: restart according to exit code and restart mode
         - reboot:   restart on exit
         - halt:     do not restart

         Returns immediately.

        @param id:     domain id
        @param reason: shutdown type: poweroff, reboot, suspend, halt
        """
        dominfo = self.domain_lookup(id)
        if reason == 'halt':
            self.domain_restart_cancel(dominfo.id)
        else:
            self.domain_restart_schedule(dominfo.id, reason, force=1)
        eserver.inject('xend.domain.shutdown', [dominfo.name, dominfo.id, reason])
        if reason == 'halt':
            reason = 'poweroff'
        val = xend.domain_shutdown(dominfo.id, reason)
        self.refresh_schedule()
        return val

    def domain_restart_schedule(self, id, reason, force=0):
        """Schedule a restart for a domain if it needs one.

        @param id:     domain id
        @param reason: shutdown reason
        """
        log.debug('domain_restart_schedule> %s %s %d', id, reason, force)
        dominfo = self.domain_lookup(id)
        if not dominfo:
            return
        if dominfo.id in self.restarts_by_id:
            return
        restart = (force and reason == 'reboot') or dominfo.restart_needed(reason)
        if restart:
            dominfo.restarting()
            self.domain_restart_add(dominfo)

    def domain_restart_add(self, dominfo):
        self.restarts_by_name[dominfo.name] = dominfo
        self.restarts_by_id[dominfo.id] = dominfo
        log.info('Scheduling restart for domain: name=%s id=%s', dominfo.name, dominfo.id)
        self.domain_restarts_schedule()
            
    def domain_restart_cancel(self, id):
        """Cancel any restart scheduled for a domain.

        @param id: domain id
        """
        dominfo = self.restarts_by_id.get(id) or self.restarts_by_name.get(id)
        if dominfo:
            log.info('Cancelling restart for domain: name=%s id=%s', dominfo.name, dominfo.id)
            dominfo.restart_cancel()
            del self.restarts_by_id[dominfo.id]
            del self.restarts_by_name[dominfo.name]

    def domain_restarts(self):
        """Execute any scheduled domain restarts for domains that have gone.
        """
        self.domain_restarts_cancel()
        for dominfo in self.restarts_by_id.values():
            if dominfo.id in self.domain_by_id:
                # Don't execute restart for domains still running.
                continue
            # Remove it from the restarts.
            del self.restarts_by_id[dominfo.id]
            del self.restarts_by_name[dominfo.name]
            try:
                def cbok(dominfo):
                    log.info('Restarted domain name=%s id=%s', dominfo.name, dominfo.id)
                    self.domain_unpause(dominfo.id)
                def cberr(err):
                    log.exception("Delayed exception restarting domain: name=%s id=%s",
                                  dominfo.name, dominfo.id)
                deferred = self.domain_restart(dominfo)
                deferred.addCallback(cbok)
                deferred.addErrback(cberr)
            except:
                log.exception("Exception restarting domain: name=%s id=%s",
                              dominfo.name, dominfo.id)
        if self.domain_restarts_exist():
            # Run again later if any restarts remain.
            self.refresh_schedule(delay=5)

    def domain_restarts_exist(self):
        return len(self.restarts_by_id)
        
    def final_domain_destroy(self, id):
        """Final destruction of a domain..

        @param id: domain id
        """
        dominfo = self.domain_lookup(id)
        log.info('Destroying domain: name=%s', dominfo.name)
        eserver.inject('xend.domain.destroy', [dominfo.name, dominfo.id])
        if dominfo:
            val = dominfo.destroy()
        else:
            #todo
            val = xc.domain_destroy(dom=dominfo.dom)
        return val       

    def domain_destroy(self, id, reason='halt'):
        """Terminate domain immediately.
        - halt:   cancel any restart for the domain
        - reboot  schedule a restart for the domain

        @param id: domain id
        """
        if reason == 'halt':
            self.domain_restart_cancel(id)
        elif reason == 'reboot':
            self.domain_restart_schedule(id, reason, force=1)
        val = self.final_domain_destroy(id)
        self.refresh_schedule()
        return val

    def domain_migrate(self, id, dst, live):
        """Start domain migration.

        @param id: domain id
        @return: deferred
        """
        # Need a cancel too?
        # Don't forget to cancel restart for it.
        dominfo = self.domain_lookup(id)
        xmigrate = XendMigrate.instance()
        val = xmigrate.migrate_begin(dominfo.id, dst, live=live)
        return val

    def domain_save(self, id, dst, progress=0):
        """Start saving a domain to file.

        @param id:       domain id
        @param dst:      destination file
        @param progress: output progress if true
        @return: deferred
        """
        dominfo = self.domain_lookup(id)
        xmigrate = XendMigrate.instance()
        return xmigrate.save_begin(dominfo.id, dst)
    
    def domain_pincpu(self, id, cpu):
        """Pin a domain to a cpu.

        @param id: domain
        @param cpu: cpu number
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.domain_pincpu(int(dominfo.id), cpu)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_set(self, id, mcuadv, warpback, warpvalue, warpl, warpu):
        """Set BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.bvtsched_domain_set(dom=dominfo.dom, mcuadv=mcuadv,
                                          warpback=warpback, warpvalue=warpvalue, 
                                          warpl=warpl, warpu=warpu)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_get(self, id):
        """Get BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.bvtsched_domain_get(dominfo.dom)
        except Exception, ex:
            raise XendError(str(ex))
    
    def domain_cpu_fbvt_set(self, id, mcuadv, warp, warpl, warpu):
        """Set FBVT (Fair Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.fbvtsched_domain_set(dom=dominfo.dom, mcuadv=mcuadv,
                                           warp=warp, warpl=warpl, warpu=warpu)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_fbvt_get(self, id):
        """Get FBVT (Fair Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.fbvtsched_domain_get(dominfo.dom)
        except Exception, ex:
            raise XendError(str(ex))
        
    def domain_cpu_atropos_set(self, id, period, slice, latency, xtratime):
        """Set Atropos scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.atropos_domain_set(dominfo.dom, period, slice, latency, xtratime)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_atropos_get(self, id):
        """Get Atropos scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.atropos_domain_get(dominfo.dom)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_device_create(self, id, devconfig):
        """Create a new device for a domain.

        @param id:       domain id
        @param devconfig: device configuration
        @return: deferred
        """
        dominfo = self.domain_lookup(id)
        self.refresh_schedule()
        val = dominfo.device_create(devconfig)
        self.update_domain(dominfo.id)
        return val

    def domain_device_configure(self, id, devconfig, idx):
        """Configure an existing device for a domain.

        @param id:   domain id
        @param devconfig: device configuration
        @param idx:  device index
        @return: updated device configuration
        """
        dominfo = self.domain_lookup(id)
        self.refresh_schedule()
        val = dominfo.device_configure(devconfig, idx)
        self.update_domain(dominfo.id)
        return val
    

    def domain_device_destroy(self, id, type, idx):
        """Destroy a device.

        @param id:  domain id
        @param idx:  device index
        @param type: device type
        """
        dominfo = self.domain_lookup(id)
        self.refresh_schedule()
        val = dominfo.device_destroy(type, idx)
        self.update_domain(dominfo.id)
        return val

    def domain_devtype_ls(self, id, type):
        """Get list of device indexes for a domain.

        @param id:  domain
        @param type: device type
        @return: device indexes
        """
        dominfo = self.domain_lookup(id)
        devs = dominfo.get_devices(type)
        return devs

    def domain_devtype_get(self, id, type, idx):
        """Get a device from a domain.

        @param id:  domain
        @param type: device type
        @param idx:  device index
        @return: device object (or None)
        """
        dominfo = self.domain_lookup(id)
        return dominfo.get_device_by_index(type, idx)

    def domain_vif_ls(self, id):
        """Get list of virtual network interface (vif) indexes for a domain.

        @param id: domain
        @return: vif indexes
        """
        return self.domain_devtype_ls(id, 'vif')

    def domain_vif_get(self, id, vif):
        """Get a virtual network interface (vif) from a domain.

        @param id: domain
        @param vif: vif index
        @return: vif device object (or None)
        """
        return self.domain_devtype_get(id, 'vif', vif)

    def domain_vbd_ls(self, id):
        """Get list of virtual block device (vbd) indexes for a domain.

        @param id: domain
        @return: vbd indexes
        """
        return self.domain_devtype_ls(id, 'vbd')

    def domain_vbd_get(self, id, vbd):
        """Get a virtual block device (vbd) from a domain.

        @param id: domain
        @param vbd: vbd index
        @return: vbd device (or None)
        """
        return self.domain_devtype_get(id, 'vbd', vbd)

    def domain_shadow_control(self, id, op):
        """Shadow page control.

        @param id: domain
        @param op:  operation
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.shadow_control(dominfo.dom, op)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_maxmem_set(self, id, mem):
        """Set the memory limit for a domain.

        @param dom: domain
        @param mem: memory limit (in MB)
        @return: 0 on success, -1 on error
        """
        dominfo = self.domain_lookup(id)
        maxmem = int(mem) * 1024
        try:
            return xc.domain_setmaxmem(dominfo.dom, maxmem_kb = maxmem)
        except Exception, ex:
            raise XendError(str(ex))


def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendDomain()
    return inst
