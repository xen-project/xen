# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for domain operations.
 Nothing here is persistent (across reboots).
 Needs to be persistent for one uptime.
"""
import sys
import traceback
import time

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()

import sxp
import XendRoot; xroot = XendRoot.instance()
import XendDB
import XendDomainInfo
import XendMigrate
import EventServer; eserver = EventServer.instance()
from XendError import XendError
from XendLogging import log

from scheduler import Scheduler

from xen.xend.server import channel


__all__ = [ "XendDomain" ]

SHUTDOWN_TIMEOUT = 30

class DomainShutdown:
    """A pending domain shutdown. The domain is asked to shut down,
    if it has not terminated or rebooted when the timeout expires it
    is destroyed.
    """

    def __init__(self, dominfo, reason, key, timeout=None):
        if timeout is None:
            timeout = SHUTDOWN_TIMEOUT
        self.start = time.time()
        self.timeout = timeout
        self.dominfo = dominfo
        self.last_restart_time = dominfo.restart_time
        self.last_restart_count = dominfo.restart_count
        self.reason = reason
        self.key = key

    def getDomain(self):
        return self.dominfo.id

    def getDomainName(self):
        return self.dominfo.name

    def getReason(self):
        return self.reason

    def getTimeout(self):
        return self.timeout

    def isTerminated(self):
        return self.dominfo.is_terminated()

    def isRestarted(self):
        return (self.dominfo.restart_count > self.last_restart_count)

    def isShutdown(self):
        return self.isTerminated() or self.isRestarted()

    def isExpired(self):
        return (time.time() - self.start) > self.timeout
        
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

    """Table of pending domain shutdowns, indexed by domain id."""
    shutdowns_by_id = {}

    """Table of delayed calls."""
    scheduler = Scheduler()
    
    def __init__(self):
        # Hack alert. Python does not support mutual imports, but XendDomainInfo
        # needs access to the XendDomain instance to look up domains. Attempting
        # to import XendDomain from XendDomainInfo causes unbounded recursion.
        # So we stuff the XendDomain instance (self) into xroot's components.
        xroot.add_component("xen.xend.XendDomain", self)
        # Table of domain info indexed by domain id.
        self.db = XendDB.XendDB(self.dbpath)
        self.domain_db = self.db.fetchall("")
        # XXXcl maybe check if there's only dom0 if we _really_ need
        #       to remove the db 
        # self.rm_all()
        eserver.subscribe('xend.virq', self.onVirq)
        self.initial_refresh()

    def onVirq(self, event, val):
        """Event handler for virq.
        """
        print 'onVirq>', val
        self.refresh_schedule(delay=0)

    def schedule_later(self, _delay, _name, _fn, *args):
        """Schedule a function to be called later (if not already scheduled).

        @param _delay: delay in seconds
        @param _name:  schedule name
        @param _fn:    function
        @param args:   arguments
        """
        self.scheduler.later(_delay, _name, _fn, args)
        
    def schedule_cancel(self, name):
        """Cancel a scheduled function call.
        
        @param name: schedule name to cancel
        """
        self.scheduler.cancel(name)

    def refresh_schedule(self, delay=1):
        """Schedule refresh to be called later.
        
        @param delay: delay in seconds
        """
        self.schedule_later(delay, 'refresh', self.refresh)

    def refresh_cancel(self):
        """Cancel any scheduled refresh.
        """
        self.schedule_cancel('refresh')

    def domain_restarts_schedule(self, delay=1):
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
            self._delete_domain(k, notify=False)

    def xen_domains(self):
        """Get table of domains indexed by id from xc.
        """
        domlist = xc.domain_getinfo()
        doms = {}
        for d in domlist:
            domid = str(d['dom'])
            doms[domid] = d
        return doms

    def xen_domain(self, dom):
        """Get info about a single domain from xc.
        Returns None if not found.
        """
        dom = int(dom)
        dominfo = xc.domain_getinfo(dom, 1)
        if dominfo == [] or dominfo[0]['dom'] != dom:
            dominfo = None
        else:
            dominfo = dominfo[0]
        return dominfo
            
    def initial_refresh(self):
        """Refresh initial domain info from domain_db.
        """
        doms = self.xen_domains()
        for config in self.domain_db.values():
            domid = str(sxp.child_value(config, 'id'))
            if domid in doms:
                try:
                    self._new_domain(config, doms[domid])
                    self.update_domain(domid)
                except Exception, ex:
                    log.exception("Error recreating domain info: id=%s", domid)
                    self._delete_domain(domid)
            else:
                self._delete_domain(domid)
        self.refresh()

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
        @return: domain
        """
        dominfo = XendDomainInfo.vm_recreate(savedinfo, info)
        self.domain_by_id[dominfo.id] = dominfo
        self.domain_by_name[dominfo.name] = dominfo
        if dominfo.restart_pending():
            self.domain_restart_add(dominfo)
        return dominfo

    def _add_domain(self, info, notify=True):
        """Add a domain entry to the tables.

        @param info:   domain info object
        @param notify: send a domain created event if true
        """
        # Remove entries under the wrong id.
        for i, d in self.domain_by_id.items():
            if i != d.id:
                del self.domain_by_id[i]
                if i in self.domain_db:
                    del self.domain_db[i]
                self.db.delete(i)
        # Remove entries under the wrong name.
        for n, d in self.domain_by_name.items():
            if n != d.name:
                del self.domain_by_name[n]
        # But also need to make sure are indexed under correct name.
        # What about entries under info.name ?
        if info.id in self.domain_by_id:
            notify = False
        self.domain_by_id[info.id] = info
        self.domain_db[info.id] = info.sxpr()
        if info.name:
            self.domain_by_name[info.name] = info
        self.sync_domain(info.id)
        if notify:
            eserver.inject('xend.domain.create', [info.name, info.id])

    def _delete_domain(self, id, notify=True):
        """Remove a domain from the tables.

        @param id:     domain id
        @param notify: send a domain died event if true
        """
        for (k, info) in self.domain_by_name.items():
            if info.id == id:
                del self.domain_by_name[k]
        info = self.domain_by_id.get(id)
        if info:
            del self.domain_by_id[id]
            if notify:
                eserver.inject('xend.domain.died', [info.name, info.id])
        if id in self.domain_db:
            del self.domain_db[id]
            self.db.delete(id)

    def reap(self):
        """Look for domains that have crashed or stopped.
        Tidy them up.
        """
        casualties = []
        doms = self.xen_domains()
        for d in doms.values():
            dead = 0
            dead = dead or (d['crashed'] or d['shutdown'])
            dead = dead or (d['dying'] and
                            not(d['running'] or d['paused'] or d['blocked']))
            if dead:
                casualties.append(d)
        destroyed = 0
        for d in casualties:
            id = str(d['dom'])
            #print 'reap>', id
            dominfo = self.domain_by_id.get(id)
            name = (dominfo and dominfo.name) or '??'
            if dominfo and dominfo.is_terminated():
                #print 'reap> already terminated:', id
                continue
            log.debug('XendDomain>reap> domain died name=%s id=%s', name, id)
            if d['shutdown']:
                reason = XendDomainInfo.shutdown_reason(d['shutdown_reason'])
                log.debug('XendDomain>reap> shutdown name=%s id=%s reason=%s', name, id, reason)
                if reason in ['suspend']:
                    if dominfo and dominfo.is_terminated():
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

    def refresh(self):
        """Refresh domain list from Xen.
        """
        self.refresh_cancel()
        self.refresh_schedule(delay=10)
        self.reap()
        doms = self.xen_domains()
        # Add entries for any domains we don't know about.
        for (id, d) in doms.items():
            if id not in self.domain_by_id:
                log.info("Creating entry for unknown domain: id=%s", id)
                savedinfo = None
                try:
                    dominfo = XendDomainInfo.vm_recreate(savedinfo, d)
                    self._add_domain(dominfo)
                except Exception, ex:
                    log.exception("Error creating domain info: id=%s", id)
        # Remove entries for domains that no longer exist.
        # Update entries for existing domains.
        for d in self.domain_by_id.values():
            info = doms.get(d.id)
            if info:
                d.update(info)
            elif d.restart_pending():
                pass
            else:
                self._delete_domain(d.id)

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
        dominfo = self.xen_domain(id)
        if dominfo:
            d = self.domain_by_id.get(id)
            if d:
                d.update(dominfo)
        else:
            self._delete_domain(id)

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
        @return: domain
        """
        dominfo = XendDomainInfo.vm_create(config)
        self._add_domain(dominfo)
        return dominfo

    def domain_restart(self, dominfo):
        """Restart a domain.

        @param dominfo: domain object
        """
        log.info("Restarting domain: name=%s id=%s", dominfo.name, dominfo.id)
        eserver.inject("xend.domain.restart",
                       [dominfo.name, dominfo.id, "begin"])
        try:
            dominfo.restart()
            self._add_domain(dominfo)
            log.info('Restarted domain name=%s id=%s', dominfo.name, dominfo.id)
            eserver.inject("xend.domain.restart",
                           [dominfo.name, dominfo.id, "success"])
            self.domain_unpause(dominfo.id)
        except Exception, ex:
            log.exception("Exception restarting domain: name=%s id=%s",
                          dominfo.name, dominfo.id)
            eserver.inject("xend.domain.restart",
                           [dominfo.name, dominfo.id, "fail"])
        return dominfo

    def domain_configure(self, id, vmconfig):
        """Configure an existing domain. This is intended for internal
        use by domain restore and migrate.

        @param id:       domain id
        @param vmconfig: vm configuration
        """
        config = sxp.child_value(vmconfig, 'config')
        dominfo = self.domain_lookup(id)
        log.debug('domain_configure> id=%s config=%s', str(id), str(config))
        if dominfo.config:
            raise XendError("Domain already configured: " + dominfo.id)
        dominfo.dom_construct(dominfo.dom, config)
        self._add_domain(dominfo)
        return dominfo
    
    def domain_restore(self, src, progress=False):
        """Restore a domain from file.

        @param src:      source file
        @param progress: output progress if true
        """
        xmigrate = XendMigrate.instance()
        return xmigrate.restore_begin(src)
    
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
        raise XendError('invalid domain: ' + name)

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
    
    def domain_shutdown(self, id, reason='poweroff', key=0):
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
            self.domain_restart_schedule(dominfo.id, reason, force=True)
        eserver.inject('xend.domain.shutdown', [dominfo.name, dominfo.id, reason])
        if reason == 'halt':
            reason = 'poweroff'
        val = dominfo.shutdown(reason, key=key)
        self.add_shutdown(dominfo, reason, key)
        self.refresh_schedule(delay=10)
        return val

    def add_shutdown(self, dominfo, reason, key):
        """Add a pending shutdown for a domain.
        This will destroy the domain if the shutdown times out.
        """
        if dominfo.id in self.shutdowns_by_id:
            return
        self.shutdowns_by_id[dominfo.id] = DomainShutdown(dominfo, reason, key)
        self.domain_shutdowns()

    def domain_shutdowns(self):
        """Process pending domain shutdowns.
        Destroys domains whose shutdowns have timed out.
        """
        self.schedule_cancel('domain_shutdowns')
        timeout = SHUTDOWN_TIMEOUT
        for shutdown in self.shutdowns_by_id.values():
            id = shutdown.getDomain()
            if shutdown.isShutdown():
                # Shutdown done - remove.
                print 'domain_shutdowns> done: ', id
                del self.shutdowns_by_id[id]
            elif shutdown.isExpired():
                # Shutdown expired - remove and destroy domain.
                del self.shutdowns_by_id[id]
                try:
                    log.info("Domain shutdown timeout expired: name=%s id=%s",
                             shutdown.getDomainName(), id)
                    self.domain_destroy(id, reason=shutdown.getReason())
                except Exception:
                    pass
            else:
                # Shutdown still pending.
                print 'domain_shutdowns> pending: ', id
                timeout = min(timeout, shutdown.getTimeout())
        if self.shutdowns_by_id:
            # Pending shutdowns remain - reschedule.
            self.schedule_later(timeout, 'domain_shutdowns', self.domain_shutdowns)

    def domain_restart_schedule(self, id, reason, force=False):
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
        eserver.inject("xend.domain.restart",
                       [dominfo.name, dominfo.id, "schedule"])
        self.domain_restarts_schedule()
            
    def domain_restart_cancel(self, id):
        """Cancel any restart scheduled for a domain.

        @param id: domain id
        """
        dominfo = self.restarts_by_id.get(id) or self.restarts_by_name.get(id)
        if dominfo:
            log.info('Cancelling restart for domain: name=%s id=%s',
                     dominfo.name, dominfo.id)
            eserver.inject("xend.domain.restart",
                           [dominfo.name, dominfo.id, "cancel"])
            dominfo.restart_cancel()
            del self.restarts_by_id[dominfo.id]
            del self.restarts_by_name[dominfo.name]

    def domain_restarts(self):
        """Execute any scheduled domain restarts for domains that have gone.
        """
        self.domain_restarts_cancel()
        doms = self.xen_domains()
        for dominfo in self.restarts_by_id.values():
            print 'domain_restarts>', dominfo.name, dominfo.id
            info = doms.get(dominfo.id)
            if info:
                # Don't execute restart for domains still running.
                print 'domain_restarts> still runnning: ', dominfo.name
                continue
            # Remove it from the restarts.
            del self.restarts_by_id[dominfo.id]
            del self.restarts_by_name[dominfo.name]
            print 'domain_restarts> restarting: ', dominfo.name
            self.domain_restart(dominfo)
        if self.domain_restarts_exist():
            # Run again later if any restarts remain.
            self.refresh_schedule(delay=10)

    def domain_restarts_exist(self):
        return len(self.restarts_by_id)
        
    def final_domain_destroy(self, id):
        """Final destruction of a domain..

        @param id: domain id
        """
        try:
            dominfo = self.domain_lookup(id)
            log.info('Destroying domain: name=%s', dominfo.name)
            eserver.inject('xend.domain.destroy', [dominfo.name, dominfo.id])
            val = dominfo.destroy()
        except:
            #todo
            try:
                val = xc.domain_destroy(dom=int(id))
            except Exception, ex:
                raise XendError(str(ex))
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
            self.domain_restart_schedule(id, reason, force=True)
        val = self.final_domain_destroy(id)
        self.refresh_schedule()
        return val

    def domain_migrate(self, id, dst, live=False, resource=0):
        """Start domain migration.

        @param id: domain id
        """
        # Need a cancel too?
        # Don't forget to cancel restart for it.
        dominfo = self.domain_lookup(id)
        xmigrate = XendMigrate.instance()
        return xmigrate.migrate_begin(dominfo, dst, live=live, resource=resource)

    def domain_save(self, id, dst, progress=False):
        """Start saving a domain to file.

        @param id:       domain id
        @param dst:      destination file
        @param progress: output progress if true
        """
        dominfo = self.domain_lookup(id)
        xmigrate = XendMigrate.instance()
        return xmigrate.save_begin(dominfo, dst)
    
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
    
    def domain_device_create(self, id, devconfig):
        """Create a new device for a domain.

        @param id:       domain id
        @param devconfig: device configuration
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_create(devconfig)
        self.update_domain(dominfo.id)
        self.refresh_schedule()
        return val

    def domain_device_configure(self, id, devconfig, idx):
        """Configure an existing device for a domain.

        @param id:   domain id
        @param devconfig: device configuration
        @param idx:  device index
        @return: updated device configuration
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_configure(devconfig, idx)
        self.update_domain(dominfo.id)
        self.refresh_schedule()
        return val
    
    def domain_device_refresh(self, id, type, idx):
        """Refresh a device.

        @param id:  domain id
        @param idx:  device index
        @param type: device type
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_refresh(type, idx)
        self.update_domain(dominfo.id)
        self.refresh_schedule()
        return val

    def domain_device_destroy(self, id, type, idx):
        """Destroy a device.

        @param id:  domain id
        @param idx:  device index
        @param type: device type
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_destroy(type, idx)
        self.update_domain(dominfo.id)
        self.refresh_schedule()
        return val

    def domain_devtype_ls(self, id, type):
        """Get list of device indexes for a domain.

        @param id:  domain
        @param type: device type
        @return: device indexes
        """
        dominfo = self.domain_lookup(id)
        return dominfo.getDeviceIndexes(type)

    def domain_devtype_get(self, id, type, idx):
        """Get a device from a domain.

        @param id:  domain
        @param type: device type
        @param idx:  device index
        @return: device object (or None)
        """
        dominfo = self.domain_lookup(id)
        return dominfo.getDeviceByIndex(type, idx)

    def domain_vif_limit_set(self, id, vif, credit, period):
        """Limit the vif's transmission rate
        """
        dominfo = self.domain_lookup(id)
        dev = dominfo.getDeviceById('vif', vif)
        if not dev:
            raise XendError("invalid vif")
        return dev.setCreditLimit(credit, period)
        
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

    def domain_mem_target_set(self, id, target):
        dominfo = self.domain_lookup(id)
        return dominfo.mem_target_set(target)
        


def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendDomain()
    return inst
