# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>

"""Handler for domain operations.
 Nothing here is persistent (across reboots).
 Needs to be persistent for one uptime.
"""
import errno
import os
import sys
import time
import traceback

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()

from xen.xend import sxp
from xen.xend import XendRoot; xroot = XendRoot.instance()
from xen.xend import XendCheckpoint
from xen.xend.XendDomainInfo import XendDomainInfo, shutdown_reason
from xen.xend import EventServer; eserver = EventServer.instance()
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log
from xen.xend import scheduler
from xen.xend.server import channel
from xen.xend.server import relocate
from xen.xend import XendDB

__all__ = [ "XendDomain" ]

SHUTDOWN_TIMEOUT = 30

class XendDomainDict(dict):
    def get_by_name(self, name):
        try:
            return filter(lambda d: d.name == name, self.values())[0]
        except IndexError, err:
            return None

class XendDomain:
    """Index of all domains. Singleton.
    """

    """Path to domain database."""
    dbpath = "domain"

    """Dict of domain info indexed by domain id."""
    domains = None
    
    def __init__(self):
        # Hack alert. Python does not support mutual imports, but XendDomainInfo
        # needs access to the XendDomain instance to look up domains. Attempting
        # to import XendDomain from XendDomainInfo causes unbounded recursion.
        # So we stuff the XendDomain instance (self) into xroot's components.
        xroot.add_component("xen.xend.XendDomain", self)
        self.domains = XendDomainDict()
        self.db = XendDB.XendDB(self.dbpath)
        eserver.subscribe('xend.virq', self.onVirq)
        self.initial_refresh()

    def list(self):
        """Get list of domain objects.

        @return: domain objects
        """
        return self.domains.values()
    
    def onVirq(self, event, val):
        """Event handler for virq.
        """
        self.refresh(cleanup=True)

    def xen_domains(self):
        """Get table of domains indexed by id from xc.
        """
        domlist = xc.domain_getinfo()
        doms = {}
        for d in domlist:
            domid = d['dom']
            doms[domid] = d
        return doms

    def xen_domain(self, dom):
        """Get info about a single domain from xc.
        Returns None if not found.

        @param dom domain id (int)
        """
        dominfo = xc.domain_getinfo(dom, 1)
        if dominfo == [] or dominfo[0]['dom'] != dom:
            dominfo = None
        else:
            dominfo = dominfo[0]
        return dominfo
            
    def initial_refresh(self):
        """Refresh initial domain info from db.
        """
        doms = self.xen_domains()
        for config in self.db.fetchall("").values():
            domid = int(sxp.child_value(config, 'id'))
            if domid in doms:
                try:
                    self._new_domain(config, doms[domid])
                except Exception, ex:
                    log.exception("Error recreating domain info: id=%d", domid)
                    self._delete_domain(domid)
            else:
                self._delete_domain(domid)
        self.refresh(cleanup=True)

    def sync_domain(self, info):
        """Sync info for a domain to disk.

        info	domain info
        """
        self.db.save(str(info.id), info.sxpr())

    def close(self):
        pass

    def _new_domain(self, savedinfo, info):
        """Create a domain entry from saved info.

        @param savedinfo: saved info from the db
        @param info:      domain info from xen
        @return: domain
        """
        uuid = sxp.child_value(savedinfo, 'uuid')
        dominfo = XendDomainInfo.recreate(savedinfo, info, uuid)
        self.domains[dominfo.id] = dominfo
        self.sync_domain(dominfo)
        return dominfo

    def _add_domain(self, info, notify=True):
        """Add a domain entry to the tables.

        @param info:   domain info object
        @param notify: send a domain created event if true
        """
        # Remove entries under the wrong id.
        for i, d in self.domains.items():
            if i != d.id:
                del self.domains[i]
                self.db.delete(str(i))
        if info.id in self.domains:
            notify = False
        self.domains[info.id] = info
        self.sync_domain(info)
        if notify:
            eserver.inject('xend.domain.create', [info.name, info.id])

    def _delete_domain(self, id, notify=True):
        """Remove a domain from the tables.

        @param id:     domain id
        @param notify: send a domain died event if true
        """
        info = self.domains.get(id)
        if info:
            del self.domains[id]
            self.db.delete(str(id))
            if notify:
                eserver.inject('xend.domain.died', [info.name, info.id])

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
        for d in casualties:
            id = d['dom']
            dominfo = self.domains.get(id)
            name = (dominfo and dominfo.name) or '??'
            if dominfo and dominfo.is_terminated():
                continue
            log.debug('XendDomain>reap> domain died name=%s id=%d', name, id)
            if d['shutdown']:
                reason = shutdown_reason(d['shutdown_reason'])
                log.debug('XendDomain>reap> shutdown name=%s id=%d reason=%s', name, id, reason)
                if reason in ['suspend']:
                    if dominfo and dominfo.is_terminated():
                        log.debug('XendDomain>reap> Suspended domain died id=%d', id)
                    else:
                        eserver.inject('xend.domain.suspended', [name, id])
                        if dominfo:
                            dominfo.state_set("suspended")
                        continue
                if reason in ['poweroff', 'reboot']:
                    eserver.inject('xend.domain.exit', [name, id, reason])
                    self.domain_restart_schedule(id, reason)
            else:
               if xroot.get_enable_dump():
                   self.domain_dumpcore(id)
               eserver.inject('xend.domain.exit', [name, id, 'crash']) 
            self.final_domain_destroy(id)

    def refresh(self, cleanup=False):
        """Refresh domain list from Xen.
        """
        if cleanup:
            self.reap()
        doms = self.xen_domains()
        # Add entries for any domains we don't know about.
        for id in doms.keys():
            if id not in self.domains:
                self.domain_lookup(id)
        # Remove entries for domains that no longer exist.
        # Update entries for existing domains.
        do_domain_restarts = False
        for d in self.domains.values():
            info = doms.get(d.id)
            if info:
                d.update(info)
            elif d.restart_pending():
                do_domain_restarts = True
            else:
                self._delete_domain(d.id)
        if cleanup and do_domain_restarts:
            scheduler.now(self.domain_restarts)

    def update_domain(self, id):
        """Update information for a single domain.

        @param id: domain id
        """
        dominfo = self.xen_domain(id)
        if dominfo:
            d = self.domains.get(id)
            if d:
                d.update(dominfo)
        else:
            self._delete_domain(id)

    def domain_ls(self):
        """Get list of domain names.

        @return: domain names
        """
        self.refresh()
        doms = self.domains.values()
        doms.sort(lambda x, y: cmp(x.name, y.name))
        return map(lambda x: x.name, doms)

    def domain_ls_ids(self):
        """Get list of domain ids.

        @return: domain names
        """
        self.refresh()
        return self.domains.keys()

    def domain_create(self, config):
        """Create a domain from a configuration.

        @param config: configuration
        @return: domain
        """
        dominfo = XendDomainInfo.create(config)
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

    def domain_configure(self, vmconfig):
        """Configure an existing domain. This is intended for internal
        use by domain restore and migrate.

        @param vmconfig: vm configuration
        """
        config = sxp.child_value(vmconfig, 'config')
        uuid = sxp.child_value(vmconfig, 'uuid')
        dominfo = XendDomainInfo.restore(config, uuid=uuid)
        self._add_domain(dominfo)
        return dominfo

    def domain_restore(self, src, progress=False):
        """Restore a domain from file.

        @param src:      source file
        @param progress: output progress if true
        """

        try:
            fd = os.open(src, os.O_RDONLY)
            return XendCheckpoint.restore(self, fd)
        except OSError, ex:
            raise XendError("can't read guest state file %s: %s" %
                            (src, ex[1]))

    def domain_get(self, id):
        """Get up-to-date info about a domain.

        @param id: domain id
        @return: domain object (or None)
        """
        self.update_domain(id)
        return self.domains.get(id)

    def domain_lookup(self, id):
        dominfo = self.domains.get(id)
        if not dominfo:
            try:
                info = self.xen_domain(id)
                if info:
                    log.info("Creating entry for unknown domain: id=%d", id)
                    dominfo = XendDomainInfo.recreate(None, info)
                    self._add_domain(dominfo)
            except Exception, ex:
                log.exception("Error creating domain info: id=%d", id)
        return dominfo

    def domain_lookup_by_name(self, name):
        dominfo = self.domains.get_by_name(name)
        if not dominfo:
            try:
                id = int(name)
                dominfo = self.domain_lookup(id)
            except ValueError:
                pass
        return dominfo

    def domain_unpause(self, id):
        """Unpause domain execution.

        @param id: domain id
        """
        dominfo = self.domain_lookup(id)
        eserver.inject('xend.domain.unpause', [dominfo.name, dominfo.id])
        try:
            return xc.domain_unpause(dom=dominfo.id)
        except Exception, ex:
            raise XendError(str(ex))
    
    def domain_pause(self, id):
        """Pause domain execution.

        @param id: domain id
        """
        dominfo = self.domain_lookup(id)
        eserver.inject('xend.domain.pause', [dominfo.name, dominfo.id])
        try:
            return xc.domain_pause(dom=dominfo.id)
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
        self.domain_restart_schedule(dominfo.id, reason, force=True)
        eserver.inject('xend.domain.shutdown', [dominfo.name, dominfo.id, reason])
        if reason == 'halt':
            reason = 'poweroff'
        val = dominfo.shutdown(reason, key=key)
        if not reason in ['suspend', 'sysrq']:
            self.domain_shutdowns()
        return val

    def domain_shutdowns(self):
        """Process pending domain shutdowns.
        Destroys domains whose shutdowns have timed out.
        """
        timeout = SHUTDOWN_TIMEOUT + 1
        for dominfo in self.domains.values():
            if not dominfo.shutdown_pending:
                # domain doesn't need shutdown
                continue
            id = dominfo.id
            left = dominfo.shutdown_time_left(SHUTDOWN_TIMEOUT)
            if left <= 0:
                # Shutdown expired - destroy domain.
                try:
                    log.info("Domain shutdown timeout expired: name=%s id=%s",
                             dominfo.name, id)
                    self.domain_destroy(id, reason=
                                        dominfo.shutdown_pending['reason'])
                except Exception:
                    pass
            else:
                # Shutdown still pending.
                timeout = min(timeout, left)
        if timeout <= SHUTDOWN_TIMEOUT:
            # Pending shutdowns remain - reschedule.
            scheduler.later(timeout, self.domain_shutdowns)

    def domain_restart_schedule(self, id, reason, force=False):
        """Schedule a restart for a domain if it needs one.

        @param id:     domain id
        @param reason: shutdown reason
        """
        log.debug('domain_restart_schedule> %d %s %d', id, reason, force)
        dominfo = self.domain_lookup(id)
        if not dominfo:
            return
        restart = (force and reason == 'reboot') or dominfo.restart_needed(reason)
        if restart:
            log.info('Scheduling restart for domain: name=%s id=%s',
                     dominfo.name, dominfo.id)
            eserver.inject("xend.domain.restart",
                           [dominfo.name, dominfo.id, "schedule"])
            dominfo.restarting()
        else:
            log.info('Cancelling restart for domain: name=%s id=%s',
                     dominfo.name, dominfo.id)
            eserver.inject("xend.domain.restart",
                           [dominfo.name, dominfo.id, "cancel"])
            dominfo.restart_cancel()

    def domain_restarts(self):
        """Execute any scheduled domain restarts for domains that have gone.
        """
        doms = self.xen_domains()
        for dominfo in self.domains.values():
            if not dominfo.restart_pending():
                continue
            print 'domain_restarts>', dominfo.name, dominfo.id
            info = doms.get(dominfo.id)
            if info:
                # Don't execute restart for domains still running.
                print 'domain_restarts> still runnning: ', dominfo.name
                continue
            # Remove it from the restarts.
            print 'domain_restarts> restarting: ', dominfo.name
            self.domain_restart(dominfo)

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
                val = xc.domain_destroy(dom=id)
            except Exception, ex:
                raise XendError(str(ex))
        return val       

    def domain_destroy(self, id, reason='halt'):
        """Terminate domain immediately.
        - halt:   cancel any restart for the domain
        - reboot  schedule a restart for the domain

        @param id: domain id
        """
        self.domain_restart_schedule(id, reason, force=True)
        val = self.final_domain_destroy(id)
        return val

    def domain_migrate(self, id, dst, live=False, resource=0):
        """Start domain migration.

        @param id: domain id
        """
        # Need a cancel too?
        # Don't forget to cancel restart for it.
        dominfo = self.domain_lookup(id)

        port = xroot.get_xend_relocation_port()
        sock = relocate.setupRelocation(dst, port)

        # temporarily rename domain for localhost migration
        if dst == "localhost":
            dominfo.name = "tmp-" + dominfo.name

        try:
            XendCheckpoint.save(self, sock.fileno(), dominfo)
        except:
            if dst == "localhost":
                dominfo.name = string.replace(dominfo.name, "tmp-", "", 1)
            raise
        
        return None

    def domain_save(self, id, dst, progress=False):
        """Start saving a domain to file.

        @param id:       domain id
        @param dst:      destination file
        @param progress: output progress if true
        """

        try:
            dominfo = self.domain_lookup(id)

            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)

            return XendCheckpoint.save(self, fd, dominfo)

        except OSError, ex:
            raise XendError("can't write guest state file %s: %s" %
                            (dst, ex[1]))

    def domain_pincpu(self, id, vcpu, cpumap):
        """Set which cpus vcpu can use

        @param id:   domain
        @param vcpu: vcpu number
        @param cpumap:  bitmap of usbale cpus
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.domain_pincpu(dominfo.id, vcpu, cpumap)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_set(self, id, mcuadv, warpback, warpvalue, warpl, warpu):
        """Set BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.bvtsched_domain_set(dom=dominfo.id, mcuadv=mcuadv,
                                          warpback=warpback, warpvalue=warpvalue, 
                                          warpl=warpl, warpu=warpu)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_get(self, id):
        """Get BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.bvtsched_domain_get(dominfo.id)
        except Exception, ex:
            raise XendError(str(ex))
    
    
    def domain_cpu_sedf_set(self, id, period, slice, latency, extratime, weight):
        """Set Simple EDF scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.sedf_domain_set(dominfo.id, period, slice, latency, extratime, weight)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_sedf_get(self, id):
        """Get Simple EDF scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.sedf_domain_get(dominfo.id)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_device_create(self, id, devconfig):
        """Create a new device for a domain.

        @param id:       domain id
        @param devconfig: device configuration
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_create(devconfig)
        self.sync_domain(dominfo)
        return val

    def domain_device_configure(self, id, devconfig, devid):
        """Configure an existing device for a domain.

        @param id:   domain id
        @param devconfig: device configuration
        @param devid:  device id
        @return: updated device configuration
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_configure(devconfig, devid)
        self.sync_domain(dominfo)
        return val
    
    def domain_device_refresh(self, id, type, devid):
        """Refresh a device.

        @param id:  domain id
        @param devid:  device id
        @param type: device type
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_refresh(type, devid)
        self.sync_domain(dominfo)
        return val

    def domain_device_destroy(self, id, type, devid):
        """Destroy a device.

        @param id:  domain id
        @param devid:  device id
        @param type: device type
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_destroy(type, devid)
        self.sync_domain(dominfo)
        return val

    def domain_devtype_ls(self, id, type):
        """Get list of device sxprs for a domain.

        @param id:  domain
        @param type: device type
        @return: device sxprs
        """
        dominfo = self.domain_lookup(id)
        return dominfo.getDeviceSxprs(type)

    def domain_devtype_get(self, id, type, devid):
        """Get a device from a domain.
        
        @param id:  domain
        @param type: device type
        @param devid:  device id
        @return: device object (or None)
        """
        dominfo = self.domain_lookup(id)
        return dominfo.getDevice(type, devid)

    def domain_vif_limit_set(self, id, vif, credit, period):
        """Limit the vif's transmission rate
        """
        dominfo = self.domain_lookup(id)
        dev = dominfo.getDevice('vif', vif)
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
            return xc.shadow_control(dominfo.id, op)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_maxmem_set(self, id, mem):
        """Set the memory limit for a domain.

        @param id: domain
        @param mem: memory limit (in MB)
        @return: 0 on success, -1 on error
        """
        dominfo = self.domain_lookup(id)
        maxmem = int(mem) * 1024
        try:
            return xc.domain_setmaxmem(dominfo.id, maxmem_kb = maxmem)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_mem_target_set(self, id, mem):
        """Set the memory target for a domain.

        @param id: domain
        @param mem: memory target (in MB)
        @return: 0 on success, -1 on error
        """
        dominfo = self.domain_lookup(id)
        return dominfo.mem_target_set(mem)

    def domain_dumpcore(self, id):
        """Save a core dump for a crashed domain.

        @param id: domain
        """
        dominfo = self.domain_lookup(id)
        corefile = "/var/xen/dump/%s.%s.core"% (dominfo.name, dominfo.id)
        try:
            xc.domain_dumpcore(dom=dominfo.id, corefile=corefile)
        except Exception, ex:
            log.warning("Dumpcore failed, id=%s name=%s: %s",
                        dominfo.id, dominfo.name, ex)
        
def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendDomain()
    return inst
