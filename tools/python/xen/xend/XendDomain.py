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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
#============================================================================

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
from xen.xend.server import relocate
from xen.xend.uuid import getUuid
from xen.xend.xenstore import XenNode, DBMap
from xen.xend.xenstore.xstransact import xstransact
from xen.xend.xenstore.xsutil import GetDomainPath

__all__ = [ "XendDomain" ]

SHUTDOWN_TIMEOUT = 30

def is_dead(dom):
    return dom['crashed'] or dom['shutdown'] or (
        dom['dying'] and not(dom['running'] or dom['paused'] or
                             dom['blocked']))


class XendDomainDict(dict):
    def get_by_name(self, name):
        try:
            return filter(lambda d: d.getName() == name, self.values())[0]
        except IndexError, err:
            return None

class XendDomain:
    """Index of all domains. Singleton.
    """

    """Dict of domain info indexed by domain id."""
    domains = None
    
    def __init__(self):
        # Hack alert. Python does not support mutual imports, but XendDomainInfo
        # needs access to the XendDomain instance to look up domains. Attempting
        # to import XendDomain from XendDomainInfo causes unbounded recursion.
        # So we stuff the XendDomain instance (self) into xroot's components.
        xroot.add_component("xen.xend.XendDomain", self)
        self.domains = XendDomainDict()
        self.domroot = "/domain"
        self.vmroot = "/domain"
        self.dbmap = DBMap(db=XenNode(self.vmroot))
        self.watchReleaseDomain()
        self.initial_refresh()
        self.dom0_setup()

    def list(self):
        """Get list of domain objects.

        @return: domain objects
        """
        self.refresh()
        return self.domains.values()

    def list_sorted(self):
        """Get list of domain objects, sorted by name.

        @return: domain objects
        """
        doms = self.list()
        doms.sort(lambda x, y: cmp(x.getName(), y.getName()))
        return doms

    def list_names(self):
        """Get list of domain names.

        @return: domain names
        """
        doms = self.list_sorted()
        return map(lambda x: x.getName(), doms)

    def onReleaseDomain(self):
        self.reap()
        self.refresh()
        self.domain_restarts()

    def watchReleaseDomain(self):
        from xen.xend.xenstore.xswatch import xswatch
        self.releaseDomain = xswatch("@releaseDomain", self.onReleaseDomain)

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
        self.dbmap.readDB()             # XXX only needed for "xend"
        for dom in doms.values():
            domid = dom['dom']
            dompath = GetDomainPath(domid)
            if not dompath:
                continue
            vmpath = xstransact.Read(dompath, "vm")
            if not vmpath:
                continue
            uuid = xstransact.Read(vmpath, "uuid")
            if not uuid:
                continue
            log.info("recreating domain %d, uuid %s" % (domid, uuid))
            dompath = "/".join(dompath.split("/")[0:-1])
            db = self.dbmap.addChild("%s/xend" % uuid)
            try:
                dominfo = XendDomainInfo.recreate(uuid, dompath, domid, db,
                                                  dom)
            except Exception, ex:
                log.exception("Error recreating domain info: id=%d", domid)
                continue
            self._add_domain(dominfo)
        self.reap()
        self.refresh()
        self.domain_restarts()

    def dom0_setup(self):
        dom0 = self.domain_lookup(0)
        if not dom0:
            dom0 = self.dom0_unknown()
        dom0.dom0_init_store()    
        dom0.dom0_enforce_vcpus()

    def close(self):
        pass

    def _add_domain(self, info, notify=True):
        """Add a domain entry to the tables.

        @param info:   domain info object
        @param notify: send a domain created event if true
        """
        if info.getDomain() in self.domains:
            notify = False
        self.domains[info.getDomain()] = info
        info.exportToDB(save=True)
        if notify:
            eserver.inject('xend.domain.create', [info.getName(),
                                                  info.getDomain()])

    def _delete_domain(self, id, notify=True):
        """Remove a domain from the tables.

        @param id:     domain id
        @param notify: send a domain died event if true
        """
        info = self.domains.get(id)
        if info:
            del self.domains[id]
            info.cleanup()
            info.delete()
            if notify:
                eserver.inject('xend.domain.died', [info.getName(),
                                                    info.getDomain()])
        # XXX this should not be needed
        for domdb in self.dbmap.values():
            if not domdb.has_key("xend"):
                continue
            db = domdb.addChild("xend")
            try:
                domid = int(domdb["domid"].getData())
            except:
                domid = None
            if (domid is None) or (domid == id):
                domdb.delete()

    def reap(self):
        """Look for domains that have crashed or stopped.
        Tidy them up.
        """
        doms = self.xen_domains()
        for d in doms.values():
            if not is_dead(d):
                continue
            domid = d['dom']
            dominfo = self.domains.get(domid)
            if not dominfo or dominfo.is_terminated():
                continue
            log.debug('domain died name=%s domid=%d', dominfo.getName(), domid)
            if d['crashed'] and xroot.get_enable_dump():
                self.domain_dumpcore(domid)
            if d['shutdown']:
                reason = shutdown_reason(d['shutdown_reason'])
                log.debug('shutdown name=%s id=%d reason=%s',
                          dominfo.getName(), domid, reason)
                if reason == 'suspend':
                    dominfo.state_set("suspended")
                    continue
                if reason in ['poweroff', 'reboot']:
                    self.domain_restart_schedule(domid, reason)
            dominfo.destroy()

    def refresh(self):
        """Refresh domain list from Xen.
        """
        doms = self.xen_domains()
        # Remove entries for domains that no longer exist.
        # Update entries for existing domains.
        for d in self.domains.values():
            info = doms.get(d.getDomain())
            if info:
                d.update(info)
            elif not d.restart_pending():
                self._delete_domain(d.getDomain())

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

    def domain_create(self, config):
        """Create a domain from a configuration.

        @param config: configuration
        @return: domain
        """
        return XendDomainInfo.create(self.dbmap.getPath(), config)

    def domain_restart(self, dominfo):
        """Restart a domain.

        @param dominfo: domain object
        """
        log.info("Restarting domain: name=%s id=%s", dominfo.getName(),
                 dominfo.getDomain())
        eserver.inject("xend.domain.restart",
                       [dominfo.getName(), dominfo.getDomain(), "begin"])
        try:
            dominfo.restart()
            log.info('Restarted domain name=%s id=%s', dominfo.getName(),
                     dominfo.getDomain())
            eserver.inject("xend.domain.restart",
                           [dominfo.getName(), dominfo.getDomain(),
                            "success"])
            self.domain_unpause(dominfo.getDomain())
        except Exception, ex:
            log.exception("Exception restarting domain: name=%s id=%s",
                          dominfo.getName(), dominfo.getDomain())
            eserver.inject("xend.domain.restart",
                           [dominfo.getName(), dominfo.getDomain(), "fail"])
        return dominfo

    def domain_configure(self, vmconfig):
        """Configure an existing domain. This is intended for internal
        use by domain restore and migrate.

        @param vmconfig: vm configuration
        """
        config = sxp.child_value(vmconfig, 'config')
        return XendDomainInfo.restore(self.dbmap.getPath(), config)

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

    def dom0_unknown(self):
        dom0 = 0
        uuid = None
        info = self.xen_domain(dom0)
        dompath = GetDomainPath(dom0)
        if dompath:
            vmpath = xstransact.Read(dompath, "vm")
            if vmpath:
                uuid = xstransact.Read(vmpath, "uuid")
            if not uuid:
                uuid = dompath.split("/")[-1]
            dompath = "/".join(dompath.split("/")[0:-1])
        if not uuid:
            uuid = getUuid()
            dompath = self.domroot
        log.info("Creating entry for unknown xend domain: id=%d uuid=%s",
                 dom0, uuid)
        try:
            dominfo = XendDomainInfo.recreate(uuid, dompath, info)
        except Exception, exn:
            log.exception(exn)
            raise XendError("Error recreating xend domain info: id=%d: %s" %
                            (dom0, str(exn)))
        self._add_domain(dominfo)
        return dominfo
        
    def domain_lookup(self, id):
        return self.domains.get(id)

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
        eserver.inject('xend.domain.unpause', [dominfo.getName(),
                                               dominfo.getDomain()])
        try:
            return xc.domain_unpause(dom=dominfo.getDomain())
        except Exception, ex:
            raise XendError(str(ex))
    
    def domain_pause(self, id):
        """Pause domain execution.

        @param id: domain id
        """
        dominfo = self.domain_lookup(id)
        eserver.inject('xend.domain.pause', [dominfo.getName(),
                                             dominfo.getDomain()])
        try:
            return xc.domain_pause(dom=dominfo.getDomain())
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
        self.domain_restart_schedule(dominfo.getDomain(), reason, force=True)
        eserver.inject('xend.domain.shutdown', [dominfo.getName(),
                                                dominfo.getDomain(), reason])
        if reason == 'halt':
            reason = 'poweroff'
        val = dominfo.shutdown(reason)
        if not reason in ['suspend']:
            self.domain_shutdowns()
        return val

    def domain_sysrq(self, id, key):
        """Send a SysRq to a domain
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.send_sysrq(key)
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
            id = dominfo.getDomain()
            left = dominfo.shutdown_time_left(SHUTDOWN_TIMEOUT)
            if left <= 0:
                # Shutdown expired - destroy domain.
                try:
                    log.info("Domain shutdown timeout expired: name=%s id=%s",
                             dominfo.getName(), id)
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
                     dominfo.getName(), dominfo.getDomain())
            eserver.inject("xend.domain.restart",
                           [dominfo.getName(), dominfo.getDomain(),
                            "schedule"])
            dominfo.restarting()
        else:
            log.info('Cancelling restart for domain: name=%s id=%s',
                     dominfo.getName(), dominfo.getDomain())
            eserver.inject("xend.domain.restart",
                           [dominfo.getName(), dominfo.getDomain(), "cancel"])
            dominfo.restart_cancel()

    def domain_restarts(self):
        """Execute any scheduled domain restarts for domains that have gone.
        """
        doms = self.xen_domains()
        for dominfo in self.domains.values():
            if not dominfo.restart_pending():
                continue
            info = doms.get(dominfo.getDomain())
            if info:
                # Don't execute restart for domains still running.
                continue
            # Remove it from the restarts.
            log.info('restarting: %s' % dominfo.getName())
            self.domain_restart(dominfo)

    def domain_destroy(self, domid, reason='halt'):
        """Terminate domain immediately.
        - halt:   cancel any restart for the domain
        - reboot  schedule a restart for the domain

        @param domid: domain id
        """
        self.domain_restart_schedule(domid, reason, force=True)
        dominfo = self.domain_lookup(domid)
        if dominfo:
            val = dominfo.destroy()
        else:
            try:
                val = xc.domain_destroy(dom=domid)
            except Exception, ex:
                raise XendError(str(ex))
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
            dominfo.setName("tmp-" + dominfo.getName())

        try:
            XendCheckpoint.save(self, sock.fileno(), dominfo, live)
        except:
            if dst == "localhost":
                dominfo.setName(
                    string.replace(dominfo.getName(), "tmp-", "", 1))
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

            # For now we don't support 'live checkpoint' 
            return XendCheckpoint.save(self, fd, dominfo, False)

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
            return xc.domain_pincpu(dominfo.getDomain(), vcpu, cpumap)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_set(self, id, mcuadv, warpback, warpvalue, warpl, warpu):
        """Set BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.bvtsched_domain_set(dom=dominfo.getDomain(),
                                          mcuadv=mcuadv,
                                          warpback=warpback,
                                          warpvalue=warpvalue, 
                                          warpl=warpl, warpu=warpu)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_get(self, id):
        """Get BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.bvtsched_domain_get(dominfo.getDomain())
        except Exception, ex:
            raise XendError(str(ex))
    
    
    def domain_cpu_sedf_set(self, id, period, slice, latency, extratime, weight):
        """Set Simple EDF scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.sedf_domain_set(dominfo.getDomain(), period, slice,
                                      latency, extratime, weight)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_sedf_get(self, id):
        """Get Simple EDF scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.sedf_domain_get(dominfo.getDomain())
        except Exception, ex:
            raise XendError(str(ex))

    def domain_device_create(self, id, devconfig):
        """Create a new device for a domain.

        @param id:       domain id
        @param devconfig: device configuration
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_create(devconfig)
        dominfo.exportToDB()
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
        dominfo.exportToDB()
        return val
    
    def domain_device_refresh(self, id, type, devid):
        """Refresh a device.

        @param id:  domain id
        @param devid:  device id
        @param type: device type
        """
        dominfo = self.domain_lookup(id)
        val = dominfo.device_refresh(type, devid)
        dominfo.exportToDB()
        return val

    def domain_device_destroy(self, id, type, devid):
        """Destroy a device.

        @param id:  domain id
        @param devid:  device id
        @param type: device type
        """
        dominfo = self.domain_lookup(id)
        return dominfo.destroyDevice(type, devid)


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
            return xc.shadow_control(dominfo.getDomain(), op)
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
            return xc.domain_setmaxmem(dominfo.getDomain(),
                                       maxmem_kb = maxmem)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_mem_target_set(self, id, mem):
        """Set the memory target for a domain.

        @param id: domain
        @param mem: memory target (in MB)
        @return: 0 on success, -1 on error
        """
        dominfo = self.domain_lookup(id)
        return dominfo.setMemoryTarget(mem * (1 << 20))

    def domain_vcpu_hotplug(self, id, vcpu, state):
        """Enable or disable VCPU vcpu in DOM id

        @param id: domain
        @param vcpu: target VCPU in domain
        @param state: which state VCPU will become
        @return: 0 on success, -1 on error
        """

        dominfo = self.domain_lookup(id)
        return dominfo.vcpu_hotplug(vcpu, state)

    def domain_dumpcore(self, id):
        """Save a core dump for a crashed domain.

        @param id: domain
        """
        dominfo = self.domain_lookup(id)
        corefile = "/var/xen/dump/%s.%s.core" % (dominfo.getName(),
                                                 dominfo.getDomain())
        try:
            xc.domain_dumpcore(dom=dominfo.getDomain(), corefile=corefile)
        except Exception, ex:
            log.warning("Dumpcore failed, id=%s name=%s: %s",
                        dominfo.getDomain(), dominfo.getName(), ex)
        
def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendDomain()
    return inst
