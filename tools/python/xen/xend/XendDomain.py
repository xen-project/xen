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
# Copyright (C) 2005 XenSource Ltd
#============================================================================

"""Handler for domain operations.
 Nothing here is persistent (across reboots).
 Needs to be persistent for one uptime.
"""
import os

import xen.lowlevel.xc

from xen.xend import sxp
from xen.xend import XendRoot
from xen.xend import XendCheckpoint
from xen.xend.XendDomainInfo import XendDomainInfo, shutdown_reason
from xen.xend import EventServer
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log
from xen.xend import scheduler
from xen.xend.server import relocate
from xen.xend.xenstore import XenNode, DBMap
from xen.xend.xenstore.xstransact import xstransact


xc = xen.lowlevel.xc.new()
xroot = XendRoot.instance()
eserver = EventServer.instance()


__all__ = [ "XendDomain" ]

PRIV_DOMAIN = 0

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
        self.vmroot = "/domain"
        self.dbmap = DBMap(db=XenNode(self.vmroot))
        self.watchReleaseDomain()
        self.refresh()
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
        self.refresh()

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


    def recreate_domain(self, xeninfo):
        """Refresh initial domain info from db."""

        dominfo = XendDomainInfo.recreate(xeninfo)
        self._add_domain(dominfo)
        return dominfo


    def dom0_setup(self):
        dom0 = self.domain_lookup(PRIV_DOMAIN)
        if not dom0:
            dom0 = self.recreate_domain(self.xen_domain(PRIV_DOMAIN))
        dom0.dom0_init_store()
        dom0.dom0_enforce_vcpus()


    def _add_domain(self, info, notify=True):
        """Add a domain entry to the tables.

        @param info:   domain info object
        @param notify: send a domain created event if true
        """
        if info.getDomid() in self.domains:
            notify = False
        self.domains[info.getDomid()] = info
        info.exportToDB()
        if notify:
            eserver.inject('xend.domain.create', [info.getName(),
                                                  info.getDomid()])

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
                                                    info.getDomid()])
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


    def refresh(self):
        """Refresh domain list from Xen.
        """
        doms = self.xen_domains()
        for d in self.domains.values():
            info = doms.get(d.getDomid())
            if info:
                d.update(info)
            else:
                self._delete_domain(d.getDomid())
        for d in doms:
            if d not in self.domains:
                try:
                    self.recreate_domain(doms[d])
                except:
                    log.exception(
                        "Failed to recreate information for domain %d.  "
                        "Destroying it in the hope of recovery.", d)
                    try:
                        xc.domain_destroy(dom = d)
                    except:
                        log.exception('Destruction of %d failed.', d)


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
        dominfo = XendDomainInfo.create(self.dbmap.getPath(), config)
        self._add_domain(dominfo)
        return dominfo

    def domain_configure(self, config):
        """Configure an existing domain. This is intended for internal
        use by domain restore and migrate.

        @param vmconfig: vm configuration
        """
        # We accept our configuration specified as ['config' [...]], which
        # some tools or configuration files may be using.  For save-restore,
        # we use the value of XendDomainInfo.sxpr() directly, which has no
        # such item.
        nested = sxp.child_value(config, 'config')
        if nested:
            config = nested
        return XendDomainInfo.restore(self.dbmap.getPath(), config)

    def domain_restore(self, src, progress=False):
        """Restore a domain from file.

        @param src:      source file
        @param progress: output progress if true
        """

        try:
            fd = os.open(src, os.O_RDONLY)
            dominfo = XendCheckpoint.restore(self, fd)
            self._add_domain(dominfo)
            return dominfo
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
                                               dominfo.getDomid()])
        try:
            return xc.domain_unpause(dom=dominfo.getDomid())
        except Exception, ex:
            raise XendError(str(ex))
    
    def domain_pause(self, id):
        """Pause domain execution.

        @param id: domain id
        """
        dominfo = self.domain_lookup(id)
        eserver.inject('xend.domain.pause', [dominfo.getName(),
                                             dominfo.getDomid()])
        try:
            return xc.domain_pause(dom=dominfo.getDomid())
        except Exception, ex:
            raise XendError(str(ex))


    def domain_shutdown(self, domid, reason='poweroff'):
        """Shutdown domain (nicely).
         - poweroff: restart according to exit code and restart mode
         - reboot:   restart on exit
         - halt:     do not restart

         Returns immediately.

        @param id:     domain id
        @param reason: shutdown type: poweroff, reboot, suspend, halt
        """
        self.callInfo(domid, XendDomainInfo.shutdown, reason)


    def domain_sysrq(self, domid, key):
        """Send a SysRq to the specified domain."""
        return self.callInfo(domid, XendDomainInfo.send_sysrq, key)


    def domain_destroy(self, domid, reason='halt'):
        """Terminate domain immediately.
        - halt:   cancel any restart for the domain
        - reboot  schedule a restart for the domain

        @param domid: domain id
        """

        if domid == PRIV_DOMAIN:
            raise XendError("Cannot destroy privileged domain %i" % domid)
        
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
            return xc.domain_pincpu(dominfo.getDomid(), vcpu, cpumap)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_set(self, id, mcuadv, warpback, warpvalue, warpl, warpu):
        """Set BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.bvtsched_domain_set(dom=dominfo.getDomid(),
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
            return xc.bvtsched_domain_get(dominfo.getDomid())
        except Exception, ex:
            raise XendError(str(ex))
    
    
    def domain_cpu_sedf_set(self, id, period, slice, latency, extratime, weight):
        """Set Simple EDF scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.sedf_domain_set(dominfo.getDomid(), period, slice,
                                      latency, extratime, weight)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_sedf_get(self, id):
        """Get Simple EDF scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup(id)
        try:
            return xc.sedf_domain_get(dominfo.getDomid())
        except Exception, ex:
            raise XendError(str(ex))


    def domain_device_create(self, domid, devconfig):
        """Create a new device for the specified domain.
        """
        return self.callInfo(domid, XendDomainInfo.device_create, devconfig)


    def domain_device_configure(self, domid, devconfig, devid):
        """Configure an existing device in the specified domain.
        @return: updated device configuration
        """
        return self.callInfo(domid, XendDomainInfo.device_configure,
                             devconfig, devid)

    
    def domain_device_refresh(self, domid, devtype, devid):
        """Refresh a device."""
        return self.callInfo(domid, XendDomainInfo.device_refresh, devtype,
                             devid)


    def domain_device_destroy(self, domid, devtype, devid):
        """Destroy a device."""
        return self.callInfo(domid, XendDomainInfo.destroyDevice, devtype,
                             devid)


    def domain_devtype_ls(self, domid, devtype):
        """Get list of device sxprs for the specified domain."""
        return self.callInfo(domid, XendDomainInfo.getDeviceSxprs, devtype)


    def domain_devtype_get(self, domid, devtype, devid):
        """Get a device from a domain.
        
        @return: device object (or None)
        """
        return self.callInfo(domid, XendDomainInfo.getDevice, devtype, devid)


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
            return xc.shadow_control(dominfo.getDomid(), op)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_maxmem_set(self, id, mem):
        """Set the memory limit for a domain.

        @param id: domain
        @param mem: memory limit (in MiB)
        @return: 0 on success, -1 on error
        """
        dominfo = self.domain_lookup(id)
        maxmem = int(mem) * 1024
        try:
            return xc.domain_setmaxmem(dominfo.getDomid(),
                                       maxmem_kb = maxmem)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_mem_target_set(self, domid, mem):
        """Set the memory target for a domain.

        @param mem: memory target (in MiB)
        """
        self.callInfo(domid, XendDomainInfo.setMemoryTarget, mem << 10)


    def domain_vcpu_hotplug(self, domid, vcpu, state):
        """Enable or disable specified VCPU in specified domain

        @param vcpu: target VCPU in domain
        @param state: which state VCPU will become
        """
        self.callInfo(domid, XendDomainInfo.vcpu_hotplug, vcpu, state)


    def domain_dumpcore(self, domid):
        """Save a core dump for a crashed domain."""
        self.callInfo(domid, XendDomainInfo.dumpCore)


    ## private:

    def callInfo(self, domid, fn, *args, **kwargs):
        try:
            self.refresh()
            dominfo = self.domains.get(domid)
            if dominfo:
                return fn(dominfo, *args, **kwargs)
        except XendError:
            raise
        except Exception, exn:
            raise XendError(str(exn))


def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendDomain()
    return inst
