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
import threading

import xen.lowlevel.xc

import XendDomainInfo

from xen.xend import XendRoot
from xen.xend import XendCheckpoint
from xen.xend import EventServer
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log
from xen.xend.server import relocate


xc = xen.lowlevel.xc.new()
xroot = XendRoot.instance()
eserver = EventServer.instance()


__all__ = [ "XendDomain" ]

PRIV_DOMAIN = 0

class XendDomain:
    """Index of all domains. Singleton.
    """

    ## public:
    
    def __init__(self):
        # Hack alert. Python does not support mutual imports, but XendDomainInfo
        # needs access to the XendDomain instance to look up domains. Attempting
        # to import XendDomain from XendDomainInfo causes unbounded recursion.
        # So we stuff the XendDomain instance (self) into xroot's components.
        xroot.add_component("xen.xend.XendDomain", self)
        self.domains = {}
        self.domains_lock = threading.Condition()
        self.watchReleaseDomain()

        self.domains_lock.acquire()
        try:
            self.refresh()
            self.dom0_setup()
        finally:
            self.domains_lock.release()


    def list(self):
        """Get list of domain objects.

        @return: domain objects
        """
        self.domains_lock.acquire()
        try:
            self.refresh()
            return self.domains.values()
        finally:
            self.domains_lock.release()


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


    ## private:

    def onReleaseDomain(self):
        self.domains_lock.acquire()
        try:
            self.refresh()
        finally:
            self.domains_lock.release()
            

    def watchReleaseDomain(self):
        from xen.xend.xenstore.xswatch import xswatch
        self.releaseDomain = xswatch("@releaseDomain", self.onReleaseDomain)


    def xen_domains(self):
        """Get table of domains indexed by id from xc.  Expects to be
        protected by the domains_lock.
        """
        domlist = xc.domain_getinfo()
        doms = {}
        for d in domlist:
            domid = d['dom']
            doms[domid] = d
        return doms


    def dom0_setup(self):
        """Expects to be protected by the domains_lock."""
        dom0 = self.domains[PRIV_DOMAIN]
        dom0.dom0_enforce_vcpus()


    def _add_domain(self, info):
        """Add the given domain entry to this instance's internal cache.
        Expects to be protected by the domains_lock.
        """
        self.domains[info.getDomid()] = info


    def _delete_domain(self, domid):
        """Remove the given domain from this instance's internal cache.
        Expects to be protected by the domains_lock.
        """
        info = self.domains.get(domid)
        if info:
            del self.domains[domid]
            info.cleanupDomain()
            info.cleanupVm()


    def refresh(self):
        """Refresh domain list from Xen.  Expects to be protected by the
        domains_lock.
        """
        doms = self.xen_domains()
        for d in self.domains.values():
            info = doms.get(d.getDomid())
            if info:
                d.update(info)
            else:
                self._delete_domain(d.getDomid())
        for d in doms:
            if d not in self.domains and not doms[d]['dying']:
                try:
                    dominfo = XendDomainInfo.recreate(doms[d])
                    self._add_domain(dominfo)
                except:
                    if d == PRIV_DOMAIN:
                        log.exception(
                            "Failed to recreate information for domain "
                            "%d.  Doing nothing except crossing my "
                            "fingers.", d)
                    else:
                        log.exception(
                            "Failed to recreate information for domain "
                            "%d.  Destroying it in the hope of "
                            "recovery.", d)
                        try:
                            xc.domain_destroy(dom = d)
                        except:
                            log.exception('Destruction of %d failed.', d)


    ## public:

    def domain_create(self, config):
        """Create a domain from a configuration.

        @param config: configuration
        @return: domain
        """
        self.domains_lock.acquire()
        try:
            dominfo = XendDomainInfo.create(config)
            self._add_domain(dominfo)
            return dominfo
        finally:
            self.domains_lock.release()


    def domain_configure(self, config):
        """Configure an existing domain.

        @param vmconfig: vm configuration
        """
        # !!!
        raise XendError("Unsupported")

    def domain_restore(self, src):
        """Restore a domain from file.

        @param src:      source file
        """

        try:
            return self.domain_restore_fd(os.open(src, os.O_RDONLY))
        except OSError, ex:
            raise XendError("can't read guest state file %s: %s" %
                            (src, ex[1]))

    def domain_restore_fd(self, fd):
        """Restore a domain from the given file descriptor."""

        try:
            return XendCheckpoint.restore(self, fd)
        except:
            # I don't really want to log this exception here, but the error
            # handling in the relocation-socket handling code (relocate.py) is
            # poor, so we need to log this for debugging.
            log.exception("Restore failed")
            raise


    def restore_(self, config):
        """Create a domain as part of the restore process.  This is called
        only from {@link XendCheckpoint}.

        A restore request comes into XendDomain through {@link
        #domain_restore} or {@link #domain_restore_fd}.  That request is
        forwarded immediately to XendCheckpoint which, when it is ready, will
        call this method.  It is necessary to come through here rather than go
        directly to {@link XendDomainInfo.restore} because we need to
        serialise the domain creation process, but cannot lock
        domain_restore_fd as a whole, otherwise we will deadlock waiting for
        the old domain to die.
        """
        self.domains_lock.acquire()
        try:
            dominfo = XendDomainInfo.restore(config)
            self._add_domain(dominfo)
            return dominfo
        finally:
            self.domains_lock.release()


    def domain_lookup(self, id):
        self.domains_lock.acquire()
        try:
            self.refresh()
            return self.domains.get(id)
        finally:
            self.domains_lock.release()


    def domain_lookup_nr(self, id):
        self.domains_lock.acquire()
        try:
            return self.domains.get(id)
        finally:
            self.domains_lock.release()


    def domain_lookup_by_name_or_id(self, name):
        self.domains_lock.acquire()
        try:
            self.refresh()
            return self.domain_lookup_by_name_or_id_nr(name)
        finally:
            self.domains_lock.release()


    def domain_lookup_by_name_or_id_nr(self, name):
        self.domains_lock.acquire()
        try:
            dominfo = self.domain_lookup_by_name_nr(name)

            if dominfo:
                return dominfo
            else:
                try:
                    return self.domains.get(int(name))
                except ValueError:
                    return None
        finally:
            self.domains_lock.release()


    def domain_lookup_by_name_nr(self, name):
        self.domains_lock.acquire()
        try:
            matching = filter(lambda d: d.getName() == name,
                              self.domains.values())
            n = len(matching)
            if n == 1:
                return matching[0]
            elif n > 1:
                raise XendError(
                    'Name uniqueness has been violated for name %s' % name)
            else:
                return None
        finally:
            self.domains_lock.release()


    def privilegedDomain(self):
        self.domains_lock.acquire()
        try:
            return self.domains[PRIV_DOMAIN]
        finally:
            self.domains_lock.release()

 
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


    def domain_shutdown(self, domid, reason = 'poweroff'):
        """Shutdown domain (nicely).

        @param reason: shutdown reason: poweroff, reboot, suspend, halt
        """
        self.callInfo(domid, XendDomainInfo.XendDomainInfo.shutdown, reason)


    def domain_sysrq(self, domid, key):
        """Send a SysRq to the specified domain."""
        return self.callInfo(domid, XendDomainInfo.XendDomainInfo.send_sysrq,
                             key)


    def domain_destroy(self, domid):
        """Terminate domain immediately."""

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

        XendCheckpoint.save(sock.fileno(), dominfo, live)
        

    def domain_save(self, id, dst):
        """Start saving a domain to file.

        @param id:       domain id
        @param dst:      destination file
        """

        try:
            dominfo = self.domain_lookup(id)

            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)

            # For now we don't support 'live checkpoint' 
            return XendCheckpoint.save(fd, dominfo, False)

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
        return self.callInfo(domid,
                             XendDomainInfo.XendDomainInfo.device_create,
                             devconfig)


    def domain_device_configure(self, domid, devconfig, devid):
        """Configure an existing device in the specified domain.
        @return: updated device configuration
        """
        return self.callInfo(domid,
                             XendDomainInfo.XendDomainInfo.device_configure,
                             devconfig, devid)

    
    def domain_device_refresh(self, domid, devtype, devid):
        """Refresh a device."""
        return self.callInfo(domid,
                             XendDomainInfo.XendDomainInfo.device_refresh,
                             devtype, devid)


    def domain_device_destroy(self, domid, devtype, devid):
        """Destroy a device."""
        return self.callInfo(domid,
                             XendDomainInfo.XendDomainInfo.destroyDevice,
                             devtype, devid)


    def domain_devtype_ls(self, domid, devtype):
        """Get list of device sxprs for the specified domain."""
        return self.callInfo(domid,
                             XendDomainInfo.XendDomainInfo.getDeviceSxprs,
                             devtype)


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
        self.callInfo(domid, XendDomainInfo.XendDomainInfo.setMemoryTarget,
                      mem << 10)


    def domain_vcpu_hotplug(self, domid, vcpu, state):
        """Enable or disable specified VCPU in specified domain

        @param vcpu: target VCPU in domain
        @param state: which state VCPU will become
        """
        self.callInfo(domid, XendDomainInfo.XendDomainInfo.vcpu_hotplug, vcpu,
                      state)


    def domain_dumpcore(self, domid):
        """Save a core dump for a crashed domain."""
        self.callInfo(domid, XendDomainInfo.XendDomainInfo.dumpCore)


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
            log.exception("")
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
