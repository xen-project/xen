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

import logging
import os
import socket
import sys
import threading

import xen.lowlevel.xc

import XendDomainInfo

from xen.xend import XendRoot
from xen.xend import XendCheckpoint
from xen.xend.XendError import XendError, XendInvalidDomain
from xen.xend.XendLogging import log
from xen.xend.xenstore.xstransact import xstransact
from xen.xend.xenstore.xswatch import xswatch
from xen.util import security


xc = xen.lowlevel.xc.xc()
xroot = XendRoot.instance()


__all__ = [ "XendDomain" ]

PRIV_DOMAIN = 0
VMROOT = '/vm/'


class XendDomain:
    """Index of all domains. Singleton.
    """

    ## public:
    
    def __init__(self):
        self.domains = {}
        self.domains_lock = threading.RLock()


    # This must be called only the once, by instance() below.  It is separate
    # from the constructor because XendDomainInfo calls back into this class
    # in order to check the uniqueness of domain names.  This means that
    # instance() must be able to return a valid instance of this class even
    # during this initialisation.
    def init(self):
        xstransact.Mkdir(VMROOT)
        xstransact.SetPermissions(VMROOT, { 'dom' : PRIV_DOMAIN })

        self.domains_lock.acquire()
        try:
            self._add_domain(
                XendDomainInfo.recreate(self.xen_domains()[PRIV_DOMAIN],
                                        True))
            self.dom0_setup()

            # This watch registration needs to be before the refresh call, so
            # that we're sure that we haven't missed any releases, but inside
            # the domains_lock, as we don't want the watch to fire until after
            # the refresh call has completed.
            xswatch("@introduceDomain", self.onChangeDomain)
            xswatch("@releaseDomain",   self.onChangeDomain)
            
            self.refresh(True)
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

    def onChangeDomain(self, _):
        self.domains_lock.acquire()
        try:
            self.refresh()
        finally:
            self.domains_lock.release()
        return 1


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

        # get max number of vcpus to use for dom0 from config
        target = int(xroot.get_dom0_vcpus())
        log.debug("number of vcpus to use is %d", target)
   
        # target == 0 means use all processors
        if target > 0:
            dom0.setVCpuCount(target)


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


    def refresh(self, initialising = False):
        """Refresh domain list from Xen.  Expects to be protected by the
        domains_lock.

        @param initialising True if this is the first refresh after starting
        Xend.  This does not change this method's behaviour, except for
        logging.
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
                if doms[d]['dying']:
                    log.log(initialising and logging.ERROR or logging.DEBUG,
                            'Cannot recreate information for dying domain %d.'
                            '  Xend will ignore this domain from now on.',
                            doms[d]['dom'])
                elif d == PRIV_DOMAIN:
                    log.fatal(
                        "No record of privileged domain %d!  Terminating.", d)
                    sys.exit(1)
                else:
                    try:
                        self._add_domain(
                            XendDomainInfo.recreate(doms[d], False))
                    except:
                        log.exception(
                            "Failed to recreate information for domain "
                            "%d.  Destroying it in the hope of "
                            "recovery.", d)
                        try:
                            xc.domain_destroy(d)
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
            fd = os.open(src, os.O_RDONLY)
            try:
                return self.domain_restore_fd(fd)
            finally:
                os.close(fd)
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
            raise XendError("Restore failed")


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
            security.refresh_ssidref(config)
            dominfo = XendDomainInfo.restore(config)
            self._add_domain(dominfo)
            return dominfo
        finally:
            self.domains_lock.release()


    def domain_lookup(self, domid):
        self.domains_lock.acquire()
        try:
            self.refresh()
            return self.domains.get(domid)
        finally:
            self.domains_lock.release()


    def domain_lookup_nr(self, domid):
        self.domains_lock.acquire()
        try:
            return self.domains.get(domid)
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
            return None
        finally:
            self.domains_lock.release()


    def privilegedDomain(self):
        self.domains_lock.acquire()
        try:
            return self.domains[PRIV_DOMAIN]
        finally:
            self.domains_lock.release()

 
    def domain_unpause(self, domid):
        """Unpause domain execution."""
        try:
            dominfo = self.domain_lookup_by_name_or_id_nr(domid)
            if not dominfo:
                raise XendInvalidDomain(str(domid))
            log.info("Domain %s (%d) unpaused.", dominfo.getName(),
                     dominfo.getDomid())
            return dominfo.unpause()
        except Exception, ex:
            raise XendError(str(ex))


    def domain_pause(self, domid):
        """Pause domain execution."""
        try:
            dominfo = self.domain_lookup_by_name_or_id_nr(domid)
            if not dominfo:
                raise XendInvalidDomain(str(domid))
            log.info("Domain %s (%d) paused.", dominfo.getName(),
                     dominfo.getDomid())
            return dominfo.pause()
        except Exception, ex:
            raise XendError(str(ex))


    def domain_destroy(self, domid):
        """Terminate domain immediately."""

        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
	if dominfo and dominfo.getDomid() == PRIV_DOMAIN:
            raise XendError("Cannot destroy privileged domain %s" % domid)

        if dominfo:
            val = dominfo.destroy()
        else:
            try:
                val = xc.domain_destroy(domid)
            except Exception, ex:
                raise XendError(str(ex))
        return val       

    def domain_migrate(self, domid, dst, live=False, resource=0, port=0):
        """Start domain migration."""

        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))

        if dominfo.getDomid() == PRIV_DOMAIN:
            raise XendError("Cannot migrate privileged domain %i" % domid)

        """ The following call may raise a XendError exception """
        dominfo.testMigrateDevices(live, dst)

        if port == 0:
            port = xroot.get_xend_relocation_port()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((dst, port))
        except socket.error, err:
            raise XendError("can't connect: %s" % err[1])

        sock.send("receive\n")
        sock.recv(80)
        XendCheckpoint.save(sock.fileno(), dominfo, live, dst)


    def domain_save(self, domid, dst):
        """Start saving a domain to file.

        @param dst:      destination file
        """

        try:
            dominfo = self.domain_lookup_by_name_or_id_nr(domid)
            if not dominfo:
                raise XendInvalidDomain(str(domid))

            if dominfo.getDomid() == PRIV_DOMAIN:
                raise XendError("Cannot save privileged domain %i" % domid)

            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
            try:
                # For now we don't support 'live checkpoint' 
                return XendCheckpoint.save(fd, dominfo, False, dst)
            finally:
                os.close(fd)
        except OSError, ex:
            raise XendError("can't write guest state file %s: %s" %
                            (dst, ex[1]))

    def domain_pincpu(self, domid, vcpu, cpumap):
        """Set which cpus vcpu can use

        @param cpumap:  string repr of list of usable cpus
        """
        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))

        try:
            return xc.vcpu_setaffinity(dominfo.getDomid(), vcpu, cpumap)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_set(self, domid, mcuadv, warpback, warpvalue, warpl,
                           warpu):
        """Set BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        try:
            return xc.bvtsched_domain_set(dom=dominfo.getDomid(),
                                          mcuadv=mcuadv,
                                          warpback=warpback,
                                          warpvalue=warpvalue, 
                                          warpl=warpl, warpu=warpu)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_bvt_get(self, domid):
        """Get BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        try:
            return xc.bvtsched_domain_get(dominfo.getDomid())
        except Exception, ex:
            raise XendError(str(ex))
    
    
    def domain_cpu_sedf_set(self, domid, period, slice_, latency, extratime,
                            weight):
        """Set Simple EDF scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        try:
            return xc.sedf_domain_set(dominfo.getDomid(), period, slice_,
                                      latency, extratime, weight)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_sedf_get(self, domid):
        """Get Simple EDF scheduler parameters for a domain.
        """
        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        try:
            sedf_info = xc.sedf_domain_get(dominfo.getDomid())
            # return sxpr
            return ['sedf',
                    ['domain',    sedf_info['domain']],
                    ['period',    sedf_info['period']],
                    ['slice',     sedf_info['slice']],
                    ['latency',   sedf_info['latency']],
                    ['extratime', sedf_info['extratime']],
                    ['weight',    sedf_info['weight']]]

        except Exception, ex:
            raise XendError(str(ex))

    def domain_maxmem_set(self, domid, mem):
        """Set the memory limit for a domain.

        @param mem: memory limit (in MiB)
        @return: 0 on success, -1 on error
        """
        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        maxmem = int(mem) * 1024
        try:
            return xc.domain_setmaxmem(dominfo.getDomid(), maxmem)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_ioport_range_enable(self, domid, first, last):
        """Enable access to a range of IO ports for a domain

        @param first: first IO port
        @param last: last IO port
        @return: 0 on success, -1 on error
        """
        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        nr_ports = last - first + 1
        try:
            return xc.domain_ioport_permission(dominfo.getDomid(),
                                               first_port = first,
                                               nr_ports = nr_ports,
                                               allow_access = 1)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_ioport_range_disable(self, domid, first, last):
        """Disable access to a range of IO ports for a domain

        @param first: first IO port
        @param last: last IO port
        @return: 0 on success, -1 on error
        """
        dominfo = self.domain_lookup_by_name_or_id_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        nr_ports = last - first + 1
        try:
            return xc.domain_ioport_permission(dominfo.getDomid(),
                                               first_port = first,
                                               nr_ports = nr_ports,
                                               allow_access = 0)
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
        inst.init()
    return inst
