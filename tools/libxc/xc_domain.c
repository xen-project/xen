/******************************************************************************
 * xc_domain.c
 *
 * API for manipulating and obtaining information on domains.
 *
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"
#include <xen/memory.h>

int xc_domain_create(int xc_handle,
                     uint32_t ssidref,
                     xen_domain_handle_t handle,
                     uint32_t flags,
                     uint32_t *pdomid)
{
    int err;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_createdomain;
    domctl.domain = (domid_t)*pdomid;
    domctl.u.createdomain.ssidref = ssidref;
    domctl.u.createdomain.flags   = flags;
    memcpy(domctl.u.createdomain.handle, handle, sizeof(xen_domain_handle_t));
    if ( (err = do_domctl(xc_handle, &domctl)) != 0 )
        return err;

    *pdomid = (uint16_t)domctl.domain;
    return 0;
}


int xc_domain_pause(int xc_handle,
                    uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_pausedomain;
    domctl.domain = (domid_t)domid;
    return do_domctl(xc_handle, &domctl);
}


int xc_domain_unpause(int xc_handle,
                      uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_unpausedomain;
    domctl.domain = (domid_t)domid;
    return do_domctl(xc_handle, &domctl);
}


int xc_domain_destroy(int xc_handle,
                      uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_destroydomain;
    domctl.domain = (domid_t)domid;
    return do_domctl(xc_handle, &domctl);
}

int xc_domain_shutdown(int xc_handle,
                       uint32_t domid,
                       int reason)
{
    int ret = -1;
    sched_remote_shutdown_t arg;
    DECLARE_HYPERCALL;

    hypercall.op     = __HYPERVISOR_sched_op;
    hypercall.arg[0] = (unsigned long)SCHEDOP_remote_shutdown;
    hypercall.arg[1] = (unsigned long)&arg;
    arg.domain_id = domid;
    arg.reason = reason;

    if ( lock_pages(&arg, sizeof(arg)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    ret = do_xen_hypercall(xc_handle, &hypercall);

    unlock_pages(&arg, sizeof(arg));

 out1:
    return ret;
}


int xc_vcpu_setaffinity(int xc_handle,
                        uint32_t domid,
                        int vcpu,
                        uint64_t cpumap)
{
    DECLARE_DOMCTL;
    int ret = -1;
    uint8_t local[sizeof (cpumap)];

    domctl.cmd = XEN_DOMCTL_setvcpuaffinity;
    domctl.domain = (domid_t)domid;
    domctl.u.vcpuaffinity.vcpu    = vcpu;

    bitmap_64_to_byte(local, &cpumap, sizeof(cpumap) * 8);

    set_xen_guest_handle(domctl.u.vcpuaffinity.cpumap.bitmap, local);

    domctl.u.vcpuaffinity.cpumap.nr_cpus = sizeof(cpumap) * 8;
    
    if ( lock_pages(local, sizeof(local)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out;
    }

    ret = do_domctl(xc_handle, &domctl);

    unlock_pages(local, sizeof(local));

 out:
    return ret;
}


int xc_vcpu_getaffinity(int xc_handle,
                        uint32_t domid,
                        int vcpu,
                        uint64_t *cpumap)
{
    DECLARE_DOMCTL;
    int ret = -1;
    uint8_t local[sizeof (cpumap)];

    domctl.cmd = XEN_DOMCTL_getvcpuaffinity;
    domctl.domain = (domid_t)domid;
    domctl.u.vcpuaffinity.vcpu = vcpu;

    set_xen_guest_handle(domctl.u.vcpuaffinity.cpumap.bitmap, local);
    domctl.u.vcpuaffinity.cpumap.nr_cpus = sizeof(cpumap) * 8;
    
    if ( lock_pages(local, sizeof(local)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out;
    }

    ret = do_domctl(xc_handle, &domctl);

    unlock_pages(local, sizeof (local));
    bitmap_byte_to_64(cpumap, local, sizeof(local) * 8);
 out:
    return ret;
}


int xc_domain_getinfo(int xc_handle,
                      uint32_t first_domid,
                      unsigned int max_doms,
                      xc_dominfo_t *info)
{
    unsigned int nr_doms;
    uint32_t next_domid = first_domid;
    DECLARE_DOMCTL;
    int rc = 0;

    memset(info, 0, max_doms*sizeof(xc_dominfo_t));

    for ( nr_doms = 0; nr_doms < max_doms; nr_doms++ )
    {
        domctl.cmd = XEN_DOMCTL_getdomaininfo;
        domctl.domain = (domid_t)next_domid;
        if ( (rc = do_domctl(xc_handle, &domctl)) < 0 )
            break;
        info->domid      = (uint16_t)domctl.domain;

        info->dying    = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_dying);
        info->shutdown = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_shutdown);
        info->paused   = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_paused);
        info->blocked  = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_blocked);
        info->running  = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_running);
        info->hvm      = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_hvm_guest);

        info->shutdown_reason =
            (domctl.u.getdomaininfo.flags>>XEN_DOMINF_shutdownshift) &
            XEN_DOMINF_shutdownmask;

        if ( info->shutdown && (info->shutdown_reason == SHUTDOWN_crash) )
        {
            info->shutdown = 0;
            info->crashed  = 1;
        }

        info->ssidref  = domctl.u.getdomaininfo.ssidref;
        info->nr_pages = domctl.u.getdomaininfo.tot_pages;
        info->max_memkb = domctl.u.getdomaininfo.max_pages << (PAGE_SHIFT-10);
        info->shared_info_frame = domctl.u.getdomaininfo.shared_info_frame;
        info->cpu_time = domctl.u.getdomaininfo.cpu_time;
        info->nr_online_vcpus = domctl.u.getdomaininfo.nr_online_vcpus;
        info->max_vcpu_id = domctl.u.getdomaininfo.max_vcpu_id;

        memcpy(info->handle, domctl.u.getdomaininfo.handle,
               sizeof(xen_domain_handle_t));

        next_domid = (uint16_t)domctl.domain + 1;
        info++;
    }

    if ( nr_doms == 0 )
        return rc;

    return nr_doms;
}

int xc_domain_getinfolist(int xc_handle,
                          uint32_t first_domain,
                          unsigned int max_domains,
                          xc_domaininfo_t *info)
{
    int ret = 0;
    DECLARE_SYSCTL;

    if ( lock_pages(info, max_domains*sizeof(xc_domaininfo_t)) != 0 )
        return -1;

    sysctl.cmd = XEN_SYSCTL_getdomaininfolist;
    sysctl.u.getdomaininfolist.first_domain = first_domain;
    sysctl.u.getdomaininfolist.max_domains  = max_domains;
    set_xen_guest_handle(sysctl.u.getdomaininfolist.buffer, info);

    if ( xc_sysctl(xc_handle, &sysctl) < 0 )
        ret = -1;
    else
        ret = sysctl.u.getdomaininfolist.num_domains;

    unlock_pages(info, max_domains*sizeof(xc_domaininfo_t));

    return ret;
}

/* get info from hvm guest for save */
int xc_domain_hvm_getcontext(int xc_handle,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size)
{
    int ret;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_gethvmcontext;
    domctl.domain = (domid_t)domid;
    domctl.u.hvmcontext.size = size;
    set_xen_guest_handle(domctl.u.hvmcontext.buffer, ctxt_buf);

    if ( ctxt_buf ) 
        if ( (ret = lock_pages(ctxt_buf, size)) != 0 )
            return ret;

    ret = do_domctl(xc_handle, &domctl);

    if ( ctxt_buf ) 
        unlock_pages(ctxt_buf, size);

    return (ret < 0 ? -1 : domctl.u.hvmcontext.size);
}

/* set info to hvm guest for restore */
int xc_domain_hvm_setcontext(int xc_handle,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size)
{
    int ret;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_sethvmcontext;
    domctl.domain = domid;
    domctl.u.hvmcontext.size = size;
    set_xen_guest_handle(domctl.u.hvmcontext.buffer, ctxt_buf);

    if ( (ret = lock_pages(ctxt_buf, size)) != 0 )
        return ret;

    ret = do_domctl(xc_handle, &domctl);

    unlock_pages(ctxt_buf, size);

    return ret;
}

int xc_vcpu_getcontext(int xc_handle,
                       uint32_t domid,
                       uint32_t vcpu,
                       vcpu_guest_context_t *ctxt)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_getvcpucontext;
    domctl.domain = (domid_t)domid;
    domctl.u.vcpucontext.vcpu   = (uint16_t)vcpu;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

    if ( (rc = lock_pages(ctxt, sizeof(*ctxt))) != 0 )
        return rc;

    rc = do_domctl(xc_handle, &domctl);

    unlock_pages(ctxt, sizeof(*ctxt));

    return rc;
}


int xc_shadow_control(int xc_handle,
                      uint32_t domid,
                      unsigned int sop,
                      unsigned long *dirty_bitmap,
                      unsigned long pages,
                      unsigned long *mb,
                      uint32_t mode,
                      xc_shadow_op_stats_t *stats)
{
    int rc;
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_shadow_op;
    domctl.domain = (domid_t)domid;
    domctl.u.shadow_op.op     = sop;
    domctl.u.shadow_op.pages  = pages;
    domctl.u.shadow_op.mb     = mb ? *mb : 0;
    domctl.u.shadow_op.mode   = mode;
    set_xen_guest_handle(domctl.u.shadow_op.dirty_bitmap,
                         (uint8_t *)dirty_bitmap);

    rc = do_domctl(xc_handle, &domctl);

    if ( stats )
        memcpy(stats, &domctl.u.shadow_op.stats,
               sizeof(xc_shadow_op_stats_t));
    
    if ( mb ) 
        *mb = domctl.u.shadow_op.mb;

    return (rc == 0) ? domctl.u.shadow_op.pages : rc;
}

int xc_domain_setcpuweight(int xc_handle,
                           uint32_t domid,
                           float weight)
{
    int sched_id;
    int ret;

    /* Figure out which scheduler is currently used: */
    if ( (ret = xc_sched_id(xc_handle, &sched_id)) != 0 )
        return ret;

    /* No-op. */
    return 0;
}

int xc_domain_setmaxmem(int xc_handle,
                        uint32_t domid,
                        unsigned int max_memkb)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_max_mem;
    domctl.domain = (domid_t)domid;
    domctl.u.max_mem.max_memkb = max_memkb;
    return do_domctl(xc_handle, &domctl);
}

#if defined(__i386__) || defined(__x86_64__)
#include <xen/hvm/e820.h>
int xc_domain_set_memmap_limit(int xc_handle,
                               uint32_t domid,
                               unsigned long map_limitkb)
{
    int rc;

    struct xen_foreign_memory_map fmap = {
        .domid = domid,
        .map = { .nr_entries = 1 }
    };

    struct e820entry e820 = {
        .addr = 0,
        .size = (uint64_t)map_limitkb << 10,
        .type = E820_RAM
    };

    set_xen_guest_handle(fmap.map.buffer, &e820);

    if ( lock_pages(&fmap, sizeof(fmap)) || lock_pages(&e820, sizeof(e820)) )
    {
        PERROR("Could not lock memory for Xen hypercall");
        rc = -1;
        goto out;
    }

    rc = xc_memory_op(xc_handle, XENMEM_set_memory_map, &fmap);

 out:
    unlock_pages(&fmap, sizeof(fmap));
    unlock_pages(&e820, sizeof(e820));
    return rc;
}
#else
int xc_domain_set_memmap_limit(int xc_handle,
                               uint32_t domid,
                               unsigned long map_limitkb)
{
    PERROR("Function not implemented");
    errno = ENOSYS;
    return -1;
}
#endif

int xc_domain_set_time_offset(int xc_handle,
                              uint32_t domid,
                              int32_t time_offset_seconds)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_settimeoffset;
    domctl.domain = (domid_t)domid;
    domctl.u.settimeoffset.time_offset_seconds = time_offset_seconds;
    return do_domctl(xc_handle, &domctl);
}

int xc_domain_memory_increase_reservation(int xc_handle,
                                          uint32_t domid,
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
                                          unsigned int address_bits,
                                          xen_pfn_t *extent_start)
{
    int err;
    struct xen_memory_reservation reservation = {
        .nr_extents   = nr_extents,
        .extent_order = extent_order,
        .address_bits = address_bits,
        .domid        = domid
    };

    /* may be NULL */
    set_xen_guest_handle(reservation.extent_start, extent_start);

    err = xc_memory_op(xc_handle, XENMEM_increase_reservation, &reservation);
    if ( err == nr_extents )
        return 0;

    if ( err >= 0 )
    {
        DPRINTF("Failed allocation for dom %d: "
                "%ld extents of order %d, addr_bits %d\n",
                domid, nr_extents, extent_order, address_bits);
        errno = ENOMEM;
        err = -1;
    }

    return err;
}

int xc_domain_memory_decrease_reservation(int xc_handle,
                                          uint32_t domid,
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
                                          xen_pfn_t *extent_start)
{
    int err;
    struct xen_memory_reservation reservation = {
        .nr_extents   = nr_extents,
        .extent_order = extent_order,
        .address_bits = 0,
        .domid        = domid
    };

    set_xen_guest_handle(reservation.extent_start, extent_start);

    if ( extent_start == NULL )
    {
        DPRINTF("decrease_reservation extent_start is NULL!\n");
        errno = EINVAL;
        return -1;
    }

    err = xc_memory_op(xc_handle, XENMEM_decrease_reservation, &reservation);
    if ( err == nr_extents )
        return 0;

    if ( err >= 0 )
    {
        DPRINTF("Failed deallocation for dom %d: %ld extents of order %d\n",
                domid, nr_extents, extent_order);
        errno = EINVAL;
        err = -1;
    }

    return err;
}

int xc_domain_memory_populate_physmap(int xc_handle,
                                          uint32_t domid,
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
                                          unsigned int address_bits,
                                          xen_pfn_t *extent_start)
{
    int err;
    struct xen_memory_reservation reservation = {
        .nr_extents   = nr_extents,
        .extent_order = extent_order,
        .address_bits = address_bits,
        .domid        = domid
    };
    set_xen_guest_handle(reservation.extent_start, extent_start);

    err = xc_memory_op(xc_handle, XENMEM_populate_physmap, &reservation);
    if ( err == nr_extents )
        return 0;

    if ( err >= 0 )
    {
        DPRINTF("Failed allocation for dom %d: %ld extents of order %d\n",
                domid, nr_extents, extent_order);
        errno = EBUSY;
        err = -1;
    }

    return err;
}

int xc_domain_max_vcpus(int xc_handle, uint32_t domid, unsigned int max)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_max_vcpus;
    domctl.domain = (domid_t)domid;
    domctl.u.max_vcpus.max    = max;
    return do_domctl(xc_handle, &domctl);
}

int xc_domain_sethandle(int xc_handle, uint32_t domid,
                        xen_domain_handle_t handle)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_setdomainhandle;
    domctl.domain = (domid_t)domid;
    memcpy(domctl.u.setdomainhandle.handle, handle,
           sizeof(xen_domain_handle_t));
    return do_domctl(xc_handle, &domctl);
}

int xc_vcpu_getinfo(int xc_handle,
                    uint32_t domid,
                    uint32_t vcpu,
                    xc_vcpuinfo_t *info)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_getvcpuinfo;
    domctl.domain = (domid_t)domid;
    domctl.u.getvcpuinfo.vcpu   = (uint16_t)vcpu;

    rc = do_domctl(xc_handle, &domctl);

    memcpy(info, &domctl.u.getvcpuinfo, sizeof(*info));

    return rc;
}

int xc_domain_ioport_permission(int xc_handle,
                                uint32_t domid,
                                uint32_t first_port,
                                uint32_t nr_ports,
                                uint32_t allow_access)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_ioport_permission;
    domctl.domain = (domid_t)domid;
    domctl.u.ioport_permission.first_port = first_port;
    domctl.u.ioport_permission.nr_ports = nr_ports;
    domctl.u.ioport_permission.allow_access = allow_access;

    return do_domctl(xc_handle, &domctl);
}

int xc_vcpu_setcontext(int xc_handle,
                       uint32_t domid,
                       uint32_t vcpu,
                       vcpu_guest_context_t *ctxt)
{
    DECLARE_DOMCTL;
    int rc;

    domctl.cmd = XEN_DOMCTL_setvcpucontext;
    domctl.domain = domid;
    domctl.u.vcpucontext.vcpu = vcpu;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

    if ( (ctxt != NULL) && ((rc = lock_pages(ctxt, sizeof(*ctxt))) != 0) )
        return rc;

    rc = do_domctl(xc_handle, &domctl);

    if ( ctxt != NULL )
        unlock_pages(ctxt, sizeof(*ctxt));

    return rc;
}

int xc_domain_irq_permission(int xc_handle,
                             uint32_t domid,
                             uint8_t pirq,
                             uint8_t allow_access)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_irq_permission;
    domctl.domain = domid;
    domctl.u.irq_permission.pirq = pirq;
    domctl.u.irq_permission.allow_access = allow_access;

    return do_domctl(xc_handle, &domctl);
}

int xc_domain_iomem_permission(int xc_handle,
                               uint32_t domid,
                               unsigned long first_mfn,
                               unsigned long nr_mfns,
                               uint8_t allow_access)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_iomem_permission;
    domctl.domain = domid;
    domctl.u.iomem_permission.first_mfn = first_mfn;
    domctl.u.iomem_permission.nr_mfns = nr_mfns;
    domctl.u.iomem_permission.allow_access = allow_access;

    return do_domctl(xc_handle, &domctl);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
