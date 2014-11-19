/******************************************************************************
 * xc_domain.c
 *
 * API for manipulating and obtaining information on domains.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"
#include "xc_core.h"
#include "xg_private.h"
#include "xg_save_restore.h"
#include <xen/memory.h>
#include <xen/hvm/hvm_op.h>

int xc_domain_create(xc_interface *xch,
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
    if ( (err = do_domctl(xch, &domctl)) != 0 )
        return err;

    *pdomid = (uint16_t)domctl.domain;
    return 0;
}

int xc_domain_cacheflush(xc_interface *xch, uint32_t domid,
                         xen_pfn_t start_pfn, xen_pfn_t nr_pfns)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_cacheflush;
    domctl.domain = (domid_t)domid;
    domctl.u.cacheflush.start_pfn = start_pfn;
    domctl.u.cacheflush.nr_pfns = nr_pfns;
    return do_domctl(xch, &domctl);
}

int xc_domain_pause(xc_interface *xch,
                    uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_pausedomain;
    domctl.domain = (domid_t)domid;
    return do_domctl(xch, &domctl);
}


int xc_domain_unpause(xc_interface *xch,
                      uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_unpausedomain;
    domctl.domain = (domid_t)domid;
    return do_domctl(xch, &domctl);
}


int xc_domain_destroy(xc_interface *xch,
                      uint32_t domid)
{
    int ret;
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_destroydomain;
    domctl.domain = (domid_t)domid;
    do {
        ret = do_domctl(xch, &domctl);
    } while ( ret && (errno == EAGAIN) );
    return ret;
}

int xc_domain_shutdown(xc_interface *xch,
                       uint32_t domid,
                       int reason)
{
    int ret = -1;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(sched_remote_shutdown_t, arg);

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_domain_shutdown hypercall");
        goto out1;
    }

    hypercall.op     = __HYPERVISOR_sched_op;
    hypercall.arg[0] = (unsigned long)SCHEDOP_remote_shutdown;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);
    arg->domain_id = domid;
    arg->reason = reason;

    ret = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

 out1:
    return ret;
}


int xc_domain_node_setaffinity(xc_interface *xch,
                               uint32_t domid,
                               xc_nodemap_t nodemap)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(uint8_t, local);
    int ret = -1;
    int nodesize;

    nodesize = xc_get_nodemap_size(xch);
    if (nodesize <= 0)
    {
        PERROR("Could not get number of nodes");
        goto out;
    }

    local = xc_hypercall_buffer_alloc(xch, local, nodesize);
    if ( local == NULL )
    {
        PERROR("Could not allocate memory for setnodeaffinity domctl hypercall");
        goto out;
    }

    domctl.cmd = XEN_DOMCTL_setnodeaffinity;
    domctl.domain = (domid_t)domid;

    memcpy(local, nodemap, nodesize);
    set_xen_guest_handle(domctl.u.nodeaffinity.nodemap.bitmap, local);
    domctl.u.nodeaffinity.nodemap.nr_bits = nodesize * 8;

    ret = do_domctl(xch, &domctl);

    xc_hypercall_buffer_free(xch, local);

 out:
    return ret;
}

int xc_domain_node_getaffinity(xc_interface *xch,
                               uint32_t domid,
                               xc_nodemap_t nodemap)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(uint8_t, local);
    int ret = -1;
    int nodesize;

    nodesize = xc_get_nodemap_size(xch);
    if (nodesize <= 0)
    {
        PERROR("Could not get number of nodes");
        goto out;
    }

    local = xc_hypercall_buffer_alloc(xch, local, nodesize);
    if ( local == NULL )
    {
        PERROR("Could not allocate memory for getnodeaffinity domctl hypercall");
        goto out;
    }

    domctl.cmd = XEN_DOMCTL_getnodeaffinity;
    domctl.domain = (domid_t)domid;

    set_xen_guest_handle(domctl.u.nodeaffinity.nodemap.bitmap, local);
    domctl.u.nodeaffinity.nodemap.nr_bits = nodesize * 8;

    ret = do_domctl(xch, &domctl);

    memcpy(nodemap, local, nodesize);

    xc_hypercall_buffer_free(xch, local);

 out:
    return ret;
}

int xc_vcpu_setaffinity(xc_interface *xch,
                        uint32_t domid,
                        int vcpu,
                        xc_cpumap_t cpumap)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(uint8_t, local);
    int ret = -1;
    int cpusize;

    cpusize = xc_get_cpumap_size(xch);
    if (cpusize <= 0)
    {
        PERROR("Could not get number of cpus");
        goto out;
    }

    local = xc_hypercall_buffer_alloc(xch, local, cpusize);
    if ( local == NULL )
    {
        PERROR("Could not allocate memory for setvcpuaffinity domctl hypercall");
        goto out;
    }

    domctl.cmd = XEN_DOMCTL_setvcpuaffinity;
    domctl.domain = (domid_t)domid;
    domctl.u.vcpuaffinity.vcpu    = vcpu;

    memcpy(local, cpumap, cpusize);

    set_xen_guest_handle(domctl.u.vcpuaffinity.cpumap.bitmap, local);

    domctl.u.vcpuaffinity.cpumap.nr_bits = cpusize * 8;

    ret = do_domctl(xch, &domctl);

    xc_hypercall_buffer_free(xch, local);

 out:
    return ret;
}


int xc_vcpu_getaffinity(xc_interface *xch,
                        uint32_t domid,
                        int vcpu,
                        xc_cpumap_t cpumap)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(uint8_t, local);
    int ret = -1;
    int cpusize;

    cpusize = xc_get_cpumap_size(xch);
    if (cpusize <= 0)
    {
        PERROR("Could not get number of cpus");
        goto out;
    }

    local = xc_hypercall_buffer_alloc(xch, local, cpusize);
    if (local == NULL)
    {
        PERROR("Could not allocate memory for getvcpuaffinity domctl hypercall");
        goto out;
    }

    domctl.cmd = XEN_DOMCTL_getvcpuaffinity;
    domctl.domain = (domid_t)domid;
    domctl.u.vcpuaffinity.vcpu = vcpu;

    set_xen_guest_handle(domctl.u.vcpuaffinity.cpumap.bitmap, local);
    domctl.u.vcpuaffinity.cpumap.nr_bits = cpusize * 8;

    ret = do_domctl(xch, &domctl);

    memcpy(cpumap, local, cpusize);

    xc_hypercall_buffer_free(xch, local);
out:
    return ret;
}

int xc_domain_get_guest_width(xc_interface *xch, uint32_t domid,
                              unsigned int *guest_width)
{
    DECLARE_DOMCTL;

    memset(&domctl, 0, sizeof(domctl));
    domctl.domain = domid;
    domctl.cmd = XEN_DOMCTL_get_address_size;

    if ( do_domctl(xch, &domctl) != 0 )
        return 1;

    /* We want the result in bytes */
    *guest_width = domctl.u.address_size.size / 8;
    return 0;
}

int xc_domain_getinfo(xc_interface *xch,
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
        if ( (rc = do_domctl(xch, &domctl)) < 0 )
            break;
        info->domid      = (uint16_t)domctl.domain;

        info->dying    = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_dying);
        info->shutdown = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_shutdown);
        info->paused   = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_paused);
        info->blocked  = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_blocked);
        info->running  = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_running);
        info->hvm      = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_hvm_guest);
        info->debugged = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_debugged);

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
        info->nr_outstanding_pages = domctl.u.getdomaininfo.outstanding_pages;
        info->nr_shared_pages = domctl.u.getdomaininfo.shr_pages;
        info->nr_paged_pages = domctl.u.getdomaininfo.paged_pages;
        info->max_memkb = domctl.u.getdomaininfo.max_pages << (PAGE_SHIFT-10);
        info->shared_info_frame = domctl.u.getdomaininfo.shared_info_frame;
        info->cpu_time = domctl.u.getdomaininfo.cpu_time;
        info->nr_online_vcpus = domctl.u.getdomaininfo.nr_online_vcpus;
        info->max_vcpu_id = domctl.u.getdomaininfo.max_vcpu_id;
        info->cpupool = domctl.u.getdomaininfo.cpupool;

        memcpy(info->handle, domctl.u.getdomaininfo.handle,
               sizeof(xen_domain_handle_t));

        next_domid = (uint16_t)domctl.domain + 1;
        info++;
    }

    if ( nr_doms == 0 )
        return rc;

    return nr_doms;
}

int xc_domain_getinfolist(xc_interface *xch,
                          uint32_t first_domain,
                          unsigned int max_domains,
                          xc_domaininfo_t *info)
{
    int ret = 0;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(info, max_domains*sizeof(*info), XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, info) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_getdomaininfolist;
    sysctl.u.getdomaininfolist.first_domain = first_domain;
    sysctl.u.getdomaininfolist.max_domains  = max_domains;
    set_xen_guest_handle(sysctl.u.getdomaininfolist.buffer, info);

    if ( xc_sysctl(xch, &sysctl) < 0 )
        ret = -1;
    else
        ret = sysctl.u.getdomaininfolist.num_domains;

    xc_hypercall_bounce_post(xch, info);

    return ret;
}

/* set broken page p2m */
int xc_set_broken_page_p2m(xc_interface *xch,
                           uint32_t domid,
                           unsigned long pfn)
{
    int ret;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_set_broken_page_p2m;
    domctl.domain = (domid_t)domid;
    domctl.u.set_broken_page_p2m.pfn = pfn;
    ret = do_domctl(xch, &domctl);

    return ret ? -1 : 0;
}

/* get info from hvm guest for save */
int xc_domain_hvm_getcontext(xc_interface *xch,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size)
{
    int ret;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt_buf, size, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, ctxt_buf) )
        return -1;

    domctl.cmd = XEN_DOMCTL_gethvmcontext;
    domctl.domain = (domid_t)domid;
    domctl.u.hvmcontext.size = size;
    set_xen_guest_handle(domctl.u.hvmcontext.buffer, ctxt_buf);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, ctxt_buf);

    return (ret < 0 ? -1 : domctl.u.hvmcontext.size);
}

/* Get just one element of the HVM guest context.
 * size must be >= HVM_SAVE_LENGTH(type) */
int xc_domain_hvm_getcontext_partial(xc_interface *xch,
                                     uint32_t domid,
                                     uint16_t typecode,
                                     uint16_t instance,
                                     void *ctxt_buf,
                                     uint32_t size)
{
    int ret;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt_buf, size, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( !ctxt_buf || xc_hypercall_bounce_pre(xch, ctxt_buf) )
        return -1;

    domctl.cmd = XEN_DOMCTL_gethvmcontext_partial;
    domctl.domain = (domid_t) domid;
    domctl.u.hvmcontext_partial.type = typecode;
    domctl.u.hvmcontext_partial.instance = instance;
    set_xen_guest_handle(domctl.u.hvmcontext_partial.buffer, ctxt_buf);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, ctxt_buf);

    return ret ? -1 : 0;
}

/* set info to hvm guest for restore */
int xc_domain_hvm_setcontext(xc_interface *xch,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size)
{
    int ret;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt_buf, size, XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, ctxt_buf) )
        return -1;

    domctl.cmd = XEN_DOMCTL_sethvmcontext;
    domctl.domain = domid;
    domctl.u.hvmcontext.size = size;
    set_xen_guest_handle(domctl.u.hvmcontext.buffer, ctxt_buf);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, ctxt_buf);

    return ret;
}

int xc_vcpu_getcontext(xc_interface *xch,
                       uint32_t domid,
                       uint32_t vcpu,
                       vcpu_guest_context_any_t *ctxt)
{
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt, sizeof(vcpu_guest_context_any_t), XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, ctxt) )
        return -1;

    domctl.cmd = XEN_DOMCTL_getvcpucontext;
    domctl.domain = (domid_t)domid;
    domctl.u.vcpucontext.vcpu   = (uint16_t)vcpu;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

    rc = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, ctxt);

    return rc;
}

int xc_watchdog(xc_interface *xch,
                uint32_t id,
                uint32_t timeout)
{
    int ret = -1;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(sched_watchdog_t, arg);

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_watchdog hypercall");
        goto out1;
    }

    hypercall.op     = __HYPERVISOR_sched_op;
    hypercall.arg[0] = (unsigned long)SCHEDOP_watchdog;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);
    arg->id = id;
    arg->timeout = timeout;

    ret = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

 out1:
    return ret;
}


int xc_shadow_control(xc_interface *xch,
                      uint32_t domid,
                      unsigned int sop,
                      xc_hypercall_buffer_t *dirty_bitmap,
                      unsigned long pages,
                      unsigned long *mb,
                      uint32_t mode,
                      xc_shadow_op_stats_t *stats)
{
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(dirty_bitmap);

    memset(&domctl, 0, sizeof(domctl));

    domctl.cmd = XEN_DOMCTL_shadow_op;
    domctl.domain = (domid_t)domid;
    domctl.u.shadow_op.op     = sop;
    domctl.u.shadow_op.pages  = pages;
    domctl.u.shadow_op.mb     = mb ? *mb : 0;
    domctl.u.shadow_op.mode   = mode;
    if (dirty_bitmap != NULL)
        set_xen_guest_handle(domctl.u.shadow_op.dirty_bitmap,
                                dirty_bitmap);

    rc = do_domctl(xch, &domctl);

    if ( stats )
        memcpy(stats, &domctl.u.shadow_op.stats,
               sizeof(xc_shadow_op_stats_t));
    
    if ( mb ) 
        *mb = domctl.u.shadow_op.mb;

    return (rc == 0) ? domctl.u.shadow_op.pages : rc;
}

int xc_domain_setmaxmem(xc_interface *xch,
                        uint32_t domid,
                        unsigned int max_memkb)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_max_mem;
    domctl.domain = (domid_t)domid;
    domctl.u.max_mem.max_memkb = max_memkb;
    return do_domctl(xch, &domctl);
}

int xc_domain_pin_memory_cacheattr(xc_interface *xch,
                                   uint32_t domid,
                                   uint64_t start,
                                   uint64_t end,
                                   uint32_t type)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_pin_mem_cacheattr;
    domctl.domain = (domid_t)domid;
    domctl.u.pin_mem_cacheattr.start = start;
    domctl.u.pin_mem_cacheattr.end = end;
    domctl.u.pin_mem_cacheattr.type = type;
    return do_domctl(xch, &domctl);
}

#if defined(__i386__) || defined(__x86_64__)
int xc_domain_set_memory_map(xc_interface *xch,
                               uint32_t domid,
                               struct e820entry entries[],
                               uint32_t nr_entries)
{
    int rc;
    struct xen_foreign_memory_map fmap = {
        .domid = domid,
        .map = { .nr_entries = nr_entries }
    };
    DECLARE_HYPERCALL_BOUNCE(entries, nr_entries * sizeof(struct e820entry),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( !entries || xc_hypercall_bounce_pre(xch, entries) )
        return -1;

    set_xen_guest_handle(fmap.map.buffer, entries);

    rc = do_memory_op(xch, XENMEM_set_memory_map, &fmap, sizeof(fmap));

    xc_hypercall_bounce_post(xch, entries);

    return rc;
}
int xc_get_machine_memory_map(xc_interface *xch,
                              struct e820entry entries[],
                              uint32_t max_entries)
{
    int rc;
    struct xen_memory_map memmap = {
        .nr_entries = max_entries
    };
    DECLARE_HYPERCALL_BOUNCE(entries, sizeof(struct e820entry) * max_entries,
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( !entries || xc_hypercall_bounce_pre(xch, entries) || max_entries <= 1)
        return -1;


    set_xen_guest_handle(memmap.buffer, entries);

    rc = do_memory_op(xch, XENMEM_machine_memory_map, &memmap, sizeof(memmap));

    xc_hypercall_bounce_post(xch, entries);

    return rc ? rc : memmap.nr_entries;
}
int xc_domain_set_memmap_limit(xc_interface *xch,
                               uint32_t domid,
                               unsigned long map_limitkb)
{
    struct e820entry e820;

    e820.addr = 0;
    e820.size = (uint64_t)map_limitkb << 10;
    e820.type = E820_RAM;

    return xc_domain_set_memory_map(xch, domid, &e820, 1);
}
#else
int xc_domain_set_memmap_limit(xc_interface *xch,
                               uint32_t domid,
                               unsigned long map_limitkb)
{
    PERROR("Function not implemented");
    errno = ENOSYS;
    return -1;
}
#endif

int xc_domain_set_time_offset(xc_interface *xch,
                              uint32_t domid,
                              int32_t time_offset_seconds)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_settimeoffset;
    domctl.domain = (domid_t)domid;
    domctl.u.settimeoffset.time_offset_seconds = time_offset_seconds;
    return do_domctl(xch, &domctl);
}

int xc_domain_disable_migrate(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_disable_migrate;
    domctl.domain = (domid_t)domid;
    domctl.u.disable_migrate.disable = 1;
    return do_domctl(xch, &domctl);
}

int xc_domain_set_tsc_info(xc_interface *xch,
                           uint32_t domid,
                           uint32_t tsc_mode,
                           uint64_t elapsed_nsec,
                           uint32_t gtsc_khz,
                           uint32_t incarnation)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_settscinfo;
    domctl.domain = (domid_t)domid;
    domctl.u.tsc_info.info.tsc_mode = tsc_mode;
    domctl.u.tsc_info.info.elapsed_nsec = elapsed_nsec;
    domctl.u.tsc_info.info.gtsc_khz = gtsc_khz;
    domctl.u.tsc_info.info.incarnation = incarnation;
    return do_domctl(xch, &domctl);
}

int xc_domain_get_tsc_info(xc_interface *xch,
                           uint32_t domid,
                           uint32_t *tsc_mode,
                           uint64_t *elapsed_nsec,
                           uint32_t *gtsc_khz,
                           uint32_t *incarnation)
{
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(xen_guest_tsc_info_t, info);

    info = xc_hypercall_buffer_alloc(xch, info, sizeof(*info));
    if ( info == NULL )
        return -ENOMEM;

    domctl.cmd = XEN_DOMCTL_gettscinfo;
    domctl.domain = (domid_t)domid;
    set_xen_guest_handle(domctl.u.tsc_info.out_info, info);
    rc = do_domctl(xch, &domctl);
    if ( rc == 0 )
    {
        *tsc_mode = info->tsc_mode;
        *elapsed_nsec = info->elapsed_nsec;
        *gtsc_khz = info->gtsc_khz;
        *incarnation = info->incarnation;
    }
    xc_hypercall_buffer_free(xch, info);
    return rc;
}


int xc_domain_maximum_gpfn(xc_interface *xch, domid_t domid)
{
    return do_memory_op(xch, XENMEM_maximum_gpfn, &domid, sizeof(domid));
}

int xc_domain_increase_reservation(xc_interface *xch,
                                   uint32_t domid,
                                   unsigned long nr_extents,
                                   unsigned int extent_order,
                                   unsigned int mem_flags,
                                   xen_pfn_t *extent_start)
{
    int err;
    DECLARE_HYPERCALL_BOUNCE(extent_start, nr_extents * sizeof(*extent_start), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    struct xen_memory_reservation reservation = {
        .nr_extents   = nr_extents,
        .extent_order = extent_order,
        .mem_flags    = mem_flags,
        .domid        = domid
    };

    /* may be NULL */
    if ( xc_hypercall_bounce_pre(xch, extent_start) )
    {
        PERROR("Could not bounce memory for XENMEM_increase_reservation hypercall");
        return -1;
    }

    set_xen_guest_handle(reservation.extent_start, extent_start);

    err = do_memory_op(xch, XENMEM_increase_reservation, &reservation, sizeof(reservation));

    xc_hypercall_bounce_post(xch, extent_start);

    return err;
}

int xc_domain_increase_reservation_exact(xc_interface *xch,
                                         uint32_t domid,
                                         unsigned long nr_extents,
                                         unsigned int extent_order,
                                         unsigned int mem_flags,
                                         xen_pfn_t *extent_start)
{
    int err;

    err = xc_domain_increase_reservation(xch, domid, nr_extents,
                                         extent_order, mem_flags, extent_start);

    if ( err == nr_extents )
        return 0;

    if ( err >= 0 )
    {
        DPRINTF("Failed allocation for dom %d: "
                "%ld extents of order %d, mem_flags %x\n",
                domid, nr_extents, extent_order, mem_flags);
        errno = ENOMEM;
        err = -1;
    }

    return err;
}

int xc_domain_decrease_reservation(xc_interface *xch,
                                   uint32_t domid,
                                   unsigned long nr_extents,
                                   unsigned int extent_order,
                                   xen_pfn_t *extent_start)
{
    int err;
    DECLARE_HYPERCALL_BOUNCE(extent_start, nr_extents * sizeof(*extent_start), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    struct xen_memory_reservation reservation = {
        .nr_extents   = nr_extents,
        .extent_order = extent_order,
        .mem_flags    = 0,
        .domid        = domid
    };

    if ( extent_start == NULL )
    {
        DPRINTF("decrease_reservation extent_start is NULL!\n");
        errno = EINVAL;
        return -1;
    }

    if ( xc_hypercall_bounce_pre(xch, extent_start) )
    {
        PERROR("Could not bounce memory for XENMEM_decrease_reservation hypercall");
        return -1;
    }
    set_xen_guest_handle(reservation.extent_start, extent_start);

    err = do_memory_op(xch, XENMEM_decrease_reservation, &reservation, sizeof(reservation));

    xc_hypercall_bounce_post(xch, extent_start);

    return err;
}

int xc_domain_decrease_reservation_exact(xc_interface *xch,
                                         uint32_t domid,
                                         unsigned long nr_extents,
                                         unsigned int extent_order,
                                         xen_pfn_t *extent_start)
{
    int err;

    err = xc_domain_decrease_reservation(xch, domid, nr_extents,
                                         extent_order, extent_start);

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

int xc_domain_add_to_physmap(xc_interface *xch,
                             uint32_t domid,
                             unsigned int space,
                             unsigned long idx,
                             xen_pfn_t gpfn)
{
    struct xen_add_to_physmap xatp = {
        .domid = domid,
        .space = space,
        .idx = idx,
        .gpfn = gpfn,
    };
    return do_memory_op(xch, XENMEM_add_to_physmap, &xatp, sizeof(xatp));
}

int xc_domain_claim_pages(xc_interface *xch,
                               uint32_t domid,
                               unsigned long nr_pages)
{
    int err;
    struct xen_memory_reservation reservation = {
        .nr_extents   = nr_pages,
        .extent_order = 0,
        .mem_flags    = 0, /* no flags */
        .domid        = domid
    };

    set_xen_guest_handle(reservation.extent_start, HYPERCALL_BUFFER_NULL);

    err = do_memory_op(xch, XENMEM_claim_pages, &reservation, sizeof(reservation));
    /* Ignore it if the hypervisor does not support the call. */
    if (err == -1 && errno == ENOSYS)
        err = errno = 0;
    return err;
}

int xc_domain_populate_physmap(xc_interface *xch,
                               uint32_t domid,
                               unsigned long nr_extents,
                               unsigned int extent_order,
                               unsigned int mem_flags,
                               xen_pfn_t *extent_start)
{
    int err;
    DECLARE_HYPERCALL_BOUNCE(extent_start, nr_extents * sizeof(*extent_start), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    struct xen_memory_reservation reservation = {
        .nr_extents   = nr_extents,
        .extent_order = extent_order,
        .mem_flags    = mem_flags,
        .domid        = domid
    };

    if ( xc_hypercall_bounce_pre(xch, extent_start) )
    {
        PERROR("Could not bounce memory for XENMEM_populate_physmap hypercall");
        return -1;
    }
    set_xen_guest_handle(reservation.extent_start, extent_start);

    err = do_memory_op(xch, XENMEM_populate_physmap, &reservation, sizeof(reservation));

    xc_hypercall_bounce_post(xch, extent_start);
    return err;
}

int xc_domain_populate_physmap_exact(xc_interface *xch,
                                     uint32_t domid,
                                     unsigned long nr_extents,
                                     unsigned int extent_order,
                                     unsigned int mem_flags,
                                     xen_pfn_t *extent_start)
{
    int err;

    err = xc_domain_populate_physmap(xch, domid, nr_extents,
                                     extent_order, mem_flags, extent_start);
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

int xc_domain_memory_exchange_pages(xc_interface *xch,
                                    int domid,
                                    unsigned long nr_in_extents,
                                    unsigned int in_order,
                                    xen_pfn_t *in_extents,
                                    unsigned long nr_out_extents,
                                    unsigned int out_order,
                                    xen_pfn_t *out_extents)
{
    int rc = -1;
    DECLARE_HYPERCALL_BOUNCE(in_extents, nr_in_extents*sizeof(*in_extents), XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(out_extents, nr_out_extents*sizeof(*out_extents), XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    struct xen_memory_exchange exchange = {
        .in = {
            .nr_extents   = nr_in_extents,
            .extent_order = in_order,
            .domid        = domid
        },
        .out = {
            .nr_extents   = nr_out_extents,
            .extent_order = out_order,
            .domid        = domid
        }
    };

    if ( xc_hypercall_bounce_pre(xch, in_extents) ||
         xc_hypercall_bounce_pre(xch, out_extents))
        goto out;

    set_xen_guest_handle(exchange.in.extent_start, in_extents);
    set_xen_guest_handle(exchange.out.extent_start, out_extents);

    rc = do_memory_op(xch, XENMEM_exchange, &exchange, sizeof(exchange));

out:
    xc_hypercall_bounce_post(xch, in_extents);
    xc_hypercall_bounce_post(xch, out_extents);

    return rc;
}

/* Currently only implemented on x86. This cannot be handled in the
 * caller, e.g. by looking for errno==ENOSYS because of the broken
 * error reporting style. Once this is fixed then this condition can
 * be removed.
 */
#if defined(__i386__)||defined(__x86_64__)
static int xc_domain_pod_target(xc_interface *xch,
                                int op,
                                uint32_t domid,
                                uint64_t target_pages,
                                uint64_t *tot_pages,
                                uint64_t *pod_cache_pages,
                                uint64_t *pod_entries)
{
    int err;

    struct xen_pod_target pod_target = {
        .domid = domid,
        .target_pages = target_pages
    };

    err = do_memory_op(xch, op, &pod_target, sizeof(pod_target));

    if ( err < 0 )
    {
        DPRINTF("Failed %s_pod_target dom %d\n",
                (op==XENMEM_set_pod_target)?"set":"get",
                domid);
        errno = -err;
        err = -1;
    }
    else
        err = 0;

    if ( tot_pages )
        *tot_pages = pod_target.tot_pages;
    if ( pod_cache_pages )
        *pod_cache_pages = pod_target.pod_cache_pages;
    if ( pod_entries )
        *pod_entries = pod_target.pod_entries;

    return err;
}


int xc_domain_set_pod_target(xc_interface *xch,
                             uint32_t domid,
                             uint64_t target_pages,
                             uint64_t *tot_pages,
                             uint64_t *pod_cache_pages,
                             uint64_t *pod_entries)
{
    return xc_domain_pod_target(xch,
                                XENMEM_set_pod_target,
                                domid,
                                target_pages,
                                tot_pages,
                                pod_cache_pages,
                                pod_entries);
}

int xc_domain_get_pod_target(xc_interface *xch,
                             uint32_t domid,
                             uint64_t *tot_pages,
                             uint64_t *pod_cache_pages,
                             uint64_t *pod_entries)
{
    return xc_domain_pod_target(xch,
                                XENMEM_get_pod_target,
                                domid,
                                -1,
                                tot_pages,
                                pod_cache_pages,
                                pod_entries);
}
#else
int xc_domain_set_pod_target(xc_interface *xch,
                             uint32_t domid,
                             uint64_t target_pages,
                             uint64_t *tot_pages,
                             uint64_t *pod_cache_pages,
                             uint64_t *pod_entries)
{
    return 0;
}
int xc_domain_get_pod_target(xc_interface *xch,
                             uint32_t domid,
                             uint64_t *tot_pages,
                             uint64_t *pod_cache_pages,
                             uint64_t *pod_entries)
{
    /* On x86 (above) xc_domain_pod_target will incorrectly return -1
     * with errno==-1 on error. Do the same for least surprise. */
    errno = -1;
    return -1;
}
#endif

int xc_domain_max_vcpus(xc_interface *xch, uint32_t domid, unsigned int max)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_max_vcpus;
    domctl.domain = (domid_t)domid;
    domctl.u.max_vcpus.max    = max;
    return do_domctl(xch, &domctl);
}

int xc_domain_sethandle(xc_interface *xch, uint32_t domid,
                        xen_domain_handle_t handle)
{
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_setdomainhandle;
    domctl.domain = (domid_t)domid;
    memcpy(domctl.u.setdomainhandle.handle, handle,
           sizeof(xen_domain_handle_t));
    return do_domctl(xch, &domctl);
}

int xc_vcpu_getinfo(xc_interface *xch,
                    uint32_t domid,
                    uint32_t vcpu,
                    xc_vcpuinfo_t *info)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_getvcpuinfo;
    domctl.domain = (domid_t)domid;
    domctl.u.getvcpuinfo.vcpu   = (uint16_t)vcpu;

    rc = do_domctl(xch, &domctl);

    memcpy(info, &domctl.u.getvcpuinfo, sizeof(*info));

    return rc;
}

int xc_domain_ioport_permission(xc_interface *xch,
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

    return do_domctl(xch, &domctl);
}

int xc_availheap(xc_interface *xch,
                 int min_width,
                 int max_width,
                 int node,
                 uint64_t *bytes)
{
    DECLARE_SYSCTL;
    int rc;

    sysctl.cmd = XEN_SYSCTL_availheap;
    sysctl.u.availheap.min_bitwidth = min_width;
    sysctl.u.availheap.max_bitwidth = max_width;
    sysctl.u.availheap.node = node;

    rc = xc_sysctl(xch, &sysctl);

    *bytes = sysctl.u.availheap.avail_bytes;

    return rc;
}

int xc_vcpu_setcontext(xc_interface *xch,
                       uint32_t domid,
                       uint32_t vcpu,
                       vcpu_guest_context_any_t *ctxt)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(ctxt, sizeof(vcpu_guest_context_any_t), XC_HYPERCALL_BUFFER_BOUNCE_IN);
    int rc;

    if ( xc_hypercall_bounce_pre(xch, ctxt) )
        return -1;

    domctl.cmd = XEN_DOMCTL_setvcpucontext;
    domctl.domain = domid;
    domctl.u.vcpucontext.vcpu = vcpu;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

    rc = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, ctxt);

    return rc;
}

int xc_domain_irq_permission(xc_interface *xch,
                             uint32_t domid,
                             uint8_t pirq,
                             uint8_t allow_access)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_irq_permission;
    domctl.domain = domid;
    domctl.u.irq_permission.pirq = pirq;
    domctl.u.irq_permission.allow_access = allow_access;

    return do_domctl(xch, &domctl);
}

int xc_domain_iomem_permission(xc_interface *xch,
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

    return do_domctl(xch, &domctl);
}

int xc_domain_send_trigger(xc_interface *xch,
                           uint32_t domid,
                           uint32_t trigger,
                           uint32_t vcpu)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_sendtrigger;
    domctl.domain = domid;
    domctl.u.sendtrigger.trigger = trigger;
    domctl.u.sendtrigger.vcpu = vcpu;

    return do_domctl(xch, &domctl);
}

int xc_set_hvm_param(xc_interface *handle, domid_t dom, int param, unsigned long value)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_param_t, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_param;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);
    arg->domid = dom;
    arg->index = param;
    arg->value = value;
    rc = do_xen_hypercall(handle, &hypercall);
    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_get_hvm_param(xc_interface *handle, domid_t dom, int param, unsigned long *value)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_hvm_param_t, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(handle, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_get_param;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);
    arg->domid = dom;
    arg->index = param;
    rc = do_xen_hypercall(handle, &hypercall);
    *value = arg->value;
    xc_hypercall_buffer_free(handle, arg);
    return rc;
}

int xc_domain_setdebugging(xc_interface *xch,
                           uint32_t domid,
                           unsigned int enable)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = domid;
    domctl.u.setdebugging.enable = enable;
    return do_domctl(xch, &domctl);
}

int xc_assign_device(
    xc_interface *xch,
    uint32_t domid,
    uint32_t machine_sbdf)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_assign_device;
    domctl.domain = domid;
    domctl.u.assign_device.machine_sbdf = machine_sbdf;

    return do_domctl(xch, &domctl);
}

int xc_get_device_group(
    xc_interface *xch,
    uint32_t domid,
    uint32_t machine_sbdf,
    uint32_t max_sdevs,
    uint32_t *num_sdevs,
    uint32_t *sdev_array)
{
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(sdev_array, max_sdevs * sizeof(*sdev_array), XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, sdev_array) )
    {
        PERROR("Could not bounce buffer for xc_get_device_group");
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_get_device_group;
    domctl.domain = (domid_t)domid;

    domctl.u.get_device_group.machine_sbdf = machine_sbdf;
    domctl.u.get_device_group.max_sdevs = max_sdevs;

    set_xen_guest_handle(domctl.u.get_device_group.sdev_array, sdev_array);

    rc = do_domctl(xch, &domctl);

    *num_sdevs = domctl.u.get_device_group.num_sdevs;

    xc_hypercall_bounce_post(xch, sdev_array);

    return rc;
}

int xc_test_assign_device(
    xc_interface *xch,
    uint32_t domid,
    uint32_t machine_sbdf)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_test_assign_device;
    domctl.domain = domid;
    domctl.u.assign_device.machine_sbdf = machine_sbdf;

    return do_domctl(xch, &domctl);
}

int xc_deassign_device(
    xc_interface *xch,
    uint32_t domid,
    uint32_t machine_sbdf)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_deassign_device;
    domctl.domain = domid;
    domctl.u.assign_device.machine_sbdf = machine_sbdf;
 
    return do_domctl(xch, &domctl);
}

int xc_domain_update_msi_irq(
    xc_interface *xch,
    uint32_t domid,
    uint32_t gvec,
    uint32_t pirq,
    uint32_t gflags,
    uint64_t gtable)
{
    int rc;
    xen_domctl_bind_pt_irq_t *bind;

    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_bind_pt_irq;
    domctl.domain = (domid_t)domid;

    bind = &(domctl.u.bind_pt_irq);
    bind->hvm_domid = domid;
    bind->irq_type = PT_IRQ_TYPE_MSI;
    bind->machine_irq = pirq;
    bind->u.msi.gvec = gvec;
    bind->u.msi.gflags = gflags;
    bind->u.msi.gtable = gtable;

    rc = do_domctl(xch, &domctl);
    return rc;
}

int xc_domain_unbind_msi_irq(
    xc_interface *xch,
    uint32_t domid,
    uint32_t gvec,
    uint32_t pirq,
    uint32_t gflags)
{
    int rc;
    xen_domctl_bind_pt_irq_t *bind;

    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_unbind_pt_irq;
    domctl.domain = (domid_t)domid;

    bind = &(domctl.u.bind_pt_irq);
    bind->hvm_domid = domid;
    bind->irq_type = PT_IRQ_TYPE_MSI;
    bind->machine_irq = pirq;
    bind->u.msi.gvec = gvec;
    bind->u.msi.gflags = gflags;

    rc = do_domctl(xch, &domctl);
    return rc;
}

/* Pass-through: binds machine irq to guests irq */
int xc_domain_bind_pt_irq(
    xc_interface *xch,
    uint32_t domid,
    uint8_t machine_irq,
    uint8_t irq_type,
    uint8_t bus,
    uint8_t device,
    uint8_t intx,
    uint8_t isa_irq)
{
    int rc;
    xen_domctl_bind_pt_irq_t * bind;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_bind_pt_irq;
    domctl.domain = (domid_t)domid;

    bind = &(domctl.u.bind_pt_irq);
    bind->hvm_domid = domid;
    bind->irq_type = irq_type;
    bind->machine_irq = machine_irq;
    if ( irq_type == PT_IRQ_TYPE_PCI ||
         irq_type == PT_IRQ_TYPE_MSI_TRANSLATE )
    {
        bind->u.pci.bus = bus;
        bind->u.pci.device = device;    
        bind->u.pci.intx = intx;
    } 
    else if ( irq_type == PT_IRQ_TYPE_ISA )
        bind->u.isa.isa_irq = isa_irq;
    
    rc = do_domctl(xch, &domctl);
    return rc;
}

int xc_domain_unbind_pt_irq(
    xc_interface *xch,
    uint32_t domid,
    uint8_t machine_irq,
    uint8_t irq_type,
    uint8_t bus,
    uint8_t device,
    uint8_t intx,
    uint8_t isa_irq)
{
    int rc;
    xen_domctl_bind_pt_irq_t * bind;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_unbind_pt_irq;
    domctl.domain = (domid_t)domid;

    bind = &(domctl.u.bind_pt_irq);
    bind->hvm_domid = domid;
    bind->irq_type = irq_type;
    bind->machine_irq = machine_irq;
    bind->u.pci.bus = bus;
    bind->u.pci.device = device;    
    bind->u.pci.intx = intx;
    bind->u.isa.isa_irq = isa_irq;
    
    rc = do_domctl(xch, &domctl);
    return rc;
}

int xc_domain_bind_pt_pci_irq(
    xc_interface *xch,
    uint32_t domid,
    uint8_t machine_irq,
    uint8_t bus,
    uint8_t device,
    uint8_t intx)
{

    return (xc_domain_bind_pt_irq(xch, domid, machine_irq,
                                  PT_IRQ_TYPE_PCI, bus, device, intx, 0));
}

int xc_domain_bind_pt_isa_irq(
    xc_interface *xch,
    uint32_t domid,
    uint8_t machine_irq)
{

    return (xc_domain_bind_pt_irq(xch, domid, machine_irq,
                                  PT_IRQ_TYPE_ISA, 0, 0, 0, machine_irq));
}

int xc_unmap_domain_meminfo(xc_interface *xch, struct xc_domain_meminfo *minfo)
{
    struct domain_info_context _di = { .guest_width = minfo->guest_width };
    struct domain_info_context *dinfo = &_di;

    free(minfo->pfn_type);
    if ( minfo->p2m_table )
        munmap(minfo->p2m_table, P2M_FLL_ENTRIES * PAGE_SIZE);
    minfo->p2m_table = NULL;

    return 0;
}

int xc_map_domain_meminfo(xc_interface *xch, int domid,
                          struct xc_domain_meminfo *minfo)
{
    struct domain_info_context _di;
    struct domain_info_context *dinfo = &_di;

    xc_dominfo_t info;
    shared_info_any_t *live_shinfo;
    xen_capabilities_info_t xen_caps = "";
    int i;

    /* Only be initialized once */
    if ( minfo->pfn_type || minfo->p2m_table )
    {
        errno = EINVAL;
        return -1;
    }

    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 )
    {
        PERROR("Could not get domain info");
        return -1;
    }

    if ( xc_domain_get_guest_width(xch, domid, &minfo->guest_width) )
    {
        PERROR("Could not get domain address size");
        return -1;
    }
    _di.guest_width = minfo->guest_width;

    /* Get page table levels (see get_platform_info() in xg_save_restore.h */
    if ( xc_version(xch, XENVER_capabilities, &xen_caps) )
    {
        PERROR("Could not get Xen capabilities (for page table levels)");
        return -1;
    }
    if ( strstr(xen_caps, "xen-3.0-x86_64") )
        /* Depends on whether it's a compat 32-on-64 guest */
        minfo->pt_levels = ( (minfo->guest_width == 8) ? 4 : 3 );
    else if ( strstr(xen_caps, "xen-3.0-x86_32p") )
        minfo->pt_levels = 3;
    else if ( strstr(xen_caps, "xen-3.0-x86_32") )
        minfo->pt_levels = 2;
    else
    {
        errno = EFAULT;
        return -1;
    }

    /* We need the shared info page for mapping the P2M */
    live_shinfo = xc_map_foreign_range(xch, domid, PAGE_SIZE, PROT_READ,
                                       info.shared_info_frame);
    if ( !live_shinfo )
    {
        PERROR("Could not map the shared info frame (MFN 0x%lx)",
               info.shared_info_frame);
        return -1;
    }

    if ( xc_core_arch_map_p2m_writable(xch, minfo->guest_width, &info,
                                       live_shinfo, &minfo->p2m_table,
                                       &minfo->p2m_size) )
    {
        PERROR("Could not map the P2M table");
        munmap(live_shinfo, PAGE_SIZE);
        return -1;
    }
    munmap(live_shinfo, PAGE_SIZE);
    _di.p2m_size = minfo->p2m_size;

    /* Make space and prepare for getting the PFN types */
    minfo->pfn_type = calloc(sizeof(*minfo->pfn_type), minfo->p2m_size);
    if ( !minfo->pfn_type )
    {
        PERROR("Could not allocate memory for the PFN types");
        goto failed;
    }
    for ( i = 0; i < minfo->p2m_size; i++ )
        minfo->pfn_type[i] = pfn_to_mfn(i, minfo->p2m_table,
                                        minfo->guest_width);

    /* Retrieve PFN types in batches */
    for ( i = 0; i < minfo->p2m_size ; i+=1024 )
    {
        int count = ((minfo->p2m_size - i ) > 1024 ) ?
                        1024: (minfo->p2m_size - i);

        if ( xc_get_pfn_type_batch(xch, domid, count, minfo->pfn_type + i) )
        {
            PERROR("Could not get %d-eth batch of PFN types", (i+1)/1024);
            goto failed;
        }
    }

    return 0;

failed:
    if ( minfo->pfn_type )
    {
        free(minfo->pfn_type);
        minfo->pfn_type = NULL;
    }
    if ( minfo->p2m_table )
    {
        munmap(minfo->p2m_table, P2M_FLL_ENTRIES * PAGE_SIZE);
        minfo->p2m_table = NULL;
    }

    return -1;
}

#ifndef min
#define min(X, Y) ({                             \
            const typeof (X) _x = (X);           \
            const typeof (Y) _y = (Y);           \
            (void) (&_x == &_y);                 \
            (_x < _y) ? _x : _y; })
#endif
int xc_domain_memory_mapping(
    xc_interface *xch,
    uint32_t domid,
    unsigned long first_gfn,
    unsigned long first_mfn,
    unsigned long nr_mfns,
    uint32_t add_mapping)
{
    DECLARE_DOMCTL;
    int ret = 0, err;
    unsigned long done = 0, nr, max_batch_sz;

    if ( !nr_mfns )
        return 0;

    domctl.cmd = XEN_DOMCTL_memory_mapping;
    domctl.domain = domid;
    domctl.u.memory_mapping.add_mapping = add_mapping;
    max_batch_sz = nr_mfns;
    do
    {
        nr = min(nr_mfns - done, max_batch_sz);
        domctl.u.memory_mapping.nr_mfns = nr;
        domctl.u.memory_mapping.first_gfn = first_gfn + done;
        domctl.u.memory_mapping.first_mfn = first_mfn + done;
        err = do_domctl(xch, &domctl);
        if ( err && errno == E2BIG )
        {
            if ( max_batch_sz <= 1 )
                break;
            max_batch_sz >>= 1;
            continue;
        }
        /* Save the first error... */
        if ( !ret )
            ret = err;
        /* .. and ignore the rest of them when removing. */
        if ( err && add_mapping != DPCI_REMOVE_MAPPING )
            break;

        done += nr;
    } while ( done < nr_mfns );

    /*
     * Undo what we have done unless unmapping, by unmapping the entire region.
     * Errors here are ignored.
     */
    if ( ret && add_mapping != DPCI_REMOVE_MAPPING )
        xc_domain_memory_mapping(xch, domid, first_gfn, first_mfn, nr_mfns,
                                 DPCI_REMOVE_MAPPING);

    /* We might get E2BIG so many times that we never advance. */
    if ( !done && !ret )
        ret = -1;

    return ret;
}
#undef min
int xc_domain_ioport_mapping(
    xc_interface *xch,
    uint32_t domid,
    uint32_t first_gport,
    uint32_t first_mport,
    uint32_t nr_ports,
    uint32_t add_mapping)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_ioport_mapping;
    domctl.domain = domid;
    domctl.u.ioport_mapping.first_gport = first_gport;
    domctl.u.ioport_mapping.first_mport = first_mport;
    domctl.u.ioport_mapping.nr_ports = nr_ports;
    domctl.u.ioport_mapping.add_mapping = add_mapping;

    return do_domctl(xch, &domctl);
}

int xc_domain_set_target(
    xc_interface *xch,
    uint32_t domid,
    uint32_t target)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_set_target;
    domctl.domain = domid;
    domctl.u.set_target.target = target;

    return do_domctl(xch, &domctl);
}

int xc_domain_subscribe_for_suspend(
    xc_interface *xch, domid_t dom, evtchn_port_t port)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_subscribe;
    domctl.domain = dom;
    domctl.u.subscribe.port = port;

    return do_domctl(xch, &domctl);
}

int xc_domain_set_machine_address_size(xc_interface *xch,
                                       uint32_t domid,
                                       unsigned int width)
{
    DECLARE_DOMCTL;

    memset(&domctl, 0, sizeof(domctl));
    domctl.domain = domid;
    domctl.cmd    = XEN_DOMCTL_set_machine_address_size;
    domctl.u.address_size.size = width;

    return do_domctl(xch, &domctl);
}


int xc_domain_get_machine_address_size(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;
    int rc;

    memset(&domctl, 0, sizeof(domctl));
    domctl.domain = domid;
    domctl.cmd    = XEN_DOMCTL_get_machine_address_size;

    rc = do_domctl(xch, &domctl);

    return rc == 0 ? domctl.u.address_size.size : rc;
}

int xc_domain_suppress_spurious_page_faults(xc_interface *xc, uint32_t domid)
{
    DECLARE_DOMCTL;

    memset(&domctl, 0, sizeof(domctl));
    domctl.domain = domid;
    domctl.cmd    = XEN_DOMCTL_suppress_spurious_page_faults;

    return do_domctl(xc, &domctl);

}

int xc_domain_debug_control(xc_interface *xc, uint32_t domid, uint32_t sop, uint32_t vcpu)
{
    DECLARE_DOMCTL;

    memset(&domctl, 0, sizeof(domctl));
    domctl.domain = (domid_t)domid;
    domctl.cmd = XEN_DOMCTL_debug_op;
    domctl.u.debug_op.op     = sop;
    domctl.u.debug_op.vcpu   = vcpu;

    return do_domctl(xc, &domctl);
}

int xc_domain_p2m_audit(xc_interface *xch, 
                        uint32_t domid,
                        uint64_t *orphans,
                        uint64_t *m2p_bad,   
                        uint64_t *p2m_bad)
{
    DECLARE_DOMCTL;
    int rc;

    domctl.cmd = XEN_DOMCTL_audit_p2m;
    domctl.domain = domid;
    rc = do_domctl(xch, &domctl);

    *orphans = domctl.u.audit_p2m.orphans;
    *m2p_bad = domctl.u.audit_p2m.m2p_bad;
    *p2m_bad = domctl.u.audit_p2m.p2m_bad;

    return rc;
}

int xc_domain_set_access_required(xc_interface *xch,
                                  uint32_t domid,
                                  unsigned int required)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_set_access_required;
    domctl.domain = domid;
    domctl.u.access_required.access_required = required;
    return do_domctl(xch, &domctl);
}

int xc_domain_set_virq_handler(xc_interface *xch, uint32_t domid, int virq)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_set_virq_handler;
    domctl.domain = domid;
    domctl.u.set_virq_handler.virq = virq;
    return do_domctl(xch, &domctl);
}

int xc_domain_set_max_evtchn(xc_interface *xch, uint32_t domid,
                             uint32_t max_port)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_set_max_evtchn;
    domctl.domain = domid;
    domctl.u.set_max_evtchn.max_port = max_port;
    return do_domctl(xch, &domctl);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
