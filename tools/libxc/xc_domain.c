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
                     u32 ssidref,
                     u32 *pdomid)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_CREATEDOMAIN;
    op.u.createdomain.domain = (domid_t)*pdomid;
    op.u.createdomain.ssidref = ssidref;
    if ( (err = do_dom0_op(xc_handle, &op)) != 0 )
        return err;

    *pdomid = (u16)op.u.createdomain.domain;
    return 0;
}    


int xc_domain_pause(int xc_handle, 
                    u32 domid)
{
    dom0_op_t op;
    op.cmd = DOM0_PAUSEDOMAIN;
    op.u.pausedomain.domain = (domid_t)domid;
    return do_dom0_op(xc_handle, &op);
}    


int xc_domain_unpause(int xc_handle,
                      u32 domid)
{
    dom0_op_t op;
    op.cmd = DOM0_UNPAUSEDOMAIN;
    op.u.unpausedomain.domain = (domid_t)domid;
    return do_dom0_op(xc_handle, &op);
}    


int xc_domain_destroy(int xc_handle,
                      u32 domid)
{
    dom0_op_t op;
    op.cmd = DOM0_DESTROYDOMAIN;
    op.u.destroydomain.domain = (domid_t)domid;
    return do_dom0_op(xc_handle, &op);
}

int xc_domain_pincpu(int xc_handle,
                     u32 domid, 
                     int vcpu,
                     cpumap_t *cpumap)
{
    dom0_op_t op;
    op.cmd = DOM0_PINCPUDOMAIN;
    op.u.pincpudomain.domain  = (domid_t)domid;
    op.u.pincpudomain.vcpu    = vcpu;
    op.u.pincpudomain.cpumap  = cpumap;
    return do_dom0_op(xc_handle, &op);
}


int xc_domain_getinfo(int xc_handle,
                      u32 first_domid,
                      unsigned int max_doms,
                      xc_dominfo_t *info)
{
    unsigned int nr_doms;
    u32 next_domid = first_domid;
    dom0_op_t op;
    int rc = 0; 

    memset(info, 0, max_doms*sizeof(xc_dominfo_t));

    for ( nr_doms = 0; nr_doms < max_doms; nr_doms++ )
    {
        op.cmd = DOM0_GETDOMAININFO;
        op.u.getdomaininfo.domain = (domid_t)next_domid;
        if ( (rc = do_dom0_op(xc_handle, &op)) < 0 )
            break;
        info->domid      = (u16)op.u.getdomaininfo.domain;

        info->dying    = !!(op.u.getdomaininfo.flags & DOMFLAGS_DYING);
        info->shutdown = !!(op.u.getdomaininfo.flags & DOMFLAGS_SHUTDOWN);
        info->paused   = !!(op.u.getdomaininfo.flags & DOMFLAGS_PAUSED);
        info->blocked  = !!(op.u.getdomaininfo.flags & DOMFLAGS_BLOCKED);
        info->running  = !!(op.u.getdomaininfo.flags & DOMFLAGS_RUNNING);

        info->shutdown_reason = 
            (op.u.getdomaininfo.flags>>DOMFLAGS_SHUTDOWNSHIFT) & 
            DOMFLAGS_SHUTDOWNMASK;

        if ( info->shutdown && (info->shutdown_reason == SHUTDOWN_crash) )
        {
            info->shutdown = 0;
            info->crashed  = 1;
        }

        info->ssidref  = op.u.getdomaininfo.ssidref;
        info->nr_pages = op.u.getdomaininfo.tot_pages;
        info->max_memkb = op.u.getdomaininfo.max_pages << (PAGE_SHIFT - 10);
        info->shared_info_frame = op.u.getdomaininfo.shared_info_frame;
        info->cpu_time = op.u.getdomaininfo.cpu_time;
        info->vcpus = op.u.getdomaininfo.n_vcpu;
        memcpy(&info->vcpu_to_cpu, &op.u.getdomaininfo.vcpu_to_cpu, 
               sizeof(info->vcpu_to_cpu));
        memcpy(&info->cpumap, &op.u.getdomaininfo.cpumap, 
               sizeof(info->cpumap));

        next_domid = (u16)op.u.getdomaininfo.domain + 1;
        info++;
    }

    if( !nr_doms ) return rc; 

    return nr_doms;
}

int xc_domain_getinfolist(int xc_handle,
                          u32 first_domain,
                          unsigned int max_domains,
                          xc_domaininfo_t *info)
{
    int ret = 0;
    dom0_op_t op;

    if(mlock(info, max_domains*sizeof(xc_domaininfo_t)) != 0)
        return -1;
    
    op.cmd = DOM0_GETDOMAININFOLIST;
    op.u.getdomaininfolist.first_domain = first_domain;
    op.u.getdomaininfolist.max_domains  = max_domains;
    op.u.getdomaininfolist.buffer       = info;

    if(xc_dom0_op(xc_handle, &op) < 0)
        ret = -1;
    else
        ret = op.u.getdomaininfolist.num_domains;
    
    if(munlock(info, max_domains*sizeof(xc_domaininfo_t)) != 0)
        ret = -1;
    
    return ret;
}

int xc_domain_get_vcpu_context(int xc_handle,
                               u32 domid,
                               u32 vcpu,
                               vcpu_guest_context_t *ctxt)
{
    int rc;
    dom0_op_t op;

    op.cmd = DOM0_GETVCPUCONTEXT;
    op.u.getvcpucontext.domain = (domid_t)domid;
    op.u.getvcpucontext.vcpu   = (u16)vcpu;
    op.u.getvcpucontext.ctxt   = ctxt;

    if ( (ctxt != NULL) &&
         ((rc = mlock(ctxt, sizeof(*ctxt))) != 0) )
        return rc;

    rc = do_dom0_op(xc_handle, &op);

    if ( ctxt != NULL )
        safe_munlock(ctxt, sizeof(*ctxt));

    if ( rc > 0 )
        return -ESRCH;
    else
        return rc;
}


int xc_shadow_control(int xc_handle,
                      u32 domid, 
                      unsigned int sop,
                      unsigned long *dirty_bitmap,
                      unsigned long pages,
                      xc_shadow_control_stats_t *stats )
{
    int rc;
    dom0_op_t op;
    op.cmd = DOM0_SHADOW_CONTROL;
    op.u.shadow_control.domain = (domid_t)domid;
    op.u.shadow_control.op     = sop;
    op.u.shadow_control.dirty_bitmap = dirty_bitmap;
    op.u.shadow_control.pages  = pages;

    rc = do_dom0_op(xc_handle, &op);

    if ( stats )
        memcpy(stats, &op.u.shadow_control.stats,
               sizeof(xc_shadow_control_stats_t));

    return (rc == 0) ? op.u.shadow_control.pages : rc;
}

int xc_domain_setcpuweight(int xc_handle,
                           u32 domid,
                           float weight)
{
    int sched_id;
    int ret;
    
    /* Figure out which scheduler is currently used: */
    if ( (ret = xc_sched_id(xc_handle, &sched_id)) != 0 )
        return ret;
    
    switch ( sched_id )
    {
        case SCHED_BVT:
        {
            u32 mcuadv;
            int warpback;
            s32 warpvalue;
            long long warpl;
            long long warpu;

            /* Preserve all the scheduling parameters apart 
               of MCU advance. */
            if ( (ret = xc_bvtsched_domain_get(
                xc_handle, domid, &mcuadv, 
                &warpback, &warpvalue, &warpl, &warpu)) != 0 )
                return ret;
            
            /* The MCU advance is inverse of the weight.
               Default value of the weight is 1, default mcuadv 10.
               The scaling factor is therefore 10. */
            if ( weight > 0 )
                mcuadv = 10 / weight;
            
            ret = xc_bvtsched_domain_set(xc_handle, domid, mcuadv, 
                                         warpback, warpvalue, warpl, warpu);
            break;
        }
    }

    return ret;
}

int xc_domain_setmaxmem(int xc_handle,
                        u32 domid, 
                        unsigned int max_memkb)
{
    dom0_op_t op;
    op.cmd = DOM0_SETDOMAINMAXMEM;
    op.u.setdomainmaxmem.domain = (domid_t)domid;
    op.u.setdomainmaxmem.max_memkb = max_memkb;
    return do_dom0_op(xc_handle, &op);
}

int xc_domain_memory_increase_reservation(int xc_handle,
                                          u32 domid, 
                                          unsigned int mem_kb)
{
    int err;
    unsigned int npages = mem_kb / (PAGE_SIZE/1024);
    struct xen_memory_reservation reservation = {
        .nr_extents   = npages,
        .extent_order = 0,
        .domid        = DOMID_SELF
    };

    err = xc_memory_op(xc_handle, XENMEM_increase_reservation, &reservation);
    if (err == npages)
        return 0;

    if (err > 0) {
        errno = ENOMEM;
        err = -1;
    }
    return err;
}
