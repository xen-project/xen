/******************************************************************************
 * xc_domain.c
 * 
 * API for manipulating and obtaining information on domains.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"

int xc_domain_create(int xc_handle,
                     unsigned int mem_kb, 
                     const char *name,
                     int cpu,
                     u32 *pdomid)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_CREATEDOMAIN;
    op.u.createdomain.domain = (domid_t)*pdomid;
    op.u.createdomain.memory_kb = mem_kb;
    strncpy(op.u.createdomain.name, name, MAX_DOMAIN_NAME);
    op.u.createdomain.name[MAX_DOMAIN_NAME-1] = '\0';
    op.u.createdomain.cpu = cpu;

    if ( (err = do_dom0_op(xc_handle, &op)) == 0 )
        *pdomid = (u32)op.u.createdomain.domain;

    return err;
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
                     int cpu)
{
    dom0_op_t op;
    op.cmd = DOM0_PINCPUDOMAIN;
    op.u.pincpudomain.domain = (domid_t)domid;
    op.u.pincpudomain.cpu  = cpu;
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

    for ( nr_doms = 0; nr_doms < max_doms; nr_doms++ )
    {
        op.cmd = DOM0_GETDOMAININFO;
        op.u.getdomaininfo.domain = (domid_t)next_domid;
        op.u.getdomaininfo.ctxt = NULL; /* no exec context info, thanks. */
        if ( do_dom0_op(xc_handle, &op) < 0 )
            break;
        info->domid   = (u32)op.u.getdomaininfo.domain;

        info->cpu     =
            (op.u.getdomaininfo.flags>>DOMFLAGS_CPUSHIFT) & DOMFLAGS_CPUMASK;

        info->dying    = !!(op.u.getdomaininfo.flags & DOMFLAGS_DYING);
        info->crashed  = !!(op.u.getdomaininfo.flags & DOMFLAGS_CRASHED);
        info->shutdown = !!(op.u.getdomaininfo.flags & DOMFLAGS_SHUTDOWN);
        info->paused   = !!(op.u.getdomaininfo.flags & DOMFLAGS_PAUSED);
        info->blocked  = !!(op.u.getdomaininfo.flags & DOMFLAGS_BLOCKED);
        info->running  = !!(op.u.getdomaininfo.flags & DOMFLAGS_RUNNING);

        info->shutdown_reason = 
            (op.u.getdomaininfo.flags>>DOMFLAGS_SHUTDOWNSHIFT) & 
            DOMFLAGS_SHUTDOWNMASK;

        info->nr_pages = op.u.getdomaininfo.tot_pages;
        info->max_memkb = op.u.getdomaininfo.max_pages<<(PAGE_SHIFT-10);
        info->shared_info_frame = op.u.getdomaininfo.shared_info_frame;
        info->cpu_time = op.u.getdomaininfo.cpu_time;
        strncpy(info->name, op.u.getdomaininfo.name, XC_DOMINFO_MAXNAME);
        info->name[XC_DOMINFO_MAXNAME-1] = '\0';

        next_domid = (u32)op.u.getdomaininfo.domain + 1;
        info++;
    }

    return nr_doms;
}

int xc_domain_getfullinfo(int xc_handle,
                          u32 domid,
                          dom0_op_t *op,
                          full_execution_context_t *ctxt )
{
    int rc;
    op->cmd = DOM0_GETDOMAININFO;
    op->u.getdomaininfo.domain = (domid_t)domid;
    op->u.getdomaininfo.ctxt = ctxt;

    rc = do_dom0_op(xc_handle, op);
    if ( ((u32)op->u.getdomaininfo.domain != domid) && rc > 0 )
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

int xc_domain_setname(int xc_handle,
                      u32 domid, 
                      char *name)
{
    dom0_op_t op;
    op.cmd = DOM0_SETDOMAINNAME;
    op.u.setdomainname.domain = (domid_t)domid;
    strncpy(op.u.setdomainname.name, name, MAX_DOMAIN_NAME);
    return do_dom0_op(xc_handle, &op);
}

int xc_domain_setinitialmem(int xc_handle,
                            u32 domid, 
                            unsigned int initial_memkb)
{
    dom0_op_t op;
    op.cmd = DOM0_SETDOMAININITIALMEM;
    op.u.setdomaininitialmem.domain = (domid_t)domid;
    op.u.setdomaininitialmem.initial_memkb = initial_memkb;
    return do_dom0_op(xc_handle, &op);
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

