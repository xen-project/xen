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
                     const char *name)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_CREATEDOMAIN;
    op.u.createdomain.memory_kb = mem_kb;
    strncpy(op.u.createdomain.name, name, MAX_DOMAIN_NAME);
    op.u.createdomain.name[MAX_DOMAIN_NAME-1] = '\0';

    err = do_dom0_op(xc_handle, &op);

    return (err < 0) ? err : op.u.createdomain.domain;
}    


int xc_domain_start(int xc_handle,
                    unsigned int domid)
{
    dom0_op_t op;
    op.cmd = DOM0_STARTDOMAIN;
    op.u.startdomain.domain = domid;
    return do_dom0_op(xc_handle, &op);
}    


int xc_domain_stop(int xc_handle, 
                   unsigned int domid)
{
    dom0_op_t op;
    op.cmd = DOM0_STOPDOMAIN;
    op.u.stopdomain.domain = domid;
    return do_dom0_op(xc_handle, &op);
}    


int xc_domain_destroy(int xc_handle,
                      unsigned int domid, 
                      int force)
{
    dom0_op_t op;
    op.cmd = DOM0_DESTROYDOMAIN;
    op.u.destroydomain.domain = domid;
    op.u.destroydomain.force  = !!force;
    return do_dom0_op(xc_handle, &op);
}

int xc_domain_getinfo(int xc_handle,
                      unsigned int first_domid,
                      unsigned int max_doms,
                      xc_dominfo_t *info)
{
    unsigned int nr_doms, next_domid = first_domid;
    dom0_op_t op;

    for ( nr_doms = 0; nr_doms < max_doms; nr_doms++ )
    {
        op.cmd = DOM0_GETDOMAININFO;
        op.u.getdomaininfo.domain = next_domid;
        if ( do_dom0_op(xc_handle, &op) < 0 )
            break;
        info->domid   = op.u.getdomaininfo.domain;
        info->cpu     = op.u.getdomaininfo.processor;
        info->has_cpu = op.u.getdomaininfo.has_cpu;
        info->stopped = (op.u.getdomaininfo.state == DOMSTATE_STOPPED);
        info->nr_pages = op.u.getdomaininfo.tot_pages;
        info->cpu_time = op.u.getdomaininfo.cpu_time;
        strncpy(info->name, op.u.getdomaininfo.name, XC_DOMINFO_MAXNAME);
        info->name[XC_DOMINFO_MAXNAME-1] = '\0';

        next_domid = op.u.getdomaininfo.domain + 1;
        info++;
    }

    return nr_doms;
}
