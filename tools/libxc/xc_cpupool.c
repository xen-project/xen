/******************************************************************************
 * xc_cpupool.c
 *
 * API for manipulating and obtaining information on cpupools.
 *
 * Copyright (c) 2009, J Gross.
 */

#include <stdarg.h>
#include "xc_private.h"

int xc_cpupool_create(int xc_handle,
                      uint32_t *ppoolid,
                      uint32_t sched_id)
{
    int err;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cpupool_op;
    domctl.u.cpupool_op.op = XEN_DOMCTL_CPUPOOL_OP_CREATE;
    domctl.u.cpupool_op.cpupool_id = (*ppoolid == 0) ?
        XEN_DOMCTL_CPUPOOL_PAR_ANY : *ppoolid;
    domctl.u.cpupool_op.sched_id = sched_id;
    if ( (err = do_domctl_save(xc_handle, &domctl)) != 0 )
        return err;

    *ppoolid = domctl.u.cpupool_op.cpupool_id;
    return 0;
}

int xc_cpupool_destroy(int xc_handle,
                       uint32_t poolid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cpupool_op;
    domctl.u.cpupool_op.op = XEN_DOMCTL_CPUPOOL_OP_DESTROY;
    domctl.u.cpupool_op.cpupool_id = poolid;
    return do_domctl_save(xc_handle, &domctl);
}

int xc_cpupool_getinfo(int xc_handle, 
                       uint32_t first_poolid,
                       uint32_t n_max, 
                       xc_cpupoolinfo_t *info)
{
    int err = 0;
    int p;
    uint32_t poolid = first_poolid;
    uint8_t local[sizeof (info->cpumap)];
    DECLARE_DOMCTL;

    memset(info, 0, n_max * sizeof(xc_cpupoolinfo_t));

    for (p = 0; p < n_max; p++)
    {
        domctl.cmd = XEN_DOMCTL_cpupool_op;
        domctl.u.cpupool_op.op = XEN_DOMCTL_CPUPOOL_OP_INFO;
        domctl.u.cpupool_op.cpupool_id = poolid;
        set_xen_guest_handle(domctl.u.cpupool_op.cpumap.bitmap, local);
        domctl.u.cpupool_op.cpumap.nr_cpus = sizeof(info->cpumap) * 8;

        if ( (err = lock_pages(local, sizeof(local))) != 0 )
        {
            PERROR("Could not lock memory for Xen hypercall");
            break;
        }
        err = do_domctl_save(xc_handle, &domctl);
        unlock_pages(local, sizeof (local));

        if ( err < 0 )
            break;

        info->cpupool_id = domctl.u.cpupool_op.cpupool_id;
        info->sched_id = domctl.u.cpupool_op.sched_id;
        info->n_dom = domctl.u.cpupool_op.n_dom;
        bitmap_byte_to_64(&(info->cpumap), local, sizeof(local) * 8);
        poolid = domctl.u.cpupool_op.cpupool_id + 1;
        info++;
    }

    if ( p == 0 )
        return err;

    return p;
}

int xc_cpupool_addcpu(int xc_handle,
                      uint32_t poolid,
                      int cpu)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cpupool_op;
    domctl.u.cpupool_op.op = XEN_DOMCTL_CPUPOOL_OP_ADDCPU;
    domctl.u.cpupool_op.cpupool_id = poolid;
    domctl.u.cpupool_op.cpu = (cpu < 0) ? XEN_DOMCTL_CPUPOOL_PAR_ANY : cpu;
    return do_domctl_save(xc_handle, &domctl);
}

int xc_cpupool_removecpu(int xc_handle,
                         uint32_t poolid,
                         int cpu)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cpupool_op;
    domctl.u.cpupool_op.op = XEN_DOMCTL_CPUPOOL_OP_RMCPU;
    domctl.u.cpupool_op.cpupool_id = poolid;
    domctl.u.cpupool_op.cpu = (cpu < 0) ? XEN_DOMCTL_CPUPOOL_PAR_ANY : cpu;
    return do_domctl_save(xc_handle, &domctl);
}

int xc_cpupool_movedomain(int xc_handle,
                          uint32_t poolid,
                          uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cpupool_op;
    domctl.u.cpupool_op.op = XEN_DOMCTL_CPUPOOL_OP_MOVEDOMAIN;
    domctl.u.cpupool_op.cpupool_id = poolid;
    domctl.u.cpupool_op.domid = domid;
    return do_domctl_save(xc_handle, &domctl);
}

int xc_cpupool_freeinfo(int xc_handle,
                        uint64_t *cpumap)
{
    int err;
    uint8_t local[sizeof (*cpumap)];
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cpupool_op;
    domctl.u.cpupool_op.op = XEN_DOMCTL_CPUPOOL_OP_FREEINFO;
    set_xen_guest_handle(domctl.u.cpupool_op.cpumap.bitmap, local);
    domctl.u.cpupool_op.cpumap.nr_cpus = sizeof(*cpumap) * 8;

    if ( (err = lock_pages(local, sizeof(local))) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        return err;
    }

    err = do_domctl_save(xc_handle, &domctl);
    unlock_pages(local, sizeof (local));

    if (err < 0)
        return err;

    bitmap_byte_to_64(cpumap, local, sizeof(local) * 8);

    return 0;
}
