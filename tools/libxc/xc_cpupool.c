/******************************************************************************
 * xc_cpupool.c
 *
 * API for manipulating and obtaining information on cpupools.
 *
 * Copyright (c) 2009, J Gross.
 */

#include <stdarg.h>
#include "xc_private.h"

static int do_sysctl_save(xc_interface *xch, struct xen_sysctl *sysctl)
{
    int ret;

    do {
        ret = do_sysctl(xch, sysctl);
    } while ( (ret < 0) && (errno == EAGAIN) );

    return ret;
}

int xc_cpupool_create(xc_interface *xch,
                      uint32_t *ppoolid,
                      uint32_t sched_id)
{
    int err;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_cpupool_op;
    sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_CREATE;
    sysctl.u.cpupool_op.cpupool_id = (*ppoolid == 0) ?
        XEN_SYSCTL_CPUPOOL_PAR_ANY : *ppoolid;
    sysctl.u.cpupool_op.sched_id = sched_id;
    if ( (err = do_sysctl_save(xch, &sysctl)) != 0 )
        return err;

    *ppoolid = sysctl.u.cpupool_op.cpupool_id;
    return 0;
}

int xc_cpupool_destroy(xc_interface *xch,
                       uint32_t poolid)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_cpupool_op;
    sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_DESTROY;
    sysctl.u.cpupool_op.cpupool_id = poolid;
    return do_sysctl_save(xch, &sysctl);
}

int xc_cpupool_getinfo(xc_interface *xch, 
                       uint32_t first_poolid,
                       uint32_t n_max, 
                       xc_cpupoolinfo_t *info)
{
    int err = 0;
    int p;
    uint32_t poolid = first_poolid;
    uint8_t local[sizeof (info->cpumap)];
    DECLARE_SYSCTL;

    memset(info, 0, n_max * sizeof(xc_cpupoolinfo_t));

    for (p = 0; p < n_max; p++)
    {
        sysctl.cmd = XEN_SYSCTL_cpupool_op;
        sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_INFO;
        sysctl.u.cpupool_op.cpupool_id = poolid;
        set_xen_guest_handle(sysctl.u.cpupool_op.cpumap.bitmap, local);
        sysctl.u.cpupool_op.cpumap.nr_cpus = sizeof(info->cpumap) * 8;

        if ( (err = lock_pages(local, sizeof(local))) != 0 )
        {
            PERROR("Could not lock memory for Xen hypercall");
            break;
        }
        err = do_sysctl_save(xch, &sysctl);
        unlock_pages(local, sizeof (local));

        if ( err < 0 )
            break;

        info->cpupool_id = sysctl.u.cpupool_op.cpupool_id;
        info->sched_id = sysctl.u.cpupool_op.sched_id;
        info->n_dom = sysctl.u.cpupool_op.n_dom;
        bitmap_byte_to_64(&(info->cpumap), local, sizeof(local) * 8);
        poolid = sysctl.u.cpupool_op.cpupool_id + 1;
        info++;
    }

    if ( p == 0 )
        return err;

    return p;
}

int xc_cpupool_addcpu(xc_interface *xch,
                      uint32_t poolid,
                      int cpu)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_cpupool_op;
    sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_ADDCPU;
    sysctl.u.cpupool_op.cpupool_id = poolid;
    sysctl.u.cpupool_op.cpu = (cpu < 0) ? XEN_SYSCTL_CPUPOOL_PAR_ANY : cpu;
    return do_sysctl_save(xch, &sysctl);
}

int xc_cpupool_removecpu(xc_interface *xch,
                         uint32_t poolid,
                         int cpu)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_cpupool_op;
    sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_RMCPU;
    sysctl.u.cpupool_op.cpupool_id = poolid;
    sysctl.u.cpupool_op.cpu = (cpu < 0) ? XEN_SYSCTL_CPUPOOL_PAR_ANY : cpu;
    return do_sysctl_save(xch, &sysctl);
}

int xc_cpupool_movedomain(xc_interface *xch,
                          uint32_t poolid,
                          uint32_t domid)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_cpupool_op;
    sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_MOVEDOMAIN;
    sysctl.u.cpupool_op.cpupool_id = poolid;
    sysctl.u.cpupool_op.domid = domid;
    return do_sysctl_save(xch, &sysctl);
}

int xc_cpupool_freeinfo(xc_interface *xch,
                        uint64_t *cpumap)
{
    int err;
    uint8_t local[sizeof (*cpumap)];
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_cpupool_op;
    sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_FREEINFO;
    set_xen_guest_handle(sysctl.u.cpupool_op.cpumap.bitmap, local);
    sysctl.u.cpupool_op.cpumap.nr_cpus = sizeof(*cpumap) * 8;

    if ( (err = lock_pages(local, sizeof(local))) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        return err;
    }

    err = do_sysctl_save(xch, &sysctl);
    unlock_pages(local, sizeof (local));

    if (err < 0)
        return err;

    bitmap_byte_to_64(cpumap, local, sizeof(local) * 8);

    return 0;
}
