/******************************************************************************
 * xc_cpupool.c
 *
 * API for manipulating and obtaining information on cpupools.
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

static int get_cpumap_size(xc_interface *xch)
{
    return (xc_get_max_cpus(xch) + 7) / 8;
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

xc_cpupoolinfo_t *xc_cpupool_getinfo(xc_interface *xch, 
                       uint32_t poolid)
{
    int err = 0;
    xc_cpupoolinfo_t *info = NULL;
    int local_size;
    int cpumap_size;
    int size;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BUFFER(uint8_t, local);

    local_size = get_cpumap_size(xch);
    if (!local_size)
    {
        PERROR("Could not get number of cpus");
        return NULL;
    }

    local = xc_hypercall_buffer_alloc(xch, local, local_size);
    if ( local == NULL ) {
        PERROR("Could not allocate locked memory for xc_cpupool_getinfo");
        return NULL;
    }

    cpumap_size = (local_size + sizeof(*info->cpumap) - 1) / sizeof(*info->cpumap);
    size = sizeof(xc_cpupoolinfo_t) + cpumap_size * sizeof(*info->cpumap);

    sysctl.cmd = XEN_SYSCTL_cpupool_op;
    sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_INFO;
    sysctl.u.cpupool_op.cpupool_id = poolid;
    set_xen_guest_handle(sysctl.u.cpupool_op.cpumap.bitmap, local);
    sysctl.u.cpupool_op.cpumap.nr_cpus = local_size * 8;

    err = do_sysctl_save(xch, &sysctl);

    if ( err < 0 )
	goto out;

    info = malloc(size);
    if ( !info )
	goto out;

    memset(info, 0, size);
    info->cpumap_size = local_size * 8;
    info->cpumap = (uint64_t *)(info + 1);

    info->cpupool_id = sysctl.u.cpupool_op.cpupool_id;
    info->sched_id = sysctl.u.cpupool_op.sched_id;
    info->n_dom = sysctl.u.cpupool_op.n_dom;
    bitmap_byte_to_64(info->cpumap, local, local_size * 8);

out:
    xc_hypercall_buffer_free(xch, local);

    return info;
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

uint64_t * xc_cpupool_freeinfo(xc_interface *xch,
                        int *cpusize)
{
    int err = -1;
    uint64_t *cpumap = NULL;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BUFFER(uint8_t, local);

    *cpusize = get_cpumap_size(xch);
    if (*cpusize == 0)
        return NULL;

    local = xc_hypercall_buffer_alloc(xch, local, *cpusize);
    if ( local == NULL ) {
        PERROR("Could not allocate locked memory for xc_cpupool_freeinfo");
        return NULL;
    }

    sysctl.cmd = XEN_SYSCTL_cpupool_op;
    sysctl.u.cpupool_op.op = XEN_SYSCTL_CPUPOOL_OP_FREEINFO;
    set_xen_guest_handle(sysctl.u.cpupool_op.cpumap.bitmap, local);
    sysctl.u.cpupool_op.cpumap.nr_cpus = *cpusize * 8;

    err = do_sysctl_save(xch, &sysctl);

    if ( err < 0 )
	goto out;

    cpumap = calloc((*cpusize + sizeof(*cpumap) - 1) / sizeof(*cpumap), sizeof(*cpumap));
    if (cpumap == NULL)
	goto out;

    bitmap_byte_to_64(cpumap, local, *cpusize * 8);

out:
    xc_hypercall_buffer_free(xch, local);
    return cpumap;
}
