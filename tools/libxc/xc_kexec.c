/******************************************************************************
 * xc_kexec.c
 *
 * API for loading and executing kexec images.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 */
#include "xc_private.h"

int xc_kexec_exec(xc_interface *xch, int type)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_kexec_exec_t, exec);
    int ret = -1;

    exec = xc_hypercall_buffer_alloc(xch, exec, sizeof(*exec));
    if ( exec == NULL )
    {
        PERROR("Count not alloc bounce buffer for kexec_exec hypercall");
        goto out;
    }

    exec->type = type;

    hypercall.op = __HYPERVISOR_kexec_op;
    hypercall.arg[0] = KEXEC_CMD_kexec;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(exec);

    ret = do_xen_hypercall(xch, &hypercall);

out:
    xc_hypercall_buffer_free(xch, exec);

    return ret;
}

int xc_kexec_get_range(xc_interface *xch, int range,  int nr,
                       uint64_t *size, uint64_t *start)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_kexec_range_t, get_range);
    int ret = -1;

    get_range = xc_hypercall_buffer_alloc(xch, get_range, sizeof(*get_range));
    if ( get_range == NULL )
    {
        PERROR("Could not alloc bounce buffer for kexec_get_range hypercall");
        goto out;
    }

    get_range->range = range;
    get_range->nr = nr;

    hypercall.op = __HYPERVISOR_kexec_op;
    hypercall.arg[0] = KEXEC_CMD_kexec_get_range;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(get_range);

    ret = do_xen_hypercall(xch, &hypercall);

    *size = get_range->size;
    *start = get_range->start;

out:
    xc_hypercall_buffer_free(xch, get_range);

    return ret;
}

int xc_kexec_load(xc_interface *xch, uint8_t type, uint16_t arch,
                  uint64_t entry_maddr,
                  uint32_t nr_segments, xen_kexec_segment_t *segments)
{
    int ret = -1;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BOUNCE(segments, sizeof(*segments) * nr_segments,
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BUFFER(xen_kexec_load_t, load);

    if ( xc_hypercall_bounce_pre(xch, segments) )
    {
        PERROR("Could not allocate bounce buffer for kexec load hypercall");
        goto out;
    }
    load = xc_hypercall_buffer_alloc(xch, load, sizeof(*load));
    if ( load == NULL )
    {
        PERROR("Could not allocate buffer for kexec load hypercall");
        goto out;
    }

    load->type = type;
    load->arch = arch;
    load->entry_maddr = entry_maddr;
    load->nr_segments = nr_segments;
    set_xen_guest_handle(load->segments.h, segments);

    hypercall.op = __HYPERVISOR_kexec_op;
    hypercall.arg[0] = KEXEC_CMD_kexec_load;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(load);

    ret = do_xen_hypercall(xch, &hypercall);

out:
    xc_hypercall_buffer_free(xch, load);
    xc_hypercall_bounce_post(xch, segments);

    return ret;
}

int xc_kexec_unload(xc_interface *xch, int type)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(xen_kexec_unload_t, unload);
    int ret = -1;

    unload = xc_hypercall_buffer_alloc(xch, unload, sizeof(*unload));
    if ( unload == NULL )
    {
        PERROR("Count not alloc buffer for kexec unload hypercall");
        goto out;
    }

    unload->type = type;

    hypercall.op = __HYPERVISOR_kexec_op;
    hypercall.arg[0] = KEXEC_CMD_kexec_unload;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(unload);

    ret = do_xen_hypercall(xch, &hypercall);

out:
    xc_hypercall_buffer_free(xch, unload);

    return ret;
}
