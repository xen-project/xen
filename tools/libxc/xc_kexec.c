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
    DECLARE_HYPERCALL_BUFFER(xen_kexec_exec_t, exec);
    int ret = -1;

    exec = xc_hypercall_buffer_alloc(xch, exec, sizeof(*exec));
    if ( exec == NULL )
    {
        PERROR("Could not alloc bounce buffer for kexec_exec hypercall");
        goto out;
    }

    exec->type = type;

    ret = xencall2(xch->xcall, __HYPERVISOR_kexec_op,
                   KEXEC_CMD_kexec,
                   HYPERCALL_BUFFER_AS_ARG(exec));

out:
    xc_hypercall_buffer_free(xch, exec);

    return ret;
}

int xc_kexec_get_range(xc_interface *xch, int range,  int nr,
                       uint64_t *size, uint64_t *start)
{
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

    ret = xencall2(xch->xcall, __HYPERVISOR_kexec_op,
                   KEXEC_CMD_kexec_get_range,
                   HYPERCALL_BUFFER_AS_ARG(get_range));

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

    ret = xencall2(xch->xcall, __HYPERVISOR_kexec_op,
                   KEXEC_CMD_kexec_load,
                   HYPERCALL_BUFFER_AS_ARG(load));

out:
    xc_hypercall_buffer_free(xch, load);
    xc_hypercall_bounce_post(xch, segments);

    return ret;
}

int xc_kexec_unload(xc_interface *xch, int type)
{
    DECLARE_HYPERCALL_BUFFER(xen_kexec_unload_t, unload);
    int ret = -1;

    unload = xc_hypercall_buffer_alloc(xch, unload, sizeof(*unload));
    if ( unload == NULL )
    {
        PERROR("Could not alloc buffer for kexec unload hypercall");
        goto out;
    }

    unload->type = type;

    ret = xencall2(xch->xcall, __HYPERVISOR_kexec_op,
                   KEXEC_CMD_kexec_unload,
                   HYPERCALL_BUFFER_AS_ARG(unload));

out:
    xc_hypercall_buffer_free(xch, unload);

    return ret;
}

int xc_kexec_status(xc_interface *xch, int type)
{
    DECLARE_HYPERCALL_BUFFER(xen_kexec_status_t, status);
    int ret = -1;

    status = xc_hypercall_buffer_alloc(xch, status, sizeof(*status));
    if ( status == NULL )
    {
        PERROR("Could not alloc buffer for kexec status hypercall");
        goto out;
    }

    status->type = type;

    ret = xencall2(xch->xcall, __HYPERVISOR_kexec_op,
                   KEXEC_CMD_kexec_status,
                   HYPERCALL_BUFFER_AS_ARG(status));

out:
    xc_hypercall_buffer_free(xch, status);

    return ret;
}
