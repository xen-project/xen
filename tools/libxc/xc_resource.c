/*
 * xc_resource.c
 *
 * Generic resource access API
 *
 * Copyright (C) 2014      Intel Corporation
 * Author Dongxiao Xu <dongxiao.xu@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "xc_private.h"

static int xc_resource_op_one(xc_interface *xch, xc_resource_op_t *op)
{
    int rc;
    DECLARE_PLATFORM_OP;
    DECLARE_NAMED_HYPERCALL_BOUNCE(entries, op->entries,
                                op->nr_entries * sizeof(*op->entries),
                                XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, entries) )
        return -1;

    platform_op.cmd = XENPF_resource_op;
    platform_op.u.resource_op.nr_entries = op->nr_entries;
    platform_op.u.resource_op.cpu = op->cpu;
    set_xen_guest_handle(platform_op.u.resource_op.entries, entries);

    rc = do_platform_op(xch, &platform_op);
    op->result = rc;

    xc_hypercall_bounce_post(xch, entries);

    return rc;
}

static int xc_resource_op_multi(xc_interface *xch, uint32_t nr_ops, xc_resource_op_t *ops)
{
    int rc, i, entries_size;
    xc_resource_op_t *op;
    multicall_entry_t *call;
    DECLARE_HYPERCALL_BUFFER(multicall_entry_t, call_list);
    xc_hypercall_buffer_array_t *platform_ops, *entries_list = NULL;

    call_list = xc_hypercall_buffer_alloc(xch, call_list,
                                          sizeof(*call_list) * nr_ops);
    if ( !call_list )
        return -1;

    platform_ops = xc_hypercall_buffer_array_create(xch, nr_ops);
    if ( !platform_ops )
    {
        rc = -1;
        goto out;
    }

    entries_list = xc_hypercall_buffer_array_create(xch, nr_ops);
    if ( !entries_list )
    {
        rc = -1;
        goto out;
    }

    for ( i = 0; i < nr_ops; i++ )
    {
        DECLARE_HYPERCALL_BUFFER(xen_platform_op_t, platform_op);
        DECLARE_HYPERCALL_BUFFER(xc_resource_entry_t, entries);

        op = ops + i;

        platform_op = xc_hypercall_buffer_array_alloc(xch, platform_ops, i,
                        platform_op, sizeof(xen_platform_op_t));
        if ( !platform_op )
        {
            rc = -1;
            goto out;
        }

        entries_size = sizeof(xc_resource_entry_t) * op->nr_entries;
        entries = xc_hypercall_buffer_array_alloc(xch, entries_list, i,
                   entries, entries_size);
        if ( !entries)
        {
            rc = -1;
            goto out;
        }
        memcpy(entries, op->entries, entries_size);

        call = call_list + i;
        call->op = __HYPERVISOR_platform_op;
        call->args[0] = HYPERCALL_BUFFER_AS_ARG(platform_op);

        platform_op->interface_version = XENPF_INTERFACE_VERSION;
        platform_op->cmd = XENPF_resource_op;
        platform_op->u.resource_op.cpu = op->cpu;
        platform_op->u.resource_op.nr_entries = op->nr_entries;
        set_xen_guest_handle(platform_op->u.resource_op.entries, entries);
    }

    rc = do_multicall_op(xch, HYPERCALL_BUFFER(call_list), nr_ops);

    for ( i = 0; i < nr_ops; i++ )
    {
        DECLARE_HYPERCALL_BUFFER(xc_resource_entry_t, entries);
        op = ops + i;

        call = call_list + i;
        op->result = call->result;

        entries_size = sizeof(xc_resource_entry_t) * op->nr_entries;
        entries = xc_hypercall_buffer_array_get(xch, entries_list, i,
                   entries, entries_size);
        memcpy(op->entries, entries, entries_size);
    }

out:
    xc_hypercall_buffer_array_destroy(xch, entries_list);
    xc_hypercall_buffer_array_destroy(xch, platform_ops);
    xc_hypercall_buffer_free(xch, call_list);
    return rc;
}

int xc_resource_op(xc_interface *xch, uint32_t nr_ops, xc_resource_op_t *ops)
{
    if ( nr_ops == 1 )
        return xc_resource_op_one(xch, ops);
    else if ( nr_ops > 1 )
        return xc_resource_op_multi(xch, nr_ops, ops);
    else
        return -1;
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
