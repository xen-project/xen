/*
 * Copyright (c) 2016 Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/sched.h>

#include <asm/hvm/ioreq.h>

#include <xsm/xsm.h>

static bool copy_buf_from_guest(const xen_dm_op_buf_t bufs[],
                                unsigned int nr_bufs, void *dst,
                                unsigned int idx, size_t dst_size)
{
    size_t size;

    if ( idx >= nr_bufs )
        return false;

    memset(dst, 0, dst_size);

    size = min_t(size_t, dst_size, bufs[idx].size);

    return !copy_from_guest(dst, bufs[idx].h, size);
}

static bool copy_buf_to_guest(const xen_dm_op_buf_t bufs[],
                              unsigned int nr_bufs, unsigned int idx,
                              const void *src, size_t src_size)
{
    size_t size;

    if ( idx >= nr_bufs )
        return false;

    size = min_t(size_t, bufs[idx].size, src_size);

    return !copy_to_guest(bufs[idx].h, src, size);
}

static int dm_op(domid_t domid,
                 unsigned int nr_bufs,
                 xen_dm_op_buf_t bufs[])
{
    struct domain *d;
    struct xen_dm_op op;
    bool const_op = true;
    long rc;

    rc = rcu_lock_remote_domain_by_id(domid, &d);
    if ( rc )
        return rc;

    if ( !has_hvm_container_domain(d) )
        goto out;

    rc = xsm_dm_op(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    if ( !copy_buf_from_guest(bufs, nr_bufs, &op, 0, sizeof(op)) )
    {
        rc = -EFAULT;
        goto out;
    }

    rc = -EINVAL;
    if ( op.pad )
        goto out;

    switch ( op.op )
    {
    case XEN_DMOP_create_ioreq_server:
    {
        struct domain *curr_d = current->domain;
        struct xen_dm_op_create_ioreq_server *data =
            &op.u.create_ioreq_server;

        const_op = false;

        rc = -EINVAL;
        if ( data->pad[0] || data->pad[1] || data->pad[2] )
            break;

        rc = hvm_create_ioreq_server(d, curr_d->domain_id, 0,
                                     data->handle_bufioreq, &data->id);
        break;
    }

    case XEN_DMOP_get_ioreq_server_info:
    {
        struct xen_dm_op_get_ioreq_server_info *data =
            &op.u.get_ioreq_server_info;

        const_op = false;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_get_ioreq_server_info(d, data->id,
                                       &data->ioreq_pfn,
                                       &data->bufioreq_pfn,
                                       &data->bufioreq_port);
        break;
    }

    case XEN_DMOP_map_io_range_to_ioreq_server:
    {
        const struct xen_dm_op_ioreq_server_range *data =
            &op.u.map_io_range_to_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_map_io_range_to_ioreq_server(d, data->id, data->type,
                                              data->start, data->end);
        break;
    }

    case XEN_DMOP_unmap_io_range_from_ioreq_server:
    {
        const struct xen_dm_op_ioreq_server_range *data =
            &op.u.unmap_io_range_from_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_unmap_io_range_from_ioreq_server(d, data->id, data->type,
                                                  data->start, data->end);
        break;
    }

    case XEN_DMOP_set_ioreq_server_state:
    {
        const struct xen_dm_op_set_ioreq_server_state *data =
            &op.u.set_ioreq_server_state;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_set_ioreq_server_state(d, data->id, !!data->enabled);
        break;
    }

    case XEN_DMOP_destroy_ioreq_server:
    {
        const struct xen_dm_op_destroy_ioreq_server *data =
            &op.u.destroy_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_destroy_ioreq_server(d, data->id);
        break;
    }

    default:
        rc = -EOPNOTSUPP;
        break;
    }

    if ( !rc &&
         !const_op &&
         !copy_buf_to_guest(bufs, nr_bufs, 0, &op, sizeof(op)) )
        rc = -EFAULT;

 out:
    rcu_unlock_domain(d);

    return rc;
}

CHECK_dm_op_create_ioreq_server;
CHECK_dm_op_get_ioreq_server_info;
CHECK_dm_op_ioreq_server_range;
CHECK_dm_op_set_ioreq_server_state;
CHECK_dm_op_destroy_ioreq_server;

#define MAX_NR_BUFS 1

int compat_dm_op(domid_t domid,
                 unsigned int nr_bufs,
                 COMPAT_HANDLE_PARAM(compat_dm_op_buf_t) bufs)
{
    struct xen_dm_op_buf nat[MAX_NR_BUFS];
    unsigned int i;

    if ( nr_bufs > MAX_NR_BUFS )
        return -E2BIG;

    for ( i = 0; i < nr_bufs; i++ )
    {
        struct compat_dm_op_buf cmp;

        if ( copy_from_compat_offset(&cmp, bufs, i, 1) )
            return -EFAULT;

#define XLAT_dm_op_buf_HNDL_h(_d_, _s_) \
        guest_from_compat_handle((_d_)->h, (_s_)->h)

        XLAT_dm_op_buf(&nat[i], &cmp);

#undef XLAT_dm_op_buf_HNDL_h
    }

    return dm_op(domid, nr_bufs, nat);
}

long do_dm_op(domid_t domid,
              unsigned int nr_bufs,
              XEN_GUEST_HANDLE_PARAM(xen_dm_op_buf_t) bufs)
{
    struct xen_dm_op_buf nat[MAX_NR_BUFS];

    if ( nr_bufs > MAX_NR_BUFS )
        return -E2BIG;

    if ( copy_from_guest_offset(nat, bufs, 0, nr_bufs) )
        return -EFAULT;

    return dm_op(domid, nr_bufs, nat);
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
