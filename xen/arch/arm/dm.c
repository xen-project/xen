/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019 Arm ltd.
 */

#include <xen/dm.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/ioreq.h>
#include <xen/nospec.h>

#include <asm/vgic.h>

int dm_op(const struct dmop_args *op_args)
{
    struct domain *d;
    struct xen_dm_op op;
    bool const_op = true;
    long rc;
    size_t offset;

    static const uint8_t op_size[] = {
        [XEN_DMOP_create_ioreq_server]              = sizeof(struct xen_dm_op_create_ioreq_server),
        [XEN_DMOP_get_ioreq_server_info]            = sizeof(struct xen_dm_op_get_ioreq_server_info),
        [XEN_DMOP_map_io_range_to_ioreq_server]     = sizeof(struct xen_dm_op_ioreq_server_range),
        [XEN_DMOP_unmap_io_range_from_ioreq_server] = sizeof(struct xen_dm_op_ioreq_server_range),
        [XEN_DMOP_set_ioreq_server_state]           = sizeof(struct xen_dm_op_set_ioreq_server_state),
        [XEN_DMOP_destroy_ioreq_server]             = sizeof(struct xen_dm_op_destroy_ioreq_server),
        [XEN_DMOP_set_irq_level]                    = sizeof(struct xen_dm_op_set_irq_level),
        [XEN_DMOP_nr_vcpus]                         = sizeof(struct xen_dm_op_nr_vcpus),
    };

    rc = rcu_lock_remote_domain_by_id(op_args->domid, &d);
    if ( rc )
        return rc;

    rc = xsm_dm_op(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    offset = offsetof(struct xen_dm_op, u);

    rc = -EFAULT;
    if ( op_args->buf[0].size < offset )
        goto out;

    if ( copy_from_guest_offset((void *)&op, op_args->buf[0].h, 0, offset) )
        goto out;

    if ( op.op >= ARRAY_SIZE(op_size) )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    op.op = array_index_nospec(op.op, ARRAY_SIZE(op_size));

    if ( op_args->buf[0].size < offset + op_size[op.op] )
        goto out;

    if ( copy_from_guest_offset((void *)&op.u, op_args->buf[0].h, offset,
                                op_size[op.op]) )
        goto out;

    rc = -EINVAL;
    if ( op.pad )
        goto out;

    switch ( op.op )
    {
    case XEN_DMOP_set_irq_level:
    {
        const struct xen_dm_op_set_irq_level *data =
            &op.u.set_irq_level;
        unsigned int i;

        /* Only SPIs are supported */
        if ( (data->irq < NR_LOCAL_IRQS) || (data->irq >= vgic_num_irqs(d)) )
        {
            rc = -EINVAL;
            break;
        }

        if ( data->level != 0 && data->level != 1 )
        {
            rc = -EINVAL;
            break;
        }

        /* Check that padding is always 0 */
        for ( i = 0; i < sizeof(data->pad); i++ )
        {
            if ( data->pad[i] )
            {
                rc = -EINVAL;
                break;
            }
        }

        /*
         * Allow to set the logical level of a line for non-allocated
         * interrupts only.
         */
        if ( test_bit(data->irq, d->arch.vgic.allocated_irqs) )
        {
            rc = -EINVAL;
            break;
        }

        vgic_inject_irq(d, NULL, data->irq, data->level);
        rc = 0;
        break;
    }

    case XEN_DMOP_nr_vcpus:
    {
        struct xen_dm_op_nr_vcpus *data = &op.u.nr_vcpus;

        data->vcpus = d->max_vcpus;
        const_op = false;
        rc = 0;
        break;
    }

    default:
        rc = ioreq_server_dm_op(&op, d, &const_op);
        break;
    }

    if ( (!rc || rc == -ERESTART) &&
         !const_op && copy_to_guest_offset(op_args->buf[0].h, offset,
                                           (void *)&op.u, op_size[op.op]) )
        rc = -EFAULT;

 out:
    rcu_unlock_domain(d);

    return rc;
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
