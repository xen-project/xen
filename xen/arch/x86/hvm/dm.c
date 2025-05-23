/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2016 Citrix Systems Inc.
 */

#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/dm.h>
#include <xen/hypercall.h>
#include <xen/ioreq.h>
#include <xen/nospec.h>
#include <xen/sched.h>

#include <asm/hap.h>
#include <asm/hvm/cacheattr.h>
#include <asm/shadow.h>

#include <xsm/xsm.h>

#include <public/hvm/hvm_op.h>

static bool _raw_copy_from_guest_buf_offset(void *dst,
                                            const struct dmop_args *args,
                                            unsigned int buf_idx,
                                            size_t offset_bytes,
                                            size_t dst_bytes)
{
    size_t buf_bytes;

    if ( buf_idx >= args->nr_bufs )
        return false;

    buf_bytes =  args->buf[buf_idx].size;

    if ( (offset_bytes + dst_bytes) < offset_bytes ||
         (offset_bytes + dst_bytes) > buf_bytes )
        return false;

    return !copy_from_guest_offset(dst, args->buf[buf_idx].h,
                                   offset_bytes, dst_bytes);
}

#define COPY_FROM_GUEST_BUF_OFFSET(dst, bufs, buf_idx, offset_bytes) \
    _raw_copy_from_guest_buf_offset(&(dst), bufs, buf_idx, offset_bytes, \
                                    sizeof(dst))

static int track_dirty_vram(struct domain *d, xen_pfn_t first_pfn,
                            unsigned int nr_frames,
                            const struct xen_dm_op_buf *buf)
{
    if ( nr_frames > (GB(1) >> PAGE_SHIFT) )
        return -EINVAL;

    if ( d->is_dying )
        return -ESRCH;

    if ( !d->max_vcpus || !d->vcpu[0] )
        return -EINVAL;

    if ( DIV_ROUND_UP(nr_frames, BITS_PER_BYTE) > buf->size )
        return -EINVAL;

    return shadow_mode_enabled(d)
        ? shadow_track_dirty_vram(d, first_pfn, nr_frames, buf->h)
        :    hap_track_dirty_vram(d, first_pfn, nr_frames, buf->h);
}

static int set_pci_intx_level(struct domain *d, uint16_t domain,
                              uint8_t bus, uint8_t device,
                              uint8_t intx, uint8_t level)
{
    if ( domain != 0 || bus != 0 || device > 0x1f || intx > 3 )
        return -EINVAL;

    switch ( level )
    {
    case 0:
        hvm_pci_intx_deassert(d, device, intx);
        break;
    case 1:
        hvm_pci_intx_assert(d, device, intx);
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int set_isa_irq_level(struct domain *d, uint8_t isa_irq,
                             uint8_t level)
{
    if ( isa_irq >= NR_ISA_IRQS )
        return -EINVAL;

    switch ( level )
    {
    case 0:
        hvm_isa_irq_deassert(d, isa_irq);
        break;
    case 1:
        hvm_isa_irq_assert(d, isa_irq, NULL);
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int modified_memory(struct domain *d,
                           const struct dmop_args *bufs,
                           struct xen_dm_op_modified_memory *header)
{
#define EXTENTS_BUFFER 1

    /* Process maximum of 256 pfns before checking for continuation. */
    const unsigned int cont_check_interval = 0x100;
    unsigned int *rem_extents =  &header->nr_extents;
    unsigned int batch_rem_pfns = cont_check_interval;
    /* Used for continuation. */
    unsigned int *pfns_done = &header->opaque;

    if ( !paging_mode_log_dirty(d) )
        return 0;

    if ( (bufs->buf[EXTENTS_BUFFER].size /
          sizeof(struct xen_dm_op_modified_memory_extent)) <
         *rem_extents )
        return -EINVAL;

    while ( *rem_extents > 0 )
    {
        struct xen_dm_op_modified_memory_extent extent;
        unsigned int batch_nr;
        xen_pfn_t pfn, end_pfn;

        if ( !COPY_FROM_GUEST_BUF_OFFSET(extent, bufs, EXTENTS_BUFFER,
                                         (*rem_extents - 1) * sizeof(extent)) )
            return -EFAULT;

        if ( extent.pad )
            return -EINVAL;

        end_pfn = extent.first_pfn + extent.nr;

        if ( end_pfn <= extent.first_pfn ||
             end_pfn > domain_get_maximum_gpfn(d) )
            return -EINVAL;

        if ( *pfns_done >= extent.nr )
            return -EINVAL;

        pfn = extent.first_pfn + *pfns_done;
        batch_nr = extent.nr - *pfns_done;

        if ( batch_nr > batch_rem_pfns )
        {
            batch_nr = batch_rem_pfns;
            *pfns_done += batch_nr;
            end_pfn = pfn + batch_nr;
        }
        else
        {
            (*rem_extents)--;
            *pfns_done = 0;
        }

        batch_rem_pfns -= batch_nr;

        for ( ; pfn < end_pfn; pfn++ )
        {
            struct page_info *page;

            page = get_page_from_gfn(d, pfn, NULL, P2M_UNSHARE);
            if ( page )
            {
                paging_mark_pfn_dirty(d, _pfn(pfn));
                /*
                 * These are most probably not page tables any more
                 * don't take a long time and don't die either.
                 */
                sh_remove_shadows(d, page_to_mfn(page), 1, 0);
                put_page(page);
            }
        }

        /*
         * After a full batch of cont_check_interval pfns
         * have been processed, and there are still extents
         * remaining to process, check for continuation.
         */
        if ( (batch_rem_pfns == 0) && (*rem_extents > 0) )
        {
            if ( hypercall_preempt_check() )
                return -ERESTART;

            batch_rem_pfns = cont_check_interval;
        }
    }
    return 0;

#undef EXTENTS_BUFFER
}

static bool allow_p2m_type_change(p2m_type_t old, p2m_type_t new)
{
    if ( new == p2m_ioreq_server )
        return old == p2m_ram_rw;

    if ( old == p2m_ioreq_server )
        return new == p2m_ram_rw;

    return p2m_is_ram(old) ||
           (p2m_is_hole(old) && new == p2m_mmio_dm);
}

static int set_mem_type(struct domain *d,
                        struct xen_dm_op_set_mem_type *data)
{
    xen_pfn_t last_pfn = data->first_pfn + data->nr - 1;
    unsigned int iter = 0;
    p2m_type_t nt;
    int rc = 0;

    /* Interface types to internal p2m types */
    static const p2m_type_t memtype[] = {
        [HVMMEM_ram_rw]  = p2m_ram_rw,
        [HVMMEM_ram_ro]  = p2m_ram_ro,
        [HVMMEM_mmio_dm] = p2m_mmio_dm,
        [HVMMEM_unused] = p2m_invalid,
        [HVMMEM_ioreq_server] = p2m_ioreq_server,
    };

    if ( (data->first_pfn > last_pfn) ||
         (last_pfn > domain_get_maximum_gpfn(d)) )
        return -EINVAL;

    if ( data->mem_type >= ARRAY_SIZE(memtype) ||
         unlikely(data->mem_type == HVMMEM_unused) )
        return -EINVAL;

    nt = array_access_nospec(memtype, data->mem_type);

    if ( nt == p2m_ioreq_server )
    {
        unsigned int flags;

        if ( !hap_enabled(d) )
            return -EOPNOTSUPP;

        /* Do not change to p2m_ioreq_server if no ioreq server mapped. */
        if ( !p2m_get_ioreq_server(d, &flags) )
            return -EINVAL;
    }

    while ( iter < data->nr )
    {
        unsigned long pfn = data->first_pfn + iter;
        p2m_type_t ot;

        get_gfn_unshare(d, pfn, &ot);
        if ( p2m_is_paging(ot) )
        {
            put_gfn(d, pfn);
            p2m_mem_paging_populate(d, _gfn(pfn));
            return -EAGAIN;
        }

        if ( p2m_is_shared(ot) )
            rc = -EAGAIN;
        else if ( !allow_p2m_type_change(ot, nt) )
            rc = -EINVAL;
        else
            rc = p2m_change_type_one(d, pfn, ot, nt);

        put_gfn(d, pfn);

        if ( rc )
            break;

        iter++;

        /*
         * Check for continuation every 256th iteration and if the
         * iteration is not the last.
         */
        if ( (iter < data->nr) && ((iter & 0xff) == 0) &&
             hypercall_preempt_check() )
        {
            data->first_pfn += iter;
            data->nr -= iter;

            rc = -ERESTART;
            break;
        }
    }

    return rc;
}

static int inject_event(struct domain *d,
                        const struct xen_dm_op_inject_event *data)
{
    struct vcpu *v;

    if ( data->vcpuid >= d->max_vcpus || !(v = d->vcpu[data->vcpuid]) )
        return -EINVAL;

    if ( cmpxchg(&v->arch.hvm.inject_event.vector,
                 HVM_EVENT_VECTOR_UNSET, HVM_EVENT_VECTOR_UPDATING) !=
         HVM_EVENT_VECTOR_UNSET )
        return -EBUSY;

    v->arch.hvm.inject_event.type = data->type;
    v->arch.hvm.inject_event.insn_len = data->insn_len;
    v->arch.hvm.inject_event.error_code = data->error_code;
    v->arch.hvm.inject_event.cr2 = data->cr2;
    smp_wmb();
    v->arch.hvm.inject_event.vector = data->vector;

    return 0;
}

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
        [XEN_DMOP_track_dirty_vram]                 = sizeof(struct xen_dm_op_track_dirty_vram),
        [XEN_DMOP_set_pci_intx_level]               = sizeof(struct xen_dm_op_set_pci_intx_level),
        [XEN_DMOP_set_isa_irq_level]                = sizeof(struct xen_dm_op_set_isa_irq_level),
        [XEN_DMOP_set_pci_link_route]               = sizeof(struct xen_dm_op_set_pci_link_route),
        [XEN_DMOP_modified_memory]                  = sizeof(struct xen_dm_op_modified_memory),
        [XEN_DMOP_set_mem_type]                     = sizeof(struct xen_dm_op_set_mem_type),
        [XEN_DMOP_inject_event]                     = sizeof(struct xen_dm_op_inject_event),
        [XEN_DMOP_inject_msi]                       = sizeof(struct xen_dm_op_inject_msi),
        [XEN_DMOP_map_mem_type_to_ioreq_server]     = sizeof(struct xen_dm_op_map_mem_type_to_ioreq_server),
        [XEN_DMOP_remote_shutdown]                  = sizeof(struct xen_dm_op_remote_shutdown),
        [XEN_DMOP_relocate_memory]                  = sizeof(struct xen_dm_op_relocate_memory),
        [XEN_DMOP_pin_memory_cacheattr]             = sizeof(struct xen_dm_op_pin_memory_cacheattr),
        [XEN_DMOP_nr_vcpus]                         = sizeof(struct xen_dm_op_nr_vcpus),
    };

    rc = rcu_lock_remote_domain_by_id(op_args->domid, &d);
    if ( rc )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

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
    case XEN_DMOP_map_mem_type_to_ioreq_server:
    {
        struct xen_dm_op_map_mem_type_to_ioreq_server *data =
            &op.u.map_mem_type_to_ioreq_server;
        unsigned long first_gfn = data->opaque;

        const_op = false;

        rc = -EOPNOTSUPP;
        if ( !hap_enabled(d) )
            break;

        if ( first_gfn == 0 )
            rc = ioreq_server_map_mem_type(d, data->id,
                                           data->type, data->flags);
        else
            rc = 0;

        /*
         * Iterate p2m table when an ioreq server unmaps from p2m_ioreq_server,
         * and reset the remaining p2m_ioreq_server entries back to p2m_ram_rw.
         */
        if ( rc == 0 && data->flags == 0 )
        {
            struct p2m_domain *p2m = p2m_get_hostp2m(d);

            while ( read_atomic(&p2m->ioreq.entry_count) &&
                    first_gfn <= p2m->max_mapped_pfn )
            {
                /* Iterate p2m table for 256 gfns each time. */
                rc = p2m_finish_type_change(d, _gfn(first_gfn), 256);
                if ( rc < 0 )
                    break;

                first_gfn += 256;

                /* Check for continuation if it's not the last iteration. */
                if ( first_gfn <= p2m->max_mapped_pfn &&
                     hypercall_preempt_check() )
                {
                    rc = -ERESTART;
                    data->opaque = first_gfn;
                    break;
                }
            }
        }

        break;
    }

    case XEN_DMOP_track_dirty_vram:
    {
        const struct xen_dm_op_track_dirty_vram *data =
            &op.u.track_dirty_vram;

        rc = -EINVAL;
        if ( data->pad )
            break;

        if ( op_args->nr_bufs < 2 )
            break;

        rc = track_dirty_vram(d, data->first_pfn, data->nr, &op_args->buf[1]);
        break;
    }

    case XEN_DMOP_set_pci_intx_level:
    {
        const struct xen_dm_op_set_pci_intx_level *data =
            &op.u.set_pci_intx_level;

        rc = set_pci_intx_level(d, data->domain, data->bus,
                                data->device, data->intx,
                                data->level);
        break;
    }

    case XEN_DMOP_set_isa_irq_level:
    {
        const struct xen_dm_op_set_isa_irq_level *data =
            &op.u.set_isa_irq_level;

        rc = set_isa_irq_level(d, data->isa_irq, data->level);
        break;
    }

    case XEN_DMOP_set_pci_link_route:
    {
        const struct xen_dm_op_set_pci_link_route *data =
            &op.u.set_pci_link_route;

        rc = hvm_set_pci_link_route(d, data->link, data->isa_irq);
        break;
    }

    case XEN_DMOP_modified_memory:
    {
        struct xen_dm_op_modified_memory *data =
            &op.u.modified_memory;

        rc = modified_memory(d, op_args, data);
        const_op = !rc;
        break;
    }

    case XEN_DMOP_set_mem_type:
    {
        struct xen_dm_op_set_mem_type *data =
            &op.u.set_mem_type;

        const_op = false;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = set_mem_type(d, data);
        break;
    }

    case XEN_DMOP_inject_event:
    {
        const struct xen_dm_op_inject_event *data =
            &op.u.inject_event;

        rc = -EINVAL;
        if ( data->pad0 || data->pad1 )
            break;

        rc = inject_event(d, data);
        break;
    }

    case XEN_DMOP_inject_msi:
    {
        const struct xen_dm_op_inject_msi *data =
            &op.u.inject_msi;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = hvm_inject_msi(d, data->addr, data->data);
        break;
    }

    case XEN_DMOP_remote_shutdown:
    {
        const struct xen_dm_op_remote_shutdown *data =
            &op.u.remote_shutdown;

        domain_shutdown(d, data->reason);
        rc = 0;
        break;
    }

    case XEN_DMOP_relocate_memory:
    {
        struct xen_dm_op_relocate_memory *data = &op.u.relocate_memory;
        struct xen_add_to_physmap xatp = {
            .domid = op_args->domid,
            .size = data->size,
            .space = XENMAPSPACE_gmfn_range,
            .idx = data->src_gfn,
            .gpfn = data->dst_gfn,
        };

        if ( data->pad )
        {
            rc = -EINVAL;
            break;
        }

        rc = xenmem_add_to_physmap(d, &xatp, 0);
        if ( rc == 0 && data->size != xatp.size )
            rc = xatp.size;
        if ( rc > 0 )
        {
            data->size -= rc;
            data->src_gfn += rc;
            data->dst_gfn += rc;
            const_op = false;
            rc = -ERESTART;
        }
        break;
    }

    case XEN_DMOP_pin_memory_cacheattr:
    {
        const struct xen_dm_op_pin_memory_cacheattr *data =
            &op.u.pin_memory_cacheattr;

        if ( data->pad )
        {
            rc = -EINVAL;
            break;
        }

        rc = hvm_set_mem_pinned_cacheattr(d, data->start, data->end,
                                          data->type);
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

#include <compat/hvm/dm_op.h>

CHECK_dm_op_create_ioreq_server;
CHECK_dm_op_get_ioreq_server_info;
CHECK_dm_op_ioreq_server_range;
CHECK_dm_op_set_ioreq_server_state;
CHECK_dm_op_destroy_ioreq_server;
CHECK_dm_op_track_dirty_vram;
CHECK_dm_op_set_pci_intx_level;
CHECK_dm_op_set_isa_irq_level;
CHECK_dm_op_set_pci_link_route;
CHECK_dm_op_modified_memory;
CHECK_dm_op_set_mem_type;
CHECK_dm_op_inject_event;
CHECK_dm_op_inject_msi;
CHECK_dm_op_map_mem_type_to_ioreq_server;
CHECK_dm_op_remote_shutdown;
CHECK_dm_op_relocate_memory;
CHECK_dm_op_pin_memory_cacheattr;
CHECK_dm_op_nr_vcpus;

int compat_dm_op(
    domid_t domid, unsigned int nr_bufs, XEN_GUEST_HANDLE_PARAM(void) bufs)
{
    struct dmop_args args;
    unsigned int i;
    int rc;

    if ( nr_bufs > ARRAY_SIZE(args.buf) )
        return -E2BIG;

    args.domid = domid;
    args.nr_bufs = array_index_nospec(nr_bufs, ARRAY_SIZE(args.buf) + 1);

    for ( i = 0; i < args.nr_bufs; i++ )
    {
        struct compat_dm_op_buf cmp;

        if ( copy_from_guest_offset(&cmp, bufs, i, 1) )
            return -EFAULT;

#define XLAT_dm_op_buf_HNDL_h(_d_, _s_) \
        guest_from_compat_handle((_d_)->h, (_s_)->h)

        XLAT_dm_op_buf(&args.buf[i], &cmp);

#undef XLAT_dm_op_buf_HNDL_h
    }

    rc = dm_op(&args);

    if ( rc == -ERESTART )
        rc = hypercall_create_continuation(__HYPERVISOR_dm_op, "iih",
                                           domid, nr_bufs, bufs);

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
