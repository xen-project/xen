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

#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/sched.h>

#include <asm/hap.h>
#include <asm/hvm/ioreq.h>
#include <asm/shadow.h>

#include <xsm/xsm.h>

struct dmop_args {
    domid_t domid;
    unsigned int nr_bufs;
    /* Reserve enough buf elements for all current hypercalls. */
    struct xen_dm_op_buf buf[2];
};

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

static bool _raw_copy_to_guest_buf_offset(const struct dmop_args *args,
                                          unsigned int buf_idx,
                                          size_t offset_bytes,
                                          const void *src,
                                          size_t src_bytes)
{
    size_t buf_bytes;

    if ( buf_idx >= args->nr_bufs )
        return false;

    buf_bytes = args->buf[buf_idx].size;


    if ( (offset_bytes + src_bytes) < offset_bytes ||
         (offset_bytes + src_bytes) > buf_bytes )
        return false;

    return !copy_to_guest_offset(args->buf[buf_idx].h, offset_bytes,
                                 src, src_bytes);
}

#define COPY_FROM_GUEST_BUF_OFFSET(dst, bufs, buf_idx, offset_bytes) \
    _raw_copy_from_guest_buf_offset(&(dst), bufs, buf_idx, offset_bytes, \
                                    sizeof(dst))

#define COPY_TO_GUEST_BUF_OFFSET(bufs, buf_idx, offset_bytes, src) \
    _raw_copy_to_guest_buf_offset(bufs, buf_idx, offset_bytes, \
                                  &(src), sizeof(src))

#define COPY_FROM_GUEST_BUF(dst, bufs, buf_idx) \
    COPY_FROM_GUEST_BUF_OFFSET(dst, bufs, buf_idx, 0)

#define COPY_TO_GUEST_BUF(bufs, buf_idx, src) \
    COPY_TO_GUEST_BUF_OFFSET(bufs, buf_idx, 0, src)

static int track_dirty_vram(struct domain *d, xen_pfn_t first_pfn,
                            unsigned int nr, const struct xen_dm_op_buf *buf)
{
    if ( nr > (GB(1) >> PAGE_SHIFT) )
        return -EINVAL;

    if ( d->is_dying )
        return -ESRCH;

    if ( !d->max_vcpus || !d->vcpu[0] )
        return -EINVAL;

    if ( ((nr + 7) / 8) > buf->size )
        return -EINVAL;

    return shadow_mode_enabled(d) ?
        shadow_track_dirty_vram(d, first_pfn, nr, buf->h) :
        hap_track_dirty_vram(d, first_pfn, nr, buf->h);
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
    if ( isa_irq > 15 )
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
                mfn_t gmfn = _mfn(page_to_mfn(page));

                paging_mark_dirty(d, gmfn);
                /*
                 * These are most probably not page tables any more
                 * don't take a long time and don't die either.
                 */
                sh_remove_shadows(d, gmfn, 1, 0);
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

    if ( data->mem_type  == HVMMEM_ioreq_server )
    {
        unsigned int flags;

        if ( !hap_enabled(d) )
            return -EOPNOTSUPP;

        /* Do not change to HVMMEM_ioreq_server if no ioreq server mapped. */
        if ( !p2m_get_ioreq_server(d, &flags) )
            return -EINVAL;
    }

    while ( iter < data->nr )
    {
        unsigned long pfn = data->first_pfn + iter;
        p2m_type_t t;

        get_gfn_unshare(d, pfn, &t);
        if ( p2m_is_paging(t) )
        {
            put_gfn(d, pfn);
            p2m_mem_paging_populate(d, pfn);
            return -EAGAIN;
        }

        if ( p2m_is_shared(t) )
            rc = -EAGAIN;
        else if ( !allow_p2m_type_change(t, memtype[data->mem_type]) )
            rc = -EINVAL;
        else
            rc = p2m_change_type_one(d, pfn, t, memtype[data->mem_type]);

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

    if ( cmpxchg(&v->arch.hvm_vcpu.inject_event.vector,
                 HVM_EVENT_VECTOR_UNSET, HVM_EVENT_VECTOR_UPDATING) !=
         HVM_EVENT_VECTOR_UNSET )
        return -EBUSY;

    v->arch.hvm_vcpu.inject_event.type = data->type;
    v->arch.hvm_vcpu.inject_event.insn_len = data->insn_len;
    v->arch.hvm_vcpu.inject_event.error_code = data->error_code;
    v->arch.hvm_vcpu.inject_event.cr2 = data->cr2;
    smp_wmb();
    v->arch.hvm_vcpu.inject_event.vector = data->vector;

    return 0;
}

static int dm_op(const struct dmop_args *op_args)
{
    struct domain *d;
    struct xen_dm_op op;
    bool const_op = true;
    long rc;

    rc = rcu_lock_remote_domain_by_id(op_args->domid, &d);
    if ( rc )
        return rc;

    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_dm_op(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    if ( !COPY_FROM_GUEST_BUF(op, op_args, 0) )
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

        rc = hvm_create_ioreq_server(d, curr_d->domain_id, false,
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
                                       &data->ioreq_gfn,
                                       &data->bufioreq_gfn,
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
            rc = hvm_map_mem_type_to_ioreq_server(d, data->id,
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

    default:
        rc = -EOPNOTSUPP;
        break;
    }

    if ( (!rc || rc == -ERESTART) &&
         !const_op && !COPY_TO_GUEST_BUF(op_args, 0, op) )
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
CHECK_dm_op_track_dirty_vram;
CHECK_dm_op_set_pci_intx_level;
CHECK_dm_op_set_isa_irq_level;
CHECK_dm_op_set_pci_link_route;
CHECK_dm_op_modified_memory;
CHECK_dm_op_set_mem_type;
CHECK_dm_op_inject_event;
CHECK_dm_op_inject_msi;
CHECK_dm_op_remote_shutdown;

int compat_dm_op(domid_t domid,
                 unsigned int nr_bufs,
                 XEN_GUEST_HANDLE_PARAM(void) bufs)
{
    struct dmop_args args;
    unsigned int i;
    int rc;

    if ( nr_bufs > ARRAY_SIZE(args.buf) )
        return -E2BIG;

    args.domid = domid;
    args.nr_bufs = nr_bufs;

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

long do_dm_op(domid_t domid,
              unsigned int nr_bufs,
              XEN_GUEST_HANDLE_PARAM(xen_dm_op_buf_t) bufs)
{
    struct dmop_args args;
    int rc;

    if ( nr_bufs > ARRAY_SIZE(args.buf) )
        return -E2BIG;

    args.domid = domid;
    args.nr_bufs = nr_bufs;

    if ( copy_from_guest_offset(&args.buf[0], bufs, 0, args.nr_bufs) )
        return -EFAULT;

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
