asm(".file \"" __FILE__ "\"");

#include <xen/types.h>
#include <xen/hypercall.h>
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/mem_access.h>
#include <asm/current.h>
#include <compat/memory.h>

#define xen_domid_t domid_t
#define compat_domid_t domid_compat_t
CHECK_TYPE(domid);
#undef compat_domid_t
#undef xen_domid_t

CHECK_vmemrange;

#ifdef CONFIG_HAS_PASSTHROUGH
struct get_reserved_device_memory {
    struct compat_reserved_device_memory_map map;
    unsigned int used_entries;
};

static int get_reserved_device_memory(xen_pfn_t start, xen_ulong_t nr,
                                      u32 id, void *ctxt)
{
    struct get_reserved_device_memory *grdm = ctxt;
    u32 sbdf = PCI_SBDF3(grdm->map.dev.pci.seg, grdm->map.dev.pci.bus,
                         grdm->map.dev.pci.devfn);

    if ( !(grdm->map.flags & XENMEM_RDM_ALL) && (sbdf != id) )
        return 0;

    if ( grdm->used_entries < grdm->map.nr_entries )
    {
        struct compat_reserved_device_memory rdm = {
            .start_pfn = start, .nr_pages = nr
        };

        if ( rdm.start_pfn != start || rdm.nr_pages != nr )
            return -ERANGE;

        if ( __copy_to_compat_offset(grdm->map.buffer, grdm->used_entries,
                                     &rdm, 1) )
            return -EFAULT;
    }

    ++grdm->used_entries;

    return 1;
}
#endif

int compat_memory_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) compat)
{
    int split, op = cmd & MEMOP_CMD_MASK;
    long rc;
    unsigned int start_extent = cmd >> MEMOP_EXTENT_SHIFT;

    do
    {
        unsigned int i, end_extent = 0;
        union {
            XEN_GUEST_HANDLE_PARAM(void) hnd;
            struct xen_memory_reservation *rsrv;
            struct xen_memory_exchange *xchg;
            struct xen_add_to_physmap *atp;
            struct xen_add_to_physmap_batch *atpb;
            struct xen_remove_from_physmap *xrfp;
            struct xen_vnuma_topology_info *vnuma;
            struct xen_mem_access_op *mao;
        } nat;
        union {
            struct compat_memory_reservation rsrv;
            struct compat_memory_exchange xchg;
            struct compat_add_to_physmap atp;
            struct compat_add_to_physmap_batch atpb;
            struct compat_vnuma_topology_info vnuma;
            struct compat_mem_access_op mao;
        } cmp;

        set_xen_guest_handle(nat.hnd, COMPAT_ARG_XLAT_VIRT_BASE);
        split = 0;
        switch ( op )
        {
            xen_pfn_t *space;

        case XENMEM_increase_reservation:
        case XENMEM_decrease_reservation:
        case XENMEM_populate_physmap:
            if ( copy_from_guest(&cmp.rsrv, compat, 1) )
                return start_extent;

            /* Is size too large for us to encode a continuation? */
            if ( cmp.rsrv.nr_extents > (UINT_MAX >> MEMOP_EXTENT_SHIFT) )
                return start_extent;

            if ( !compat_handle_is_null(cmp.rsrv.extent_start) &&
                 !compat_handle_okay(cmp.rsrv.extent_start, cmp.rsrv.nr_extents) )
                return start_extent;

            end_extent = start_extent + (COMPAT_ARG_XLAT_SIZE - sizeof(*nat.rsrv)) /
                                        sizeof(*space);
            if ( end_extent > cmp.rsrv.nr_extents )
                end_extent = cmp.rsrv.nr_extents;

            space = (xen_pfn_t *)(nat.rsrv + 1);
#define XLAT_memory_reservation_HNDL_extent_start(_d_, _s_) \
            do \
            { \
                if ( !compat_handle_is_null((_s_)->extent_start) ) \
                { \
                    set_xen_guest_handle((_d_)->extent_start, space - start_extent); \
                    if ( op != XENMEM_increase_reservation ) \
                    { \
                        for ( i = start_extent; i < end_extent; ++i ) \
                        { \
                            compat_pfn_t pfn; \
                            if ( __copy_from_compat_offset(&pfn, (_s_)->extent_start, i, 1) ) \
                            { \
                                end_extent = i; \
                                split = -1; \
                                break; \
                            } \
                            *space++ = pfn; \
                        } \
                    } \
                } \
                else \
                { \
                    set_xen_guest_handle((_d_)->extent_start, NULL); \
                    end_extent = cmp.rsrv.nr_extents; \
                } \
            } while (0)
            XLAT_memory_reservation(nat.rsrv, &cmp.rsrv);
#undef XLAT_memory_reservation_HNDL_extent_start

            if ( end_extent < cmp.rsrv.nr_extents )
            {
                nat.rsrv->nr_extents = end_extent;
                ++split;
            }

            break;

        case XENMEM_exchange:
        {
            int order_delta;

            if ( copy_from_guest(&cmp.xchg, compat, 1) )
                return -EFAULT;

            order_delta = cmp.xchg.out.extent_order - cmp.xchg.in.extent_order;
            /* Various sanity checks. */
            if ( (cmp.xchg.nr_exchanged > cmp.xchg.in.nr_extents) ||
                 (order_delta > 0 && (cmp.xchg.nr_exchanged & ((1U << order_delta) - 1))) ||
                 /* Sizes of input and output lists do not overflow an int? */
                 ((~0U >> cmp.xchg.in.extent_order) < cmp.xchg.in.nr_extents) ||
                 ((~0U >> cmp.xchg.out.extent_order) < cmp.xchg.out.nr_extents) ||
                 /* Sizes of input and output lists match? */
                 ((cmp.xchg.in.nr_extents << cmp.xchg.in.extent_order) !=
                  (cmp.xchg.out.nr_extents << cmp.xchg.out.extent_order)) )
                return -EINVAL;

            if ( !compat_handle_okay(cmp.xchg.in.extent_start,
                                     cmp.xchg.in.nr_extents) ||
                 !compat_handle_okay(cmp.xchg.out.extent_start,
                                     cmp.xchg.out.nr_extents) )
                return -EFAULT;

            start_extent = cmp.xchg.nr_exchanged;
            end_extent = (COMPAT_ARG_XLAT_SIZE - sizeof(*nat.xchg)) /
                         (((1U << ABS(order_delta)) + 1) *
                          sizeof(*space));
            if ( end_extent == 0 )
            {
                printk("Cannot translate compatibility mode XENMEM_exchange extents (%u,%u)\n",
                       cmp.xchg.in.extent_order, cmp.xchg.out.extent_order);
                return -E2BIG;
            }
            if ( order_delta > 0 )
                end_extent <<= order_delta;
            end_extent += start_extent;
            if ( end_extent > cmp.xchg.in.nr_extents )
                end_extent = cmp.xchg.in.nr_extents;

            space = (xen_pfn_t *)(nat.xchg + 1);
            /* Code below depends upon .in preceding .out. */
            BUILD_BUG_ON(offsetof(xen_memory_exchange_t, in) > offsetof(xen_memory_exchange_t, out));
#define XLAT_memory_reservation_HNDL_extent_start(_d_, _s_) \
            do \
            { \
                set_xen_guest_handle((_d_)->extent_start, space - start_extent); \
                for ( i = start_extent; i < end_extent; ++i ) \
                { \
                    compat_pfn_t pfn; \
                    if ( __copy_from_compat_offset(&pfn, (_s_)->extent_start, i, 1) ) \
                        return -EFAULT; \
                    *space++ = pfn; \
                } \
                if ( order_delta > 0 ) \
                { \
                    start_extent >>= order_delta; \
                    end_extent >>= order_delta; \
                } \
                else \
                { \
                    start_extent <<= -order_delta; \
                    end_extent <<= -order_delta; \
                } \
                order_delta = -order_delta; \
            } while (0)
            XLAT_memory_exchange(nat.xchg, &cmp.xchg);
#undef XLAT_memory_reservation_HNDL_extent_start

            if ( end_extent < cmp.xchg.in.nr_extents )
            {
                nat.xchg->in.nr_extents = end_extent;
                if ( order_delta >= 0 )
                    nat.xchg->out.nr_extents = end_extent >> order_delta;
                else
                    nat.xchg->out.nr_extents = end_extent << -order_delta;
                ++split;
            }

            break;
        }

        case XENMEM_current_reservation:
        case XENMEM_maximum_reservation:
        case XENMEM_maximum_gpfn:
        case XENMEM_maximum_ram_page:
            nat.hnd = compat;
            break;

        case XENMEM_add_to_physmap:
            BUILD_BUG_ON((typeof(cmp.atp.size))-1 >
                         (UINT_MAX >> MEMOP_EXTENT_SHIFT));

            if ( copy_from_guest(&cmp.atp, compat, 1) )
                return -EFAULT;

            XLAT_add_to_physmap(nat.atp, &cmp.atp);

            break;

        case XENMEM_add_to_physmap_batch:
        {
            unsigned int limit = (COMPAT_ARG_XLAT_SIZE - sizeof(*nat.atpb))
                                 / (sizeof(nat.atpb->idxs.p) + sizeof(nat.atpb->gpfns.p));
            /* Use an intermediate variable to suppress warnings on old gcc: */
            unsigned int size = cmp.atpb.size;
            xen_ulong_t *idxs = (void *)(nat.atpb + 1);
            xen_pfn_t *gpfns = (void *)(idxs + limit);
            /*
             * The union will always be 16-bit width. So it is not
             * necessary to have the exact field which correspond to the
             * space.
             */
            enum XLAT_add_to_physmap_batch_u u =
                XLAT_add_to_physmap_batch_u_res0;

            if ( copy_from_guest(&cmp.atpb, compat, 1) ||
                 !compat_handle_okay(cmp.atpb.idxs, size) ||
                 !compat_handle_okay(cmp.atpb.gpfns, size) ||
                 !compat_handle_okay(cmp.atpb.errs, size) )
                return -EFAULT;

            end_extent = start_extent + limit;
            if ( end_extent > size )
                end_extent = size;

            idxs -= start_extent;
            gpfns -= start_extent;

            for ( i = start_extent; i < end_extent; ++i )
            {
                compat_ulong_t idx;
                compat_pfn_t gpfn;

                if ( __copy_from_compat_offset(&idx, cmp.atpb.idxs, i, 1) ||
                     __copy_from_compat_offset(&gpfn, cmp.atpb.gpfns, i, 1) )
                    return -EFAULT;
                idxs[i] = idx;
                gpfns[i] = gpfn;
            }

#define XLAT_add_to_physmap_batch_HNDL_idxs(_d_, _s_) \
            set_xen_guest_handle((_d_)->idxs, idxs)
#define XLAT_add_to_physmap_batch_HNDL_gpfns(_d_, _s_) \
            set_xen_guest_handle((_d_)->gpfns, gpfns)
#define XLAT_add_to_physmap_batch_HNDL_errs(_d_, _s_) \
            guest_from_compat_handle((_d_)->errs, (_s_)->errs)

            XLAT_add_to_physmap_batch(nat.atpb, &cmp.atpb);

#undef XLAT_add_to_physmap_batch_HNDL_errs
#undef XLAT_add_to_physmap_batch_HNDL_gpfns
#undef XLAT_add_to_physmap_batch_HNDL_idxs

            if ( end_extent < cmp.atpb.size )
            {
                nat.atpb->size = end_extent;
                ++split;
            }

            break;
        }

        case XENMEM_remove_from_physmap:
        {
            struct compat_remove_from_physmap cmp;

            if ( copy_from_guest(&cmp, compat, 1) )
                return -EFAULT;

            XLAT_remove_from_physmap(nat.xrfp, &cmp);

            break;
        }

        case XENMEM_access_op:
            if ( copy_from_guest(&cmp.mao, compat, 1) )
                return -EFAULT;
            
#define XLAT_mem_access_op_HNDL_pfn_list(_d_, _s_)                      \
            guest_from_compat_handle((_d_)->pfn_list, (_s_)->pfn_list)
#define XLAT_mem_access_op_HNDL_access_list(_d_, _s_)                   \
            guest_from_compat_handle((_d_)->access_list, (_s_)->access_list)
            
            XLAT_mem_access_op(nat.mao, &cmp.mao);
            
#undef XLAT_mem_access_op_HNDL_pfn_list
#undef XLAT_mem_access_op_HNDL_access_list
            
            break;

        case XENMEM_get_vnumainfo:
        {
            enum XLAT_vnuma_topology_info_vdistance vdistance =
                XLAT_vnuma_topology_info_vdistance_h;
            enum XLAT_vnuma_topology_info_vcpu_to_vnode vcpu_to_vnode =
                XLAT_vnuma_topology_info_vcpu_to_vnode_h;
            enum XLAT_vnuma_topology_info_vmemrange vmemrange =
                XLAT_vnuma_topology_info_vmemrange_h;

            if ( copy_from_guest(&cmp.vnuma, compat, 1) )
                return -EFAULT;

#define XLAT_vnuma_topology_info_HNDL_vdistance_h(_d_, _s_)		\
            guest_from_compat_handle((_d_)->vdistance.h, (_s_)->vdistance.h)
#define XLAT_vnuma_topology_info_HNDL_vcpu_to_vnode_h(_d_, _s_)		\
            guest_from_compat_handle((_d_)->vcpu_to_vnode.h, (_s_)->vcpu_to_vnode.h)
#define XLAT_vnuma_topology_info_HNDL_vmemrange_h(_d_, _s_)		\
            guest_from_compat_handle((_d_)->vmemrange.h, (_s_)->vmemrange.h)

            XLAT_vnuma_topology_info(nat.vnuma, &cmp.vnuma);

#undef XLAT_vnuma_topology_info_HNDL_vdistance_h
#undef XLAT_vnuma_topology_info_HNDL_vcpu_to_vnode_h
#undef XLAT_vnuma_topology_info_HNDL_vmemrange_h
            break;
        }

#ifdef CONFIG_HAS_PASSTHROUGH
        case XENMEM_reserved_device_memory_map:
        {
            struct get_reserved_device_memory grdm;

            if ( unlikely(start_extent) )
                return -EINVAL;

            if ( copy_from_guest(&grdm.map, compat, 1) ||
                 !compat_handle_okay(grdm.map.buffer, grdm.map.nr_entries) )
                return -EFAULT;

            if ( grdm.map.flags & ~XENMEM_RDM_ALL )
                return -EINVAL;

            grdm.used_entries = 0;
            rc = iommu_get_reserved_device_memory(get_reserved_device_memory,
                                                  &grdm);

            if ( !rc && grdm.map.nr_entries < grdm.used_entries )
                rc = -ENOBUFS;
            grdm.map.nr_entries = grdm.used_entries;
            if ( __copy_to_guest(compat, &grdm.map, 1) )
                rc = -EFAULT;

            return rc;
        }
#endif

        default:
            return compat_arch_memory_op(cmd, compat);
        }

        rc = do_memory_op(cmd, nat.hnd);
        if ( rc < 0 )
        {
            if ( rc == -ENOBUFS && op == XENMEM_get_vnumainfo )
            {
                cmp.vnuma.nr_vnodes = nat.vnuma->nr_vnodes;
                cmp.vnuma.nr_vcpus = nat.vnuma->nr_vcpus;
                cmp.vnuma.nr_vmemranges = nat.vnuma->nr_vmemranges;
                if ( __copy_to_guest(compat, &cmp.vnuma, 1) )
                    rc = -EFAULT;
            }
            break;
        }

        cmd = 0;
        if ( hypercall_xlat_continuation(&cmd, 2, 0x02, nat.hnd, compat) )
        {
            BUG_ON(rc != __HYPERVISOR_memory_op);
            BUG_ON((cmd & MEMOP_CMD_MASK) != op);
            split = -1;
        }

        switch ( op )
        {
        case XENMEM_increase_reservation:
        case XENMEM_decrease_reservation:
        case XENMEM_populate_physmap:
            end_extent = split >= 0 ? rc : cmd >> MEMOP_EXTENT_SHIFT;
            if ( (op != XENMEM_decrease_reservation) &&
                 !guest_handle_is_null(nat.rsrv->extent_start) )
            {
                for ( ; start_extent < end_extent; ++start_extent )
                {
                    compat_pfn_t pfn = nat.rsrv->extent_start.p[start_extent];

                    BUG_ON(pfn != nat.rsrv->extent_start.p[start_extent]);
                    if ( __copy_to_compat_offset(cmp.rsrv.extent_start,
                                                 start_extent, &pfn, 1) )
                    {
                        if ( split >= 0 )
                        {
                            rc = start_extent;
                            split = 0;
                        }
                        else
                            /*
                             * Short of being able to cancel the continuation,
                             * force it to restart here; eventually we shall
                             * get out of this state.
                             */
                            rc = (start_extent << MEMOP_EXTENT_SHIFT) | op;
                        break;
                    }
                }
            }
            else
            {
                start_extent = end_extent;
            }
            /* Bail if there was an error. */
            if ( (split >= 0) && (end_extent != nat.rsrv->nr_extents) )
                split = 0;
            break;

        case XENMEM_exchange:
        {
            DEFINE_XEN_GUEST_HANDLE(compat_memory_exchange_t);
            int order_delta;

            BUG_ON(split >= 0 && rc);
            BUG_ON(end_extent < nat.xchg->nr_exchanged);
            end_extent = nat.xchg->nr_exchanged;

            order_delta = cmp.xchg.out.extent_order - cmp.xchg.in.extent_order;
            if ( order_delta > 0 )
            {
                start_extent >>= order_delta;
                BUG_ON(end_extent & ((1U << order_delta) - 1));
                end_extent >>= order_delta;
            }
            else
            {
                start_extent <<= -order_delta;
                end_extent <<= -order_delta;
            }

            for ( ; start_extent < end_extent; ++start_extent )
            {
                compat_pfn_t pfn = nat.xchg->out.extent_start.p[start_extent];

                BUG_ON(pfn != nat.xchg->out.extent_start.p[start_extent]);
                if ( __copy_to_compat_offset(cmp.xchg.out.extent_start,
                                             start_extent, &pfn, 1) )
                {
                    rc = -EFAULT;
                    break;
                }
            }

            cmp.xchg.nr_exchanged = nat.xchg->nr_exchanged;
            if ( __copy_field_to_guest(guest_handle_cast(compat,
                                                         compat_memory_exchange_t),
                                       &cmp.xchg, nr_exchanged) )
                rc = -EFAULT;

            if ( rc < 0 )
            {
                if ( split < 0 )
                    /* Cannot cancel the continuation... */
                    domain_crash(current->domain);
                return rc;
            }
            break;
        }

        case XENMEM_add_to_physmap_batch:
            start_extent = end_extent;
            break;

        case XENMEM_maximum_ram_page:
        case XENMEM_current_reservation:
        case XENMEM_maximum_reservation:
        case XENMEM_maximum_gpfn:
        case XENMEM_add_to_physmap:
        case XENMEM_remove_from_physmap:
        case XENMEM_access_op:
            break;

        case XENMEM_get_vnumainfo:
            cmp.vnuma.nr_vnodes = nat.vnuma->nr_vnodes;
            cmp.vnuma.nr_vcpus = nat.vnuma->nr_vcpus;
            cmp.vnuma.nr_vmemranges = nat.vnuma->nr_vmemranges;
            if ( __copy_to_guest(compat, &cmp.vnuma, 1) )
                rc = -EFAULT;
            break;

        default:
            domain_crash(current->domain);
            split = 0;
            break;
        }

        cmd = op | (start_extent << MEMOP_EXTENT_SHIFT);
        if ( split > 0 && hypercall_preempt_check() )
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "ih", cmd, compat);
    } while ( split > 0 );

    if ( unlikely(rc > INT_MAX) )
        return INT_MAX;

    if ( unlikely(rc < INT_MIN) )
        return INT_MIN;

    return rc;
}
