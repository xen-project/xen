#ifdef CONFIG_COMPAT

#include <xen/event.h>
#include <xen/multicall.h>
#include <compat/memory.h>
#include <compat/xen.h>

int compat_set_gdt(XEN_GUEST_HANDLE(uint) frame_list, unsigned int entries)
{
    unsigned int i, nr_pages = (entries + 511) / 512;
    unsigned long frames[16];
    long ret;

    /* Rechecked in set_gdt, but ensures a sane limit for copy_from_user(). */
    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    if ( !guest_handle_okay(frame_list, nr_pages) )
        return -EFAULT;

    for ( i = 0; i < nr_pages; ++i )
    {
        unsigned int frame;

        if ( __copy_from_guest(&frame, frame_list, 1) )
            return -EFAULT;
        frames[i] = frame;
        guest_handle_add_offset(frame_list, 1);
    }

    LOCK_BIGLOCK(current->domain);

    if ( (ret = set_gdt(current, frames, entries)) == 0 )
        local_flush_tlb();

    UNLOCK_BIGLOCK(current->domain);

    return ret;
}

int compat_update_descriptor(u32 pa_lo, u32 pa_hi, u32 desc_lo, u32 desc_hi)
{
    return do_update_descriptor(pa_lo | ((u64)pa_hi << 32),
                                desc_lo | ((u64)desc_hi << 32));
}

int compat_arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    struct compat_machphys_mfn_list xmml;
    l2_pgentry_t l2e;
    unsigned long v;
    compat_pfn_t mfn;
    unsigned int i;
    int rc = 0;

    switch ( op )
    {
    case XENMEM_add_to_physmap:
    {
        struct compat_add_to_physmap cmp;
        struct xen_add_to_physmap *nat = (void *)COMPAT_ARG_XLAT_VIRT_START(current->vcpu_id);

        if ( copy_from_guest(&cmp, arg, 1) )
            return -EFAULT;

        XLAT_add_to_physmap(nat, &cmp);
        rc = arch_memory_op(op, guest_handle_from_ptr(nat, void));

        break;
    }

    case XENMEM_set_memory_map:
    {
        struct compat_foreign_memory_map cmp;
        struct xen_foreign_memory_map *nat = (void *)COMPAT_ARG_XLAT_VIRT_START(current->vcpu_id);

        if ( copy_from_guest(&cmp, arg, 1) )
            return -EFAULT;

#define XLAT_memory_map_HNDL_buffer(_d_, _s_) \
        guest_from_compat_handle((_d_)->buffer, (_s_)->buffer)
        XLAT_foreign_memory_map(nat, &cmp);
#undef XLAT_memory_map_HNDL_buffer

        rc = arch_memory_op(op, guest_handle_from_ptr(nat, void));

        break;
    }

    case XENMEM_memory_map:
    case XENMEM_machine_memory_map:
    {
        struct compat_memory_map cmp;
        struct xen_memory_map *nat = (void *)COMPAT_ARG_XLAT_VIRT_START(current->vcpu_id);

        if ( copy_from_guest(&cmp, arg, 1) )
            return -EFAULT;

#define XLAT_memory_map_HNDL_buffer(_d_, _s_) \
        guest_from_compat_handle((_d_)->buffer, (_s_)->buffer)
        XLAT_memory_map(nat, &cmp);
#undef XLAT_memory_map_HNDL_buffer

        rc = arch_memory_op(op, guest_handle_from_ptr(nat, void));
        if ( rc < 0 )
            break;

#define XLAT_memory_map_HNDL_buffer(_d_, _s_) ((void)0)
        XLAT_memory_map(&cmp, nat);
#undef XLAT_memory_map_HNDL_buffer
        if ( copy_to_guest(arg, &cmp, 1) )
            rc = -EFAULT;

        break;
    }

    case XENMEM_machphys_mapping:
    {
        struct domain *d = current->domain;
        struct compat_machphys_mapping mapping = {
            .v_start = MACH2PHYS_COMPAT_VIRT_START(d),
            .v_end   = MACH2PHYS_COMPAT_VIRT_END,
            .max_mfn = MACH2PHYS_COMPAT_NR_ENTRIES(d) - 1
        };

        if ( copy_to_guest(arg, &mapping, 1) )
            rc = -EFAULT;

        break;
    }

    case XENMEM_machphys_mfn_list:
        if ( copy_from_guest(&xmml, arg, 1) )
            return -EFAULT;

        for ( i = 0, v = RDWR_COMPAT_MPT_VIRT_START;
              (i != xmml.max_extents) && (v != RDWR_COMPAT_MPT_VIRT_END);
              i++, v += 1 << L2_PAGETABLE_SHIFT )
        {
            l2e = compat_idle_pg_table_l2[l2_table_offset(v)];
            if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
                break;
            mfn = l2e_get_pfn(l2e) + l1_table_offset(v);
            if ( copy_to_compat_offset(xmml.extent_start, i, &mfn, 1) )
                return -EFAULT;
        }

        xmml.nr_extents = i;
        if ( copy_to_guest(arg, &xmml, 1) )
            rc = -EFAULT;

        break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

int compat_update_va_mapping(unsigned int va, u32 lo, u32 hi,
                             unsigned int flags)
{
    return do_update_va_mapping(va, lo | ((u64)hi << 32), flags);
}

int compat_update_va_mapping_otherdomain(unsigned long va, u32 lo, u32 hi,
                                         unsigned long flags,
                                         domid_t domid)
{
    return do_update_va_mapping_otherdomain(va, lo | ((u64)hi << 32), flags, domid);
}

DEFINE_XEN_GUEST_HANDLE(mmuext_op_compat_t);

int compat_mmuext_op(XEN_GUEST_HANDLE(mmuext_op_compat_t) cmp_uops,
                     unsigned int count,
                     XEN_GUEST_HANDLE(uint) pdone,
                     unsigned int foreigndom)
{
    unsigned int i, preempt_mask;
    int rc = 0;
    XEN_GUEST_HANDLE(mmuext_op_t) nat_ops;

    preempt_mask = count & MMU_UPDATE_PREEMPTED;
    count ^= preempt_mask;

    if ( unlikely(!guest_handle_okay(cmp_uops, count)) )
        return -EFAULT;

    set_xen_guest_handle(nat_ops, (void *)COMPAT_ARG_XLAT_VIRT_START(current->vcpu_id));

    for ( ; count; count -= i )
    {
        mmuext_op_t *nat_op = nat_ops.p;
        unsigned int limit;
        int err;

        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_mmuext_op, "hihi",
                cmp_uops, count | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
            break;
        }

        limit = COMPAT_ARG_XLAT_SIZE / sizeof(*nat_op);

        for ( i = 0; i < min(limit, count); ++i )
        {
            mmuext_op_compat_t cmp_op;
            enum XLAT_mmuext_op_arg1 arg1;
            enum XLAT_mmuext_op_arg2 arg2;

            if ( unlikely(__copy_from_guest(&cmp_op, cmp_uops, 1) != 0) )
            {
                rc = -EFAULT;
                break;
            }

            switch ( cmp_op.cmd )
            {
            case MMUEXT_PIN_L1_TABLE:
            case MMUEXT_PIN_L2_TABLE:
            case MMUEXT_PIN_L3_TABLE:
            case MMUEXT_PIN_L4_TABLE:
            case MMUEXT_UNPIN_TABLE:
            case MMUEXT_NEW_BASEPTR:
                arg1 = XLAT_mmuext_op_arg1_mfn;
                break;
            default:
                arg1 = XLAT_mmuext_op_arg1_linear_addr;
                break;
            case MMUEXT_NEW_USER_BASEPTR:
                rc = -EINVAL;
            case MMUEXT_TLB_FLUSH_LOCAL:
            case MMUEXT_TLB_FLUSH_MULTI:
            case MMUEXT_TLB_FLUSH_ALL:
            case MMUEXT_FLUSH_CACHE:
                arg1 = -1;
                break;
            }

            if ( rc )
                break;

            switch ( cmp_op.cmd )
            {
            case MMUEXT_SET_LDT:
                arg2 = XLAT_mmuext_op_arg2_nr_ents;
                break;
            case MMUEXT_TLB_FLUSH_MULTI:
            case MMUEXT_INVLPG_MULTI:
                arg2 = XLAT_mmuext_op_arg2_vcpumask;
                break;
            default:
                arg2 = -1;
                break;
            }

#define XLAT_mmuext_op_HNDL_arg2_vcpumask(_d_, _s_) \
            do \
            { \
                unsigned int vcpumask; \
                if ( i < --limit ) \
                { \
                    (_d_)->arg2.vcpumask.p = (void *)(nat_ops.p + limit); \
                    if ( copy_from_compat(&vcpumask, (_s_)->arg2.vcpumask, 1) == 0 ) \
                        *(unsigned long *)(_d_)->arg2.vcpumask.p = vcpumask; \
                    else \
                        rc = -EFAULT; \
                } \
            } while(0)
            XLAT_mmuext_op(nat_op, &cmp_op);
#undef XLAT_mmuext_op_HNDL_arg2_vcpumask

            if ( rc || i >= limit )
                break;

            guest_handle_add_offset(cmp_uops, 1);
            ++nat_op;
        }

        err = do_mmuext_op(nat_ops, i | preempt_mask, pdone, foreigndom);

        if ( err )
        {
            BUILD_BUG_ON(__HYPERVISOR_mmuext_op <= 0);
            if ( err == __HYPERVISOR_mmuext_op )
            {
                struct cpu_user_regs *regs = guest_cpu_user_regs();
                struct mc_state *mcs = &this_cpu(mc_state);
                unsigned int arg1 = !test_bit(_MCSF_in_multicall, &mcs->flags)
                                    ? regs->ecx
                                    : mcs->call.args[1];
                unsigned int left = arg1 & ~MMU_UPDATE_PREEMPTED;

                BUG_ON(left == arg1);
                BUG_ON(left > count);
                guest_handle_add_offset(nat_ops, count - left);
                BUG_ON(left + i < count);
                guest_handle_add_offset(cmp_uops, (signed int)(count - left - i));
                left = 1;
                BUG_ON(!hypercall_xlat_continuation(&left, 0x01, nat_ops, cmp_uops));
                BUG_ON(left != arg1);
                if (!test_bit(_MCSF_in_multicall, &mcs->flags))
                    regs->_ecx += count - i;
                else
                    mcs->compat_call.args[1] += count - i;
            }
            else
                BUG_ON(err > 0);
            rc = err;
        }

        if ( rc )
            break;

        /* Force do_mmuext_op() to not start counting from zero again. */
        preempt_mask = MMU_UPDATE_PREEMPTED;
    }

    return rc;
}

#endif /* CONFIG_COMPAT */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
