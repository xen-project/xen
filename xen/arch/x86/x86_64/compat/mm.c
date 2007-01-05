#ifdef CONFIG_COMPAT

#include <compat/memory.h>

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
