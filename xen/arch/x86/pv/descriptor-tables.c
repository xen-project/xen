/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/x86/pv/descriptor-tables.c
 *
 * Descriptor table manipulation code for PV guests
 *
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
 */

#include <xen/guest_access.h>
#include <xen/hypercall.h>

#include <asm/p2m.h>
#include <asm/pv/mm.h>

/*
 * Flush the LDT, dropping any typerefs.  Returns a boolean indicating whether
 * mappings have been removed (i.e. a TLB flush is needed).
 */
bool pv_destroy_ldt(struct vcpu *v)
{
    l1_pgentry_t *pl1e;
    unsigned int i, mappings_dropped = 0;
    struct page_info *page;

    ASSERT(!in_irq());

    ASSERT(v == current || !vcpu_cpu_dirty(v));

    pl1e = pv_ldt_ptes(v);

    for ( i = 0; i < 16; i++ )
    {
        if ( !(l1e_get_flags(pl1e[i]) & _PAGE_PRESENT) )
            continue;

        page = l1e_get_page(pl1e[i]);
        l1e_write(&pl1e[i], l1e_empty());
        mappings_dropped++;

        ASSERT_PAGE_IS_TYPE(page, PGT_seg_desc_page);
        ASSERT_PAGE_IS_DOMAIN(page, v->domain);
        put_page_and_type(page);
    }

    return mappings_dropped;
}

void pv_destroy_gdt(struct vcpu *v)
{
    l1_pgentry_t *pl1e = pv_gdt_ptes(v);
    mfn_t zero_mfn = _mfn(virt_to_mfn(zero_page));
    l1_pgentry_t zero_l1e = l1e_from_mfn(zero_mfn, __PAGE_HYPERVISOR_RO);
    unsigned int i;

    ASSERT(v == current || !vcpu_cpu_dirty(v));

    v->arch.pv.gdt_ents = 0;
    for ( i = 0; i < FIRST_RESERVED_GDT_PAGE; i++ )
    {
        mfn_t mfn = l1e_get_mfn(pl1e[i]);

        if ( (l1e_get_flags(pl1e[i]) & _PAGE_PRESENT) &&
             !mfn_eq(mfn, zero_mfn) )
            put_page_and_type(mfn_to_page(mfn));

        l1e_write(&pl1e[i], zero_l1e);
        v->arch.pv.gdt_frames[i] = 0;
    }
}

int pv_set_gdt(struct vcpu *v, const unsigned long frames[],
               unsigned int entries)
{
    struct domain *d = v->domain;
    l1_pgentry_t *pl1e;
    unsigned int i, nr_frames = DIV_ROUND_UP(entries, 512);

    ASSERT(v == current || !vcpu_cpu_dirty(v));

    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    /* Check the pages in the new GDT. */
    for ( i = 0; i < nr_frames; i++ )
    {
        mfn_t mfn = _mfn(frames[i]);

        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_seg_desc_page) )
            goto fail;
    }

    /* Tear down the old GDT. */
    pv_destroy_gdt(v);

    /* Install the new GDT. */
    v->arch.pv.gdt_ents = entries;
    pl1e = pv_gdt_ptes(v);
    for ( i = 0; i < nr_frames; i++ )
    {
        v->arch.pv.gdt_frames[i] = frames[i];
        l1e_write(&pl1e[i], l1e_from_pfn(frames[i], __PAGE_HYPERVISOR_RW));
    }

    return 0;

 fail:
    while ( i-- > 0 )
        put_page_and_type(mfn_to_page(_mfn(frames[i])));

    return -EINVAL;
}

long do_set_gdt(
    XEN_GUEST_HANDLE_PARAM(xen_ulong_t) frame_list, unsigned int entries)
{
    unsigned int nr_frames = DIV_ROUND_UP(entries, 512);
    unsigned long frames[16];
    struct vcpu *curr = current;
    long ret;

    /* Rechecked in set_gdt, but ensures a sane limit for copy_from_user(). */
    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    if ( copy_from_guest(frames, frame_list, nr_frames) )
        return -EFAULT;

    domain_lock(curr->domain);

    if ( (ret = pv_set_gdt(curr, frames, entries)) == 0 )
        flush_tlb_local();

    domain_unlock(curr->domain);

    return ret;
}

#ifdef CONFIG_PV32

int compat_set_gdt(
    XEN_GUEST_HANDLE_PARAM(uint) frame_list, unsigned int entries)
{
    struct vcpu *curr = current;
    unsigned int i, nr_frames = DIV_ROUND_UP(entries, 512);
    unsigned long frames[16];
    int ret;

    /* Rechecked in set_gdt, but ensures a sane limit for copy_from_user(). */
    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    if ( !guest_handle_okay(frame_list, nr_frames) )
        return -EFAULT;

    for ( i = 0; i < nr_frames; ++i )
    {
        unsigned int frame;

        if ( __copy_from_guest(&frame, frame_list, 1) )
            return -EFAULT;

        frames[i] = frame;
        guest_handle_add_offset(frame_list, 1);
    }

    domain_lock(curr->domain);

    if ( (ret = pv_set_gdt(curr, frames, entries)) == 0 )
        flush_tlb_local();

    domain_unlock(curr->domain);

    return ret;
}

int compat_update_descriptor(
    uint32_t pa_lo, uint32_t pa_hi, uint32_t desc_lo, uint32_t desc_hi)
{
    seg_desc_t d;

    d.raw = ((uint64_t)desc_hi << 32) | desc_lo;

    return do_update_descriptor(pa_lo | ((uint64_t)pa_hi << 32), d);
}

#endif /* CONFIG_PV32 */

static bool check_descriptor(const struct domain *dom, seg_desc_t *d)
{
    unsigned int a = d->a, b = d->b, cs, dpl;

    /* A not-present descriptor will always fault, so is safe. */
    if ( !(b & _SEGMENT_P) )
        return true;

    /* Check and fix up the DPL. */
    dpl = (b >> 13) & 3;
    __fixup_guest_selector(dom, dpl);
    b = (b & ~_SEGMENT_DPL) | (dpl << 13);

    /* All code and data segments are okay. No base/limit checking. */
    if ( b & _SEGMENT_S )
    {
        if ( is_pv_32bit_domain(dom) )
        {
            unsigned long base, limit;

            if ( b & _SEGMENT_L )
                goto bad;

            /*
             * Older PAE Linux guests use segments which are limited to
             * 0xf6800000. Extend these to allow access to the larger read-only
             * M2P table available in 32on64 mode.
             */
            base = (b & 0xff000000) | ((b & 0xff) << 16) | (a >> 16);

            limit = (b & 0xf0000) | (a & 0xffff);
            limit++; /* We add one because limit is inclusive. */

            if ( b & _SEGMENT_G )
                limit <<= 12;

            if ( (base == 0) && (limit > HYPERVISOR_COMPAT_VIRT_START(dom)) )
            {
                a |= 0x0000ffff;
                b |= 0x000f0000;
            }
        }

        goto good;
    }

    /* Invalid type 0 is harmless. It is used for 2nd half of a call gate. */
    if ( (b & _SEGMENT_TYPE) == 0x000 )
        return true;

    /* Everything but a call gate is discarded here. */
    if ( (b & _SEGMENT_TYPE) != 0xc00 )
        goto bad;

    /* Validate the target code selector. */
    cs = a >> 16;
    if ( !guest_gate_selector_okay(dom, cs) )
        goto bad;
    /*
     * Force DPL to zero, causing a GP fault with its error code indicating
     * the gate in use, allowing emulation. This is necessary because with
     * native guests (kernel in ring 3) call gates cannot be used directly
     * to transition from user to kernel mode (and whether a gate is used
     * to enter the kernel can only be determined when the gate is being
     * used), and with compat guests call gates cannot be used at all as
     * there are only 64-bit ones.
     * Store the original DPL in the selector's RPL field.
     */
    b &= ~_SEGMENT_DPL;
    cs = (cs & ~3) | dpl;
    a = (a & 0xffffU) | (cs << 16);

    /* Reserved bits must be zero. */
    if ( b & (is_pv_32bit_domain(dom) ? 0xe0 : 0xff) )
        goto bad;

 good:
    d->a = a;
    d->b = b;
    return true;

 bad:
    return false;
}

int validate_segdesc_page(struct page_info *page)
{
    const struct domain *owner = page_get_owner(page);
    seg_desc_t *descs = __map_domain_page(page);
    unsigned i;

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(owner, &descs[i])) )
            break;

    unmap_domain_page(descs);

    return i == 512 ? 0 : -EINVAL;
}

long do_update_descriptor(uint64_t gaddr, seg_desc_t d)
{
    struct domain *currd = current->domain;
    gfn_t gfn = gaddr_to_gfn(gaddr);
    mfn_t mfn;
    seg_desc_t *entry;
    struct page_info *page;
    long ret = -EINVAL;

    /* gaddr must be aligned, or it will corrupt adjacent descriptors. */
    if ( !IS_ALIGNED(gaddr, sizeof(d)) || !check_descriptor(currd, &d) )
        return -EINVAL;

    page = get_page_from_gfn(currd, gfn_x(gfn), NULL, P2M_ALLOC);
    if ( !page )
        return -EINVAL;

    mfn = page_to_mfn(page);

    /* Check if the given frame is in use in an unsafe context. */
    switch ( page->u.inuse.type_info & PGT_type_mask )
    {
    case PGT_seg_desc_page:
        if ( unlikely(!get_page_type(page, PGT_seg_desc_page)) )
            goto out;
        break;
    default:
        if ( unlikely(!get_page_type(page, PGT_writable_page)) )
            goto out;
        break;
    }

    paging_mark_dirty(currd, mfn);

    /* All is good so make the update. */
    entry = map_domain_page(mfn) + (gaddr & ~PAGE_MASK);
    ACCESS_ONCE(entry->raw) = d.raw;
    unmap_domain_page(entry);

    put_page_type(page);

    ret = 0; /* success */

 out:
    put_page(page);

    return ret;
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
