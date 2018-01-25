/*
 * arch/x86/pv/descriptor-tables.c
 *
 * Descriptor table manipulation code for PV guests
 *
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/guest_access.h>
#include <xen/hypercall.h>

#include <asm/p2m.h>
#include <asm/pv/mm.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

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

    spin_lock(&v->arch.pv_vcpu.shadow_ldt_lock);

    if ( v->arch.pv_vcpu.shadow_ldt_mapcnt == 0 )
        goto out;

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

    ASSERT(v->arch.pv_vcpu.shadow_ldt_mapcnt == mappings_dropped);
    v->arch.pv_vcpu.shadow_ldt_mapcnt = 0;

 out:
    spin_unlock(&v->arch.pv_vcpu.shadow_ldt_lock);

    return mappings_dropped;
}

void pv_destroy_gdt(struct vcpu *v)
{
    l1_pgentry_t *pl1e = pv_gdt_ptes(v);
    mfn_t zero_mfn = _mfn(virt_to_mfn(zero_page));
    l1_pgentry_t zero_l1e = l1e_from_mfn(zero_mfn, __PAGE_HYPERVISOR_RO);
    unsigned int i;

    v->arch.pv_vcpu.gdt_ents = 0;
    for ( i = 0; i < FIRST_RESERVED_GDT_PAGE; i++ )
    {
        mfn_t mfn = l1e_get_mfn(pl1e[i]);

        if ( (l1e_get_flags(pl1e[i]) & _PAGE_PRESENT) &&
             !mfn_eq(mfn, zero_mfn) )
            put_page_and_type(mfn_to_page(mfn));

        l1e_write(&pl1e[i], zero_l1e);
        v->arch.pv_vcpu.gdt_frames[i] = 0;
    }
}

long pv_set_gdt(struct vcpu *v, unsigned long *frames, unsigned int entries)
{
    struct domain *d = v->domain;
    l1_pgentry_t *pl1e;
    unsigned int i, nr_frames = DIV_ROUND_UP(entries, 512);

    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    /* Check the pages in the new GDT. */
    for ( i = 0; i < nr_frames; i++ )
    {
        struct page_info *page;

        page = get_page_from_gfn(d, frames[i], NULL, P2M_ALLOC);
        if ( !page )
            goto fail;
        if ( !get_page_type(page, PGT_seg_desc_page) )
        {
            put_page(page);
            goto fail;
        }
        frames[i] = mfn_x(page_to_mfn(page));
    }

    /* Tear down the old GDT. */
    pv_destroy_gdt(v);

    /* Install the new GDT. */
    v->arch.pv_vcpu.gdt_ents = entries;
    pl1e = pv_gdt_ptes(v);
    for ( i = 0; i < nr_frames; i++ )
    {
        v->arch.pv_vcpu.gdt_frames[i] = frames[i];
        l1e_write(&pl1e[i], l1e_from_pfn(frames[i], __PAGE_HYPERVISOR_RW));
    }

    return 0;

 fail:
    while ( i-- > 0 )
    {
        put_page_and_type(mfn_to_page(_mfn(frames[i])));
    }
    return -EINVAL;
}

long do_set_gdt(XEN_GUEST_HANDLE_PARAM(xen_ulong_t) frame_list,
                unsigned int entries)
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

int compat_set_gdt(XEN_GUEST_HANDLE_PARAM(uint) frame_list,
                   unsigned int entries)
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

long do_update_descriptor(uint64_t pa, uint64_t desc)
{
    struct domain *currd = current->domain;
    unsigned long gmfn = pa >> PAGE_SHIFT;
    unsigned long mfn;
    unsigned int  offset;
    struct desc_struct *gdt_pent, d;
    struct page_info *page;
    long ret = -EINVAL;

    offset = ((unsigned int)pa & ~PAGE_MASK) / sizeof(struct desc_struct);

    *(uint64_t *)&d = desc;

    page = get_page_from_gfn(currd, gmfn, NULL, P2M_ALLOC);
    if ( (((unsigned int)pa % sizeof(struct desc_struct)) != 0) ||
         !page ||
         !check_descriptor(currd, &d) )
    {
        if ( page )
            put_page(page);
        return -EINVAL;
    }
    mfn = mfn_x(page_to_mfn(page));

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

    paging_mark_dirty(currd, _mfn(mfn));

    /* All is good so make the update. */
    gdt_pent = map_domain_page(_mfn(mfn));
    write_atomic((uint64_t *)&gdt_pent[offset], *(uint64_t *)&d);
    unmap_domain_page(gdt_pent);

    put_page_type(page);

    ret = 0; /* success */

 out:
    put_page(page);

    return ret;
}

int compat_update_descriptor(uint32_t pa_lo, uint32_t pa_hi,
                             uint32_t desc_lo, uint32_t desc_hi)
{
    return do_update_descriptor(pa_lo | ((uint64_t)pa_hi << 32),
                                desc_lo | ((uint64_t)desc_hi << 32));
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
