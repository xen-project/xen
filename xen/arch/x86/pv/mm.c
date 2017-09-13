/*
 * pv/mm.c
 *
 * Memory managment code for PV guests
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

#include <asm/current.h>
#include <asm/p2m.h>
#include <asm/setup.h>

#include "mm.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

/*
 * Get a mapping of a PV guest's l1e for this linear address.  The return
 * pointer should be unmapped using unmap_domain_page().
 */
l1_pgentry_t *map_guest_l1e(unsigned long linear, mfn_t *gl1mfn)
{
    l2_pgentry_t l2e;

    ASSERT(!paging_mode_translate(current->domain));
    ASSERT(!paging_mode_external(current->domain));

    if ( unlikely(!__addr_ok(linear)) )
        return NULL;

    /* Find this l1e and its enclosing l1mfn in the linear map. */
    if ( __copy_from_user(&l2e,
                          &__linear_l2_table[l2_linear_offset(linear)],
                          sizeof(l2_pgentry_t)) )
        return NULL;

    /* Check flags that it will be safe to read the l1e. */
    if ( (l2e_get_flags(l2e) & (_PAGE_PRESENT | _PAGE_PSE)) != _PAGE_PRESENT )
        return NULL;

    *gl1mfn = l2e_get_mfn(l2e);

    return (l1_pgentry_t *)map_domain_page(*gl1mfn) + l1_table_offset(linear);
}

/*
 * Read the guest's l1e that maps this address, from the kernel-mode
 * page tables.
 */
static l1_pgentry_t guest_get_eff_kern_l1e(unsigned long linear)
{
    struct vcpu *curr = current;
    const bool user_mode = !(curr->arch.flags & TF_kernel_mode);
    l1_pgentry_t l1e;

    if ( user_mode )
        toggle_guest_mode(curr);

    l1e = guest_get_eff_l1e(linear);

    if ( user_mode )
        toggle_guest_mode(curr);

    return l1e;
}

/*
 * Map a guest's LDT page (covering the byte at @offset from start of the LDT)
 * into Xen's virtual range.  Returns true if the mapping changed, false
 * otherwise.
 */
bool pv_map_ldt_shadow_page(unsigned int offset)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct page_info *page;
    l1_pgentry_t gl1e, *pl1e;
    unsigned long linear = curr->arch.pv_vcpu.ldt_base + offset;

    BUG_ON(unlikely(in_irq()));

    /*
     * Hardware limit checking should guarantee this property.  NB. This is
     * safe as updates to the LDT can only be made by MMUEXT_SET_LDT to the
     * current vcpu, and vcpu_reset() will block until this vcpu has been
     * descheduled before continuing.
     */
    ASSERT((offset >> 3) <= curr->arch.pv_vcpu.ldt_ents);

    if ( is_pv_32bit_domain(currd) )
        linear = (uint32_t)linear;

    gl1e = guest_get_eff_kern_l1e(linear);
    if ( unlikely(!(l1e_get_flags(gl1e) & _PAGE_PRESENT)) )
        return false;

    page = get_page_from_gfn(currd, l1e_get_pfn(gl1e), NULL, P2M_ALLOC);
    if ( unlikely(!page) )
        return false;

    if ( unlikely(!get_page_type(page, PGT_seg_desc_page)) )
    {
        put_page(page);
        return false;
    }

    pl1e = &pv_ldt_ptes(curr)[offset >> PAGE_SHIFT];
    l1e_add_flags(gl1e, _PAGE_RW);

    spin_lock(&curr->arch.pv_vcpu.shadow_ldt_lock);
    l1e_write(pl1e, gl1e);
    curr->arch.pv_vcpu.shadow_ldt_mapcnt++;
    spin_unlock(&curr->arch.pv_vcpu.shadow_ldt_lock);

    return true;
}

#ifndef NDEBUG
static unsigned int __read_mostly root_pgt_pv_xen_slots
    = ROOT_PAGETABLE_PV_XEN_SLOTS;
static l4_pgentry_t __read_mostly split_l4e;
#else
#define root_pgt_pv_xen_slots ROOT_PAGETABLE_PV_XEN_SLOTS
#endif

/*
 * This function must write all ROOT_PAGETABLE_PV_XEN_SLOTS, to clobber any
 * values a guest may have left there from alloc_l4_table().
 */
void init_guest_l4_table(l4_pgentry_t l4tab[], const struct domain *d,
                         bool zap_ro_mpt)
{
    /* Xen private mappings. */
    memcpy(&l4tab[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           root_pgt_pv_xen_slots * sizeof(l4_pgentry_t));
#ifndef NDEBUG
    if ( unlikely(root_pgt_pv_xen_slots < ROOT_PAGETABLE_PV_XEN_SLOTS) )
    {
        l4_pgentry_t *next = &l4tab[ROOT_PAGETABLE_FIRST_XEN_SLOT +
                                    root_pgt_pv_xen_slots];

        if ( l4e_get_intpte(split_l4e) )
            *next++ = split_l4e;

        memset(next, 0,
               _p(&l4tab[ROOT_PAGETABLE_LAST_XEN_SLOT + 1]) - _p(next));
    }
#else
    BUILD_BUG_ON(root_pgt_pv_xen_slots != ROOT_PAGETABLE_PV_XEN_SLOTS);
#endif
    l4tab[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_pfn(domain_page_map_to_mfn(l4tab), __PAGE_HYPERVISOR_RW);
    l4tab[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_page(d->arch.perdomain_l3_pg, __PAGE_HYPERVISOR_RW);
    if ( zap_ro_mpt || is_pv_32bit_domain(d) )
        l4tab[l4_table_offset(RO_MPT_VIRT_START)] = l4e_empty();
}

void pv_arch_init_memory(void)
{
#ifndef NDEBUG
    unsigned int i;

    if ( highmem_start )
    {
        unsigned long split_va = (unsigned long)__va(highmem_start);

        if ( split_va < HYPERVISOR_VIRT_END &&
             split_va - 1 == (unsigned long)__va(highmem_start - 1) )
        {
            root_pgt_pv_xen_slots = l4_table_offset(split_va) -
                                    ROOT_PAGETABLE_FIRST_XEN_SLOT;
            ASSERT(root_pgt_pv_xen_slots < ROOT_PAGETABLE_PV_XEN_SLOTS);
            if ( l4_table_offset(split_va) == l4_table_offset(split_va - 1) )
            {
                l3_pgentry_t *l3tab = alloc_xen_pagetable();

                if ( l3tab )
                {
                    const l3_pgentry_t *l3idle =
                        l4e_to_l3e(idle_pg_table[l4_table_offset(split_va)]);

                    for ( i = 0; i < l3_table_offset(split_va); ++i )
                        l3tab[i] = l3idle[i];
                    for ( ; i < L3_PAGETABLE_ENTRIES; ++i )
                        l3tab[i] = l3e_empty();
                    split_l4e = l4e_from_pfn(virt_to_mfn(l3tab),
                                             __PAGE_HYPERVISOR_RW);
                }
                else
                    ++root_pgt_pv_xen_slots;
            }
        }
    }
#endif
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
