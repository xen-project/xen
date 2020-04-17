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

#include "mm.h"

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
        toggle_guest_pt(curr);

    l1e = guest_get_eff_l1e(linear);

    if ( user_mode )
        toggle_guest_pt(curr);

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
    unsigned long linear = curr->arch.pv.ldt_base + offset;

    BUG_ON(unlikely(in_irq()));

    /*
     * Prior limit checking should guarantee this property.  NB. This is
     * safe as updates to the LDT can only be made by MMUEXT_SET_LDT to the
     * current vcpu, and vcpu_reset() will block until this vcpu has been
     * descheduled before continuing.
     */
    if ( unlikely((offset >> 3) >= curr->arch.pv.ldt_ents) )
    {
        ASSERT_UNREACHABLE();
        return false;
    }

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

    l1e_write(pl1e, gl1e);

    return true;
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
