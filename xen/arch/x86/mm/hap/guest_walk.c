/*
 * arch/x86/mm/hap/guest_walk.c
 *
 * Guest page table walker
 * Copyright (c) 2007, AMD Corporation (Wei Huang)
 * Copyright (c) 2007, XenSource Inc.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */


#include <xen/domain_page.h>
#include <xen/paging.h>
#include <xen/config.h>
#include <xen/sched.h>
#include "private.h" /* for hap_gva_to_gfn_* */

#define _hap_gva_to_gfn(levels) hap_gva_to_gfn_##levels##_levels
#define hap_gva_to_gfn(levels) _hap_gva_to_gfn(levels)

#if GUEST_PAGING_LEVELS <= CONFIG_PAGING_LEVELS

#include <asm/guest_pt.h>

unsigned long hap_gva_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, unsigned long gva, uint32_t *pfec)
{
    unsigned long cr3;
    uint32_t missing;
    mfn_t top_mfn;
    void *top_map;
    p2m_type_t p2mt;
    walk_t gw;

    /* Get the top-level table's MFN */
    cr3 = v->arch.hvm_vcpu.guest_cr[3];
    top_mfn = gfn_to_mfn(v->domain, _gfn(cr3 >> PAGE_SHIFT), &p2mt);
    if ( !p2m_is_ram(p2mt) )
    {
        pfec[0] &= ~PFEC_page_present;
        return INVALID_GFN;
    }

    /* Map the top-level table and call the tree-walker */
    ASSERT(mfn_valid(mfn_x(top_mfn)));
    top_map = map_domain_page(mfn_x(top_mfn));
#if GUEST_PAGING_LEVELS == 3
    top_map += (cr3 & ~(PAGE_MASK | 31));
#endif
    missing = guest_walk_tables(v, gva, &gw, pfec[0], top_mfn, top_map);
    unmap_domain_page(top_map);

    /* Interpret the answer */
    if ( missing == 0 ) 
        return gfn_x(guest_l1e_get_gfn(gw.l1e));
    
    if ( missing & _PAGE_PRESENT )
        pfec[0] &= ~PFEC_page_present;
    
    return INVALID_GFN;
}

#else

unsigned long hap_gva_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, unsigned long gva, uint32_t *pfec)
{
    gdprintk(XENLOG_ERR,
             "Guest paging level is greater than host paging level!\n");
    domain_crash(v->domain);
    return INVALID_GFN;
}

#endif


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

