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

#define _hap_p2m_ga_to_gfn(levels) hap_p2m_ga_to_gfn_##levels##_levels
#define hap_p2m_ga_to_gfn(levels) _hap_p2m_ga_to_gfn(levels)

#if GUEST_PAGING_LEVELS > CONFIG_PAGING_LEVELS
#error GUEST_PAGING_LEVELS must not exceed CONFIG_PAGING_LEVELS
#endif

#include <asm/guest_pt.h>
#include <asm/p2m.h>

unsigned long hap_gva_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long gva, uint32_t *pfec)
{
    unsigned long cr3 = v->arch.hvm_vcpu.guest_cr[3];
    return hap_p2m_ga_to_gfn(GUEST_PAGING_LEVELS)(v, p2m, cr3, gva, pfec, NULL);
}

unsigned long hap_p2m_ga_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order)
{
    uint32_t missing;
    mfn_t top_mfn;
    void *top_map;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    walk_t gw;
    unsigned long top_gfn;

    /* Get the top-level table's MFN */
    top_gfn = cr3 >> PAGE_SHIFT;
    top_mfn = get_gfn_type_access(p2m, top_gfn, &p2mt, &p2ma, p2m_unshare, NULL);
    if ( p2m_is_paging(p2mt) )
    {
        ASSERT(!p2m_is_nestedp2m(p2m));
        pfec[0] = PFEC_page_paged;
        __put_gfn(p2m, top_gfn);
        p2m_mem_paging_populate(p2m->domain, cr3 >> PAGE_SHIFT);
        return INVALID_GFN;
    }
    if ( p2m_is_shared(p2mt) )
    {
        pfec[0] = PFEC_page_shared;
        __put_gfn(p2m, top_gfn);
        return INVALID_GFN;
    }
    if ( !p2m_is_ram(p2mt) )
    {
        pfec[0] &= ~PFEC_page_present;
        __put_gfn(p2m, top_gfn);
        return INVALID_GFN;
    }

    /* Map the top-level table and call the tree-walker */
    ASSERT(mfn_valid(mfn_x(top_mfn)));
    top_map = map_domain_page(mfn_x(top_mfn));
#if GUEST_PAGING_LEVELS == 3
    top_map += (cr3 & ~(PAGE_MASK | 31));
#endif
    missing = guest_walk_tables(v, p2m, ga, &gw, pfec[0], top_mfn, top_map);
    unmap_domain_page(top_map);
    __put_gfn(p2m, top_gfn);

    /* Interpret the answer */
    if ( missing == 0 )
    {
        gfn_t gfn = guest_l1e_get_gfn(gw.l1e);
        (void)get_gfn_type_access(p2m, gfn_x(gfn), &p2mt, &p2ma, p2m_unshare, NULL); 
        if ( p2m_is_paging(p2mt) )
        {
            ASSERT(!p2m_is_nestedp2m(p2m));
            pfec[0] = PFEC_page_paged;
            __put_gfn(p2m, gfn_x(gfn));
            p2m_mem_paging_populate(p2m->domain, gfn_x(gfn));
            return INVALID_GFN;
        }
        if ( p2m_is_shared(p2mt) )
        {
            pfec[0] = PFEC_page_shared;
            __put_gfn(p2m, gfn_x(gfn));
            return INVALID_GFN;
        }

        __put_gfn(p2m, gfn_x(gfn));

        if ( page_order )
            *page_order = guest_walk_to_page_order(&gw);

        return gfn_x(gfn);
    }

    if ( missing & _PAGE_PRESENT )
        pfec[0] &= ~PFEC_page_present;

    if ( missing & _PAGE_INVALID_BITS ) 
        pfec[0] |= PFEC_reserved_bit;

    if ( missing & _PAGE_PAGED )
        pfec[0] = PFEC_page_paged;

    if ( missing & _PAGE_SHARED )
        pfec[0] = PFEC_page_shared;

    return INVALID_GFN;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
