/******************************************************************************
 * arch/x86/mm/guest_walk.c
 *
 * Pagetable walker for guest memory accesses.
 *
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/types.h>
#include <xen/mm.h>
#include <xen/paging.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/page.h>
#include <asm/guest_pt.h>


/* Flags that are needed in a pagetable entry, with the sense of NX inverted */
static uint32_t mandatory_flags(struct vcpu *v, uint32_t pfec) 
{
    static const uint32_t flags[] = {
        /* I/F -  Usr Wr */
        /* 0   0   0   0 */ _PAGE_PRESENT, 
        /* 0   0   0   1 */ _PAGE_PRESENT|_PAGE_RW,
        /* 0   0   1   0 */ _PAGE_PRESENT|_PAGE_USER,
        /* 0   0   1   1 */ _PAGE_PRESENT|_PAGE_RW|_PAGE_USER,
        /* 0   1   0   0 */ _PAGE_PRESENT, 
        /* 0   1   0   1 */ _PAGE_PRESENT|_PAGE_RW,
        /* 0   1   1   0 */ _PAGE_PRESENT|_PAGE_USER,
        /* 0   1   1   1 */ _PAGE_PRESENT|_PAGE_RW|_PAGE_USER,
        /* 1   0   0   0 */ _PAGE_PRESENT|_PAGE_NX_BIT, 
        /* 1   0   0   1 */ _PAGE_PRESENT|_PAGE_RW|_PAGE_NX_BIT,
        /* 1   0   1   0 */ _PAGE_PRESENT|_PAGE_USER|_PAGE_NX_BIT,
        /* 1   0   1   1 */ _PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_NX_BIT,
        /* 1   1   0   0 */ _PAGE_PRESENT|_PAGE_NX_BIT, 
        /* 1   1   0   1 */ _PAGE_PRESENT|_PAGE_RW|_PAGE_NX_BIT,
        /* 1   1   1   0 */ _PAGE_PRESENT|_PAGE_USER|_PAGE_NX_BIT,
        /* 1   1   1   1 */ _PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_NX_BIT,
    };

    /* Don't demand not-NX if the CPU wouldn't enforce it. */
    if ( !guest_supports_nx(v) )
        pfec &= ~PFEC_insn_fetch;

    /* Don't demand R/W if the CPU wouldn't enforce it. */
    if ( is_hvm_vcpu(v) && unlikely(!hvm_wp_enabled(v)) 
         && !(pfec & PFEC_user_mode) )
        pfec &= ~PFEC_write_access;

    return flags[(pfec & 0x1f) >> 1] | _PAGE_INVALID_BITS;
}

/* Modify a guest pagetable entry to set the Accessed and Dirty bits.
 * Returns non-zero if it actually writes to guest memory. */
static uint32_t set_ad_bits(void *guest_p, void *walk_p, int set_dirty)
{
    guest_intpte_t old, new;

    old = *(guest_intpte_t *)walk_p;
    new = old | _PAGE_ACCESSED | (set_dirty ? _PAGE_DIRTY : 0);
    if ( old != new ) 
    {
        /* Write the new entry into the walk, and try to write it back
         * into the guest table as well.  If the guest table has changed
         * under out feet then leave it alone. */
        *(guest_intpte_t *)walk_p = new;
        if ( cmpxchg(((guest_intpte_t *)guest_p), old, new) == old ) 
            return 1;
    }
    return 0;
}

/* If the map is non-NULL, we leave this function having 
 * acquired an extra ref on mfn_to_page(*mfn) */
void *map_domain_gfn(struct p2m_domain *p2m, gfn_t gfn, mfn_t *mfn,
                     p2m_type_t *p2mt, p2m_query_t q, uint32_t *rc)
{
    struct page_info *page;
    void *map;

    /* Translate the gfn, unsharing if shared */
    page = get_page_from_gfn_p2m(p2m->domain, p2m, gfn_x(gfn), p2mt, NULL,
                                 q);
    if ( p2m_is_paging(*p2mt) )
    {
        ASSERT(p2m_is_hostp2m(p2m));
        if ( page )
            put_page(page);
        p2m_mem_paging_populate(p2m->domain, gfn_x(gfn));
        *rc = _PAGE_PAGED;
        return NULL;
    }
    if ( p2m_is_shared(*p2mt) )
    {
        if ( page )
            put_page(page);
        *rc = _PAGE_SHARED;
        return NULL;
    }
    if ( !page )
    {
        *rc |= _PAGE_PRESENT;
        return NULL;
    }
    *mfn = _mfn(page_to_mfn(page));
    ASSERT(mfn_valid(mfn_x(*mfn)));

    map = map_domain_page(*mfn);
    return map;
}


/* Walk the guest pagetables, after the manner of a hardware walker. */
/* Because the walk is essentially random, it can cause a deadlock 
 * warning in the p2m locking code. Highly unlikely this is an actual
 * deadlock, because who would walk page table in the opposite order? */
uint32_t
guest_walk_tables(struct vcpu *v, struct p2m_domain *p2m,
                  unsigned long va, walk_t *gw, 
                  uint32_t pfec, mfn_t top_mfn, void *top_map)
{
    struct domain *d = v->domain;
    p2m_type_t p2mt;
    guest_l1e_t *l1p = NULL;
    guest_l2e_t *l2p = NULL;
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    guest_l3e_t *l3p = NULL;
    guest_l4e_t *l4p;
#endif
    uint32_t gflags, mflags, iflags, rc = 0;
    bool_t smep = 0, smap = 0;
    bool_t pse1G = 0, pse2M = 0;
    p2m_query_t qt = P2M_ALLOC | P2M_UNSHARE;

    perfc_incr(guest_walk);
    memset(gw, 0, sizeof(*gw));
    gw->va = va;

    /* Mandatory bits that must be set in every entry.  We invert NX and
     * the invalid bits, to calculate as if there were an "X" bit that
     * allowed access.  We will accumulate, in rc, the set of flags that
     * are missing/unwanted. */
    mflags = mandatory_flags(v, pfec);
    iflags = (_PAGE_NX_BIT | _PAGE_INVALID_BITS);

    if ( is_hvm_domain(d) && !(pfec & PFEC_user_mode) )
    {
        struct segment_register seg;
        const struct cpu_user_regs *regs = guest_cpu_user_regs();

        /* SMEP: kernel-mode instruction fetches from user-mode mappings
         * should fault.  Unlike NX or invalid bits, we're looking for _all_
         * entries in the walk to have _PAGE_USER set, so we need to do the
         * whole walk as if it were a user-mode one and then invert the answer. */
        smep =  hvm_smep_enabled(v) && (pfec & PFEC_insn_fetch);

        switch ( v->arch.smap_check_policy )
        {
        case SMAP_CHECK_HONOR_CPL_AC:
            hvm_get_segment_register(v, x86_seg_ss, &seg);

            /*
             * SMAP: kernel-mode data accesses from user-mode mappings
             * should fault.
             * A fault is considered as a SMAP violation if the following
             * conditions come true:
             *   - X86_CR4_SMAP is set in CR4
             *   - A user page is accessed
             *   - CPL = 3 or X86_EFLAGS_AC is clear
             *   - Page fault in kernel mode
             */
            smap = hvm_smap_enabled(v) &&
                   ((seg.attr.fields.dpl == 3) ||
                    !(regs->eflags & X86_EFLAGS_AC));
            break;
        case SMAP_CHECK_ENABLED:
            smap = hvm_smap_enabled(v);
            break;
        default:
            ASSERT(v->arch.smap_check_policy == SMAP_CHECK_DISABLED);
            break;
        }
    }

    if ( smep || smap )
        mflags |= _PAGE_USER;

#if GUEST_PAGING_LEVELS >= 3 /* PAE or 64... */
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */

    /* Get the l4e from the top level table and check its flags*/
    gw->l4mfn = top_mfn;
    l4p = (guest_l4e_t *) top_map;
    gw->l4e = l4p[guest_l4_table_offset(va)];
    gflags = guest_l4e_get_flags(gw->l4e) ^ iflags;
    if ( !(gflags & _PAGE_PRESENT) ) {
        rc |= _PAGE_PRESENT;
        goto out;
    }
    rc |= ((gflags & mflags) ^ mflags);

    /* Map the l3 table */
    l3p = map_domain_gfn(p2m, 
                         guest_l4e_get_gfn(gw->l4e), 
                         &gw->l3mfn,
                         &p2mt,
                         qt,
                         &rc); 
    if(l3p == NULL)
        goto out;
    /* Get the l3e and check its flags*/
    gw->l3e = l3p[guest_l3_table_offset(va)];
    gflags = guest_l3e_get_flags(gw->l3e) ^ iflags;
    if ( !(gflags & _PAGE_PRESENT) ) {
        rc |= _PAGE_PRESENT;
        goto out;
    }
    rc |= ((gflags & mflags) ^ mflags);
    
    pse1G = (gflags & _PAGE_PSE) && guest_supports_1G_superpages(v); 

    if ( pse1G )
    {
        /* Generate a fake l1 table entry so callers don't all 
         * have to understand superpages. */
        gfn_t start = guest_l3e_get_gfn(gw->l3e);
        /* Grant full access in the l1e, since all the guest entry's
         * access controls are enforced in the l3e. */
        int flags = (_PAGE_PRESENT|_PAGE_USER|_PAGE_RW|
                     _PAGE_ACCESSED|_PAGE_DIRTY);
        /* Import cache-control bits. Note that _PAGE_PAT is actually
         * _PAGE_PSE, and it is always set. We will clear it in case
         * _PAGE_PSE_PAT (bit 12, i.e. first bit of gfn) is clear. */
        flags |= (guest_l3e_get_flags(gw->l3e)
                  & (_PAGE_PAT|_PAGE_PWT|_PAGE_PCD));
        if ( !(gfn_x(start) & 1) )
            /* _PAGE_PSE_PAT not set: remove _PAGE_PAT from flags. */
            flags &= ~_PAGE_PAT;

        if ( gfn_x(start) & GUEST_L3_GFN_MASK & ~0x1 )
            rc |= _PAGE_INVALID_BITS;

        /* Increment the pfn by the right number of 4k pages. */
        start = _gfn((gfn_x(start) & ~GUEST_L3_GFN_MASK) +
                     ((va >> PAGE_SHIFT) & GUEST_L3_GFN_MASK));
        gw->l1e = guest_l1e_from_gfn(start, flags);
        gw->l2mfn = gw->l1mfn = _mfn(INVALID_MFN);
        goto set_ad;
    }

#else /* PAE only... */

    /* Get the l3e and check its flag */
    gw->l3e = ((guest_l3e_t *) top_map)[guest_l3_table_offset(va)];
    if ( !(guest_l3e_get_flags(gw->l3e) & _PAGE_PRESENT) ) 
    {
        rc |= _PAGE_PRESENT;
        goto out;
    }

#endif /* PAE or 64... */

    /* Map the l2 table */
    l2p = map_domain_gfn(p2m, 
                         guest_l3e_get_gfn(gw->l3e), 
                         &gw->l2mfn,
                         &p2mt, 
                         qt,
                         &rc); 
    if(l2p == NULL)
        goto out;
    /* Get the l2e */
    gw->l2e = l2p[guest_l2_table_offset(va)];

#else /* 32-bit only... */

    /* Get l2e from the top level table */
    gw->l2mfn = top_mfn;
    l2p = (guest_l2e_t *) top_map;
    gw->l2e = l2p[guest_l2_table_offset(va)];

#endif /* All levels... */

    gflags = guest_l2e_get_flags(gw->l2e) ^ iflags;
    if ( !(gflags & _PAGE_PRESENT) ) {
        rc |= _PAGE_PRESENT;
        goto out;
    }
    rc |= ((gflags & mflags) ^ mflags);

    pse2M = (gflags & _PAGE_PSE) && guest_supports_superpages(v); 

    if ( pse2M )
    {
        /* Special case: this guest VA is in a PSE superpage, so there's
         * no guest l1e.  We make one up so that the propagation code
         * can generate a shadow l1 table.  Start with the gfn of the 
         * first 4k-page of the superpage. */
        gfn_t start = guest_l2e_get_gfn(gw->l2e);
        /* Grant full access in the l1e, since all the guest entry's 
         * access controls are enforced in the shadow l2e. */
        int flags = (_PAGE_PRESENT|_PAGE_USER|_PAGE_RW|
                     _PAGE_ACCESSED|_PAGE_DIRTY);
        /* Import cache-control bits. Note that _PAGE_PAT is actually
         * _PAGE_PSE, and it is always set. We will clear it in case
         * _PAGE_PSE_PAT (bit 12, i.e. first bit of gfn) is clear. */
        flags |= (guest_l2e_get_flags(gw->l2e)
                  & (_PAGE_PAT|_PAGE_PWT|_PAGE_PCD));
        if ( !(gfn_x(start) & 1) )
            /* _PAGE_PSE_PAT not set: remove _PAGE_PAT from flags. */
            flags &= ~_PAGE_PAT;

        if ( gfn_x(start) & GUEST_L2_GFN_MASK & ~0x1 )
        {
#if GUEST_PAGING_LEVELS == 2
            /*
             * Note that _PAGE_INVALID_BITS is zero in this case, yielding a
             * no-op here.
             *
             * Architecturally, the walk should fail if bit 21 is set (others
             * aren't being checked at least in PSE36 mode), but we'll ignore
             * this here in order to avoid specifying a non-natural, non-zero
             * _PAGE_INVALID_BITS value just for that case.
             */
#endif
            rc |= _PAGE_INVALID_BITS;
        }
        /* Increment the pfn by the right number of 4k pages.  
         * Mask out PAT and invalid bits. */
        start = _gfn((gfn_x(start) & ~GUEST_L2_GFN_MASK) +
                     guest_l1_table_offset(va));
        gw->l1e = guest_l1e_from_gfn(start, flags);
        gw->l1mfn = _mfn(INVALID_MFN);
    } 
    else 
    {
        /* Not a superpage: carry on and find the l1e. */
        l1p = map_domain_gfn(p2m, 
                             guest_l2e_get_gfn(gw->l2e), 
                             &gw->l1mfn,
                             &p2mt,
                             qt,
                             &rc);
        if(l1p == NULL)
            goto out;
        gw->l1e = l1p[guest_l1_table_offset(va)];
        gflags = guest_l1e_get_flags(gw->l1e) ^ iflags;
        if ( !(gflags & _PAGE_PRESENT) ) {
            rc |= _PAGE_PRESENT;
            goto out;
        }
        rc |= ((gflags & mflags) ^ mflags);
    }

#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
set_ad:
#endif
    /* Now re-invert the user-mode requirement for SMEP and SMAP */
    if ( smep || smap )
        rc ^= _PAGE_USER;

    /* Go back and set accessed and dirty bits only if the walk was a
     * success.  Although the PRMs say higher-level _PAGE_ACCESSED bits
     * get set whenever a lower-level PT is used, at least some hardware
     * walkers behave this way. */
    if ( rc == 0 ) 
    {
#if GUEST_PAGING_LEVELS == 4 /* 64-bit only... */
        if ( set_ad_bits(l4p + guest_l4_table_offset(va), &gw->l4e, 0) )
            paging_mark_dirty(d, mfn_x(gw->l4mfn));
        if ( set_ad_bits(l3p + guest_l3_table_offset(va), &gw->l3e,
                         (pse1G && (pfec & PFEC_write_access))) )
            paging_mark_dirty(d, mfn_x(gw->l3mfn));
#endif
        if ( !pse1G ) 
        {
            if ( set_ad_bits(l2p + guest_l2_table_offset(va), &gw->l2e,
                             (pse2M && (pfec & PFEC_write_access))) )
                paging_mark_dirty(d, mfn_x(gw->l2mfn));            
            if ( !pse2M ) 
            {
                if ( set_ad_bits(l1p + guest_l1_table_offset(va), &gw->l1e, 
                                 (pfec & PFEC_write_access)) )
                    paging_mark_dirty(d, mfn_x(gw->l1mfn));
            }
        }
    }

 out:
#if GUEST_PAGING_LEVELS == 4
    if ( l3p ) 
    {
        unmap_domain_page(l3p);
        put_page(mfn_to_page(mfn_x(gw->l3mfn)));
    }
#endif
#if GUEST_PAGING_LEVELS >= 3
    if ( l2p ) 
    {
        unmap_domain_page(l2p);
        put_page(mfn_to_page(mfn_x(gw->l2mfn)));
    }
#endif
    if ( l1p ) 
    {
        unmap_domain_page(l1p);
        put_page(mfn_to_page(mfn_x(gw->l1mfn)));
    }

    return rc;
}
