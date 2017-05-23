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

/* Allow uniquely identifying static symbols in the 3 generated objects. */
asm(".file \"" __OBJECT_FILE__ "\"");

#include <xen/types.h>
#include <xen/mm.h>
#include <xen/paging.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/page.h>
#include <asm/guest_pt.h>

/*
 * Modify a guest pagetable entry to set the Accessed and Dirty bits.
 * Returns true if it actually writes to guest memory.
 */
static bool set_ad_bits(guest_intpte_t *guest_p, guest_intpte_t *walk_p,
                        bool set_dirty)
{
    guest_intpte_t new, old = *walk_p;

    new = old | _PAGE_ACCESSED | (set_dirty ? _PAGE_DIRTY : 0);
    if ( old != new )
    {
        /*
         * Write the new entry into the walk, and try to write it back
         * into the guest table as well.  If the guest table has changed
         * under our feet then leave it alone.
         */
        *walk_p = new;
        if ( cmpxchg(guest_p, old, new) == old )
            return true;
    }
    return false;
}

/*
 * Walk the guest pagetables, after the manner of a hardware walker.
 *
 * This is a condensing of the 'Paging' chapters from Intel and AMD software
 * manuals.  Please refer closely to them.
 *
 * A pagetable walk consists of two parts:
 *   1) to find whether a translation exists, and
 *   2) if a translation does exist, to check whether the translation's access
 *      rights permit the access.
 *
 * A translation is found by following the pagetable structure (starting at
 * %cr3) to a leaf entry (an L1 PTE, or a higher level entry with PSE set)
 * which identifies the physical destination of the access.
 *
 * A translation from one level to the next exists if the PTE is both present
 * and has no reserved bits set.  If the pagewalk counters a situation where a
 * translation does not exist, the walk stops at that point.
 *
 * The access rights (NX, User, RW bits) are collected as the walk progresses.
 * If a translation exists, the accumulated access rights are compared to the
 * requested walk, to see whether the access is permitted.
 */
bool
guest_walk_tables(struct vcpu *v, struct p2m_domain *p2m,
                  unsigned long va, walk_t *gw,
                  uint32_t walk, mfn_t top_mfn, void *top_map)
{
    struct domain *d = v->domain;
    p2m_type_t p2mt;
    guest_l1e_t *l1p = NULL;
    guest_l2e_t *l2p = NULL;
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    guest_l3e_t *l3p = NULL;
    guest_l4e_t *l4p;
#endif
    uint32_t gflags, rc;
    unsigned int leaf_level;
    p2m_query_t qt = P2M_ALLOC | P2M_UNSHARE;

#define AR_ACCUM_AND (_PAGE_USER | _PAGE_RW)
#define AR_ACCUM_OR  (_PAGE_NX_BIT)
    /* Start with all AND bits set, all OR bits clear. */
    uint32_t ar, ar_and = ~0u, ar_or = 0;

    bool walk_ok = false;

    /*
     * TODO - We should ASSERT() that only the following bits are set as
     * inputs to a guest walk, but a whole load of code currently passes in
     * other PFEC_ constants.
     */
    walk &= (PFEC_implicit | PFEC_insn_fetch | PFEC_user_mode | PFEC_write_access);

    /* Only implicit supervisor data accesses exist. */
    ASSERT(!(walk & PFEC_implicit) ||
           !(walk & (PFEC_insn_fetch | PFEC_user_mode)));

    perfc_incr(guest_walk);
    memset(gw, 0, sizeof(*gw));
    gw->va = va;
    gw->pfec = walk & (PFEC_user_mode | PFEC_write_access);

    /*
     * PFEC_insn_fetch is only reported if NX or SMEP are enabled.  Hardware
     * still distingueses instruction fetches during determination of access
     * rights.
     */
    if ( guest_nx_enabled(v) || guest_smep_enabled(v) )
        gw->pfec |= (walk & PFEC_insn_fetch);

#if GUEST_PAGING_LEVELS >= 3 /* PAE or 64... */
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */

    /* Get the l4e from the top level table and check its flags*/
    gw->l4mfn = top_mfn;
    l4p = (guest_l4e_t *) top_map;
    gw->l4e = l4p[guest_l4_table_offset(va)];
    gflags = guest_l4e_get_flags(gw->l4e);
    if ( !(gflags & _PAGE_PRESENT) )
        goto out;

    /* Check for reserved bits. */
    if ( guest_l4e_rsvd_bits(v, gw->l4e) )
    {
        gw->pfec |= PFEC_reserved_bit | PFEC_page_present;
        goto out;
    }

    /* Accumulate l4e access rights. */
    ar_and &= gflags;
    ar_or  |= gflags;

    /* Map the l3 table */
    l3p = map_domain_gfn(p2m,
                         guest_l4e_get_gfn(gw->l4e),
                         &gw->l3mfn,
                         &p2mt,
                         qt,
                         &rc);
    if ( l3p == NULL )
    {
        gw->pfec |= rc & PFEC_synth_mask;
        goto out;
    }

    /* Get the l3e and check its flags*/
    gw->l3e = l3p[guest_l3_table_offset(va)];
    gflags = guest_l3e_get_flags(gw->l3e);
    if ( !(gflags & _PAGE_PRESENT) )
        goto out;

    /* Check for reserved bits, including possibly _PAGE_PSE. */
    if ( guest_l3e_rsvd_bits(v, gw->l3e) )
    {
        gw->pfec |= PFEC_reserved_bit | PFEC_page_present;
        goto out;
    }

    /* Accumulate l3e access rights. */
    ar_and &= gflags;
    ar_or  |= gflags;

    if ( gflags & _PAGE_PSE )
    {
        /*
         * Generate a fake l1 table entry so callers don't all
         * have to understand superpages.
         */
        gfn_t start = guest_l3e_get_gfn(gw->l3e);
        /*
         * Grant full access in the l1e, since all the guest entry's
         * access controls are enforced in the l3e.
         */
        int flags = (_PAGE_PRESENT|_PAGE_USER|_PAGE_RW|
                     _PAGE_ACCESSED|_PAGE_DIRTY);
        /*
         * Import protection key and cache-control bits. Note that _PAGE_PAT
         * is actually _PAGE_PSE, and it is always set. We will clear it in
         * case _PAGE_PSE_PAT (bit 12, i.e. first bit of gfn) is clear.
         */
        flags |= (guest_l3e_get_flags(gw->l3e)
                  & (_PAGE_PKEY_BITS|_PAGE_PAT|_PAGE_PWT|_PAGE_PCD));
        if ( !(gfn_x(start) & 1) )
            /* _PAGE_PSE_PAT not set: remove _PAGE_PAT from flags. */
            flags &= ~_PAGE_PAT;

        /* Increment the pfn by the right number of 4k pages. */
        start = _gfn((gfn_x(start) & ~GUEST_L3_GFN_MASK) +
                     ((va >> PAGE_SHIFT) & GUEST_L3_GFN_MASK));
        gw->l1e = guest_l1e_from_gfn(start, flags);
        gw->l2mfn = gw->l1mfn = INVALID_MFN;
        leaf_level = 3;
        goto leaf;
    }

#else /* PAE only... */

    /* Get the l3e and check its flag */
    gw->l3e = ((guest_l3e_t *) top_map)[guest_l3_table_offset(va)];
    gflags = guest_l3e_get_flags(gw->l3e);
    if ( !(gflags & _PAGE_PRESENT) )
        goto out;

    if ( guest_l3e_rsvd_bits(v, gw->l3e) )
    {
        gw->pfec |= PFEC_reserved_bit | PFEC_page_present;
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
    if ( l2p == NULL )
    {
        gw->pfec |= rc & PFEC_synth_mask;
        goto out;
    }

    /* Get the l2e */
    gw->l2e = l2p[guest_l2_table_offset(va)];

#else /* 32-bit only... */

    /* Get l2e from the top level table */
    gw->l2mfn = top_mfn;
    l2p = (guest_l2e_t *) top_map;
    gw->l2e = l2p[guest_l2_table_offset(va)];

#endif /* All levels... */

    /* Check the l2e flags. */
    gflags = guest_l2e_get_flags(gw->l2e);
    if ( !(gflags & _PAGE_PRESENT) )
        goto out;

    /*
     * In 2-level paging without CR0.PSE, there are no reserved bits, and the
     * PAT/PSE bit is ignored.
     */
    if ( GUEST_PAGING_LEVELS == 2 && !guest_can_use_l2_superpages(v) )
    {
        gw->l2e.l2 &= ~_PAGE_PSE;
        gflags &= ~_PAGE_PSE;
    }
    /* else check for reserved bits, including possibly _PAGE_PSE. */
    else if ( guest_l2e_rsvd_bits(v, gw->l2e) )
    {
        gw->pfec |= PFEC_reserved_bit | PFEC_page_present;
        goto out;
    }

    /* Accumulate l2e access rights. */
    ar_and &= gflags;
    ar_or  |= gflags;

    if ( gflags & _PAGE_PSE )
    {
        /*
         * Special case: this guest VA is in a PSE superpage, so there's
         * no guest l1e.  We make one up so that the propagation code
         * can generate a shadow l1 table.  Start with the gfn of the
         * first 4k-page of the superpage.
         */
#if GUEST_PAGING_LEVELS == 2
        gfn_t start = _gfn(unfold_pse36(gw->l2e.l2) >> PAGE_SHIFT);
#else
        gfn_t start = guest_l2e_get_gfn(gw->l2e);
#endif
        /*
         * Grant full access in the l1e, since all the guest entry's
         * access controls are enforced in the shadow l2e.
         */
        int flags = (_PAGE_PRESENT|_PAGE_USER|_PAGE_RW|
                     _PAGE_ACCESSED|_PAGE_DIRTY);
        /*
         * Import protection key and cache-control bits. Note that _PAGE_PAT
         * is actually _PAGE_PSE, and it is always set. We will clear it in
         * case _PAGE_PSE_PAT (bit 12, i.e. first bit of gfn) is clear.
         */
        flags |= (guest_l2e_get_flags(gw->l2e)
                  & (_PAGE_PKEY_BITS|_PAGE_PAT|_PAGE_PWT|_PAGE_PCD));
        if ( !(gfn_x(start) & 1) )
            /* _PAGE_PSE_PAT not set: remove _PAGE_PAT from flags. */
            flags &= ~_PAGE_PAT;

        /* Increment the pfn by the right number of 4k pages. */
        start = _gfn((gfn_x(start) & ~GUEST_L2_GFN_MASK) +
                     guest_l1_table_offset(va));
#if GUEST_PAGING_LEVELS == 2
         /* Wider than 32 bits if PSE36 superpage. */
        gw->el1e = (gfn_x(start) << PAGE_SHIFT) | flags;
#else
        gw->l1e = guest_l1e_from_gfn(start, flags);
#endif
        gw->l1mfn = INVALID_MFN;
        leaf_level = 2;
        goto leaf;
    }

    /* Map the l1 table */
    l1p = map_domain_gfn(p2m,
                         guest_l2e_get_gfn(gw->l2e),
                         &gw->l1mfn,
                         &p2mt,
                         qt,
                         &rc);
    if ( l1p == NULL )
    {
        gw->pfec |= rc & PFEC_synth_mask;
        goto out;
    }
    gw->l1e = l1p[guest_l1_table_offset(va)];
    gflags = guest_l1e_get_flags(gw->l1e);
    if ( !(gflags & _PAGE_PRESENT) )
        goto out;

    /* Check for reserved bits. */
    if ( guest_l1e_rsvd_bits(v, gw->l1e) )
    {
        gw->pfec |= PFEC_reserved_bit | PFEC_page_present;
        goto out;
    }

    /* Accumulate l1e access rights. */
    ar_and &= gflags;
    ar_or  |= gflags;

    leaf_level = 1;

 leaf:
    gw->pfec |= PFEC_page_present;

    /*
     * The pagetable walk has returned a successful translation (i.e. All PTEs
     * are present and have no reserved bits set).  Now check access rights to
     * see whether the access should succeed.
     */
    ar = (ar_and & AR_ACCUM_AND) | (ar_or & AR_ACCUM_OR);

    /*
     * Sanity check.  If EFER.NX is disabled, _PAGE_NX_BIT is reserved and
     * should have caused a translation failure before we get here.
     */
    if ( ar & _PAGE_NX_BIT )
        ASSERT(guest_nx_enabled(v));

#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    /*
     * If all access checks are thus far ok, check Protection Key for 64bit
     * data accesses to user mappings.
     *
     * N.B. In the case that the walk ended with a superpage, the fabricated
     * gw->l1e contains the appropriate leaf pkey.
     */
    if ( (ar & _PAGE_USER) && !(walk & PFEC_insn_fetch) &&
         guest_pku_enabled(v) )
    {
        unsigned int pkey = guest_l1e_get_pkey(gw->l1e);
        unsigned int pkru = read_pkru();

        if ( read_pkru_ad(pkru, pkey) ||
             ((walk & PFEC_write_access) && read_pkru_wd(pkru, pkey) &&
              ((walk & PFEC_user_mode) || guest_wp_enabled(v))) )
        {
            gw->pfec |= PFEC_prot_key;
            goto out;
        }
    }
#endif

    if ( (walk & PFEC_insn_fetch) && (ar & _PAGE_NX_BIT) )
        /* Requested an instruction fetch and found NX? Fail. */
        goto out;

    if ( walk & PFEC_user_mode ) /* Requested a user acess. */
    {
        if ( !(ar & _PAGE_USER) )
            /* Got a supervisor walk?  Unconditional fail. */
            goto out;

        if ( (walk & PFEC_write_access) && !(ar & _PAGE_RW) )
            /* Requested a write and only got a read? Fail. */
            goto out;
    }
    else /* Requested a supervisor access. */
    {
        if ( ar & _PAGE_USER ) /* Got a user walk. */
        {
            if ( (walk & PFEC_insn_fetch) && guest_smep_enabled(v) )
                /* User insn fetch and smep? Fail. */
                goto out;

            if ( !(walk & PFEC_insn_fetch) && guest_smap_enabled(v) &&
                 ((walk & PFEC_implicit) ||
                  !(guest_cpu_user_regs()->eflags & X86_EFLAGS_AC)) )
                /* User data access and smap? Fail. */
                goto out;
        }

        if ( (walk & PFEC_write_access) && !(ar & _PAGE_RW) &&
             guest_wp_enabled(v) )
            /* Requested a write, got a read, and CR0.WP is set? Fail. */
            goto out;
    }

    walk_ok = true;

    /*
     * Go back and set accessed and dirty bits only if the walk was a
     * success.  Although the PRMs say higher-level _PAGE_ACCESSED bits
     * get set whenever a lower-level PT is used, at least some hardware
     * walkers behave this way.
     */
    switch ( leaf_level )
    {
    default:
        ASSERT_UNREACHABLE();
        break;

    case 1:
        if ( set_ad_bits(&l1p[guest_l1_table_offset(va)].l1, &gw->l1e.l1,
                         (walk & PFEC_write_access)) )
            paging_mark_dirty(d, gw->l1mfn);
        /* Fallthrough */
    case 2:
        if ( set_ad_bits(&l2p[guest_l2_table_offset(va)].l2, &gw->l2e.l2,
                         (walk & PFEC_write_access) && leaf_level == 2) )
            paging_mark_dirty(d, gw->l2mfn);
        /* Fallthrough */
#if GUEST_PAGING_LEVELS == 4 /* 64-bit only... */
    case 3:
        if ( set_ad_bits(&l3p[guest_l3_table_offset(va)].l3, &gw->l3e.l3,
                         (walk & PFEC_write_access) && leaf_level == 3) )
            paging_mark_dirty(d, gw->l3mfn);

        if ( set_ad_bits(&l4p[guest_l4_table_offset(va)].l4, &gw->l4e.l4,
                         false) )
            paging_mark_dirty(d, gw->l4mfn);
#endif
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

    return walk_ok;
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
