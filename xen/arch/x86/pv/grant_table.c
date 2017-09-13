/*
 * pv/grant_table.c
 *
 * Grant table interfaces for PV guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
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

#include <xen/types.h>

#include <public/grant_table.h>

#include <asm/p2m.h>
#include <asm/pv/mm.h>

#include "mm.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

static unsigned int grant_to_pte_flags(unsigned int grant_flags,
                                       unsigned int cache_flags)
{
    unsigned int pte_flags =
        _PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_GNTTAB | _PAGE_NX;

    if ( grant_flags & GNTMAP_application_map )
        pte_flags |= _PAGE_USER;
    if ( !(grant_flags & GNTMAP_readonly) )
        pte_flags |= _PAGE_RW;

    pte_flags |= MASK_INSR((grant_flags >> _GNTMAP_guest_avail0), _PAGE_AVAIL);
    pte_flags |= cacheattr_to_pte_flags(cache_flags >> 5);

    return pte_flags;
}

int create_grant_pv_mapping(uint64_t addr, unsigned long frame,
                            unsigned int flags, unsigned int cache_flags)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    l1_pgentry_t nl1e, ol1e = { }, *pl1e;
    struct page_info *page;
    mfn_t gl1mfn;
    int rc = GNTST_general_error;

    nl1e = l1e_from_pfn(frame, grant_to_pte_flags(flags, cache_flags));
    nl1e = adjust_guest_l1e(nl1e, currd);

    /*
     * The meaning of addr depends on GNTMAP_contains_pte.  It is either a
     * machine address of an L1e the guest has nominated to be altered, or a
     * linear address we need to look up the appropriate L1e for.
     */
    if ( flags & GNTMAP_contains_pte )
    {
        /* addr must be suitably aligned, or we will corrupt adjacent ptes. */
        if ( !IS_ALIGNED(addr, sizeof(nl1e)) )
        {
            gdprintk(XENLOG_WARNING,
                     "Misaligned PTE address %"PRIx64"\n", addr);
            goto out;
        }

        gl1mfn = _mfn(addr >> PAGE_SHIFT);

        if ( !get_page_from_mfn(gl1mfn, currd) )
            goto out;

        pl1e = map_domain_page(gl1mfn) + (addr & ~PAGE_MASK);
    }
    else
    {
        /* Guest trying to pass an out-of-range linear address? */
        if ( is_pv_32bit_domain(currd) && addr != (uint32_t)addr )
            goto out;

        pl1e = map_guest_l1e(addr, &gl1mfn);

        if ( !pl1e )
        {
            gdprintk(XENLOG_WARNING,
                     "Could not find L1 PTE for linear address %"PRIx64"\n",
                     addr);
            goto out;
        }

        if ( !get_page_from_mfn(gl1mfn, currd) )
            goto out_unmap;
    }

    page = mfn_to_page(gl1mfn);
    if ( !page_lock(page) )
        goto out_put;

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
        goto out_unlock;

    ol1e = *pl1e;
    if ( UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, mfn_x(gl1mfn), curr, 0) )
        rc = GNTST_okay;

 out_unlock:
    page_unlock(page);
 out_put:
    put_page(page);
 out_unmap:
    unmap_domain_page(pl1e);

    if ( rc == GNTST_okay )
        put_page_from_l1e(ol1e, currd);

 out:
    return rc;
}

/*
 * This exists soley for implementing GNTABOP_unmap_and_replace, the ABI of
 * which is bizarre.  This GNTTABOP isn't used any more, but was used by
 * classic-xen kernels and PVOps Linux before the M2P_OVERRIDE infrastructure
 * was replaced with something which actually worked.
 *
 * Look up the L1e mapping linear, and zap it.  Return the L1e via *out.
 * Returns a boolean indicating success.  If success, the caller is
 * responsible for calling put_page_from_l1e().
 */
static bool steal_linear_address(unsigned long linear, l1_pgentry_t *out)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    l1_pgentry_t *pl1e, ol1e;
    struct page_info *page;
    mfn_t gl1mfn;
    bool okay = false;

    ASSERT(is_pv_domain(currd));

    pl1e = map_guest_l1e(linear, &gl1mfn);
    if ( !pl1e )
    {
        gdprintk(XENLOG_WARNING,
                 "Could not find L1 PTE for linear %"PRIx64"\n", linear);
        goto out;
    }

    if ( !get_page_from_mfn(gl1mfn, currd) )
        goto out_unmap;

    page = mfn_to_page(gl1mfn);
    if ( !page_lock(page) )
        goto out_put;

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
        goto out_unlock;

    ol1e = *pl1e;
    okay = UPDATE_ENTRY(l1, pl1e, ol1e, l1e_empty(), mfn_x(gl1mfn), curr, 0);

 out_unlock:
    page_unlock(page);
 out_put:
    put_page(page);
 out_unmap:
    unmap_domain_page(pl1e);

    if ( okay )
        *out = ol1e;

 out:
    return okay;
}

/*
 * Passing a new_addr of zero is taken to mean destroy.  Passing a non-zero
 * new_addr has only ever been available via GNTABOP_unmap_and_replace, and
 * only when !(flags & GNTMAP_contains_pte).
 */
int replace_grant_pv_mapping(uint64_t addr, unsigned long frame,
                             uint64_t new_addr, unsigned int flags)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    l1_pgentry_t nl1e = l1e_empty(), ol1e, *pl1e;
    struct page_info *page;
    mfn_t gl1mfn;
    int rc = GNTST_general_error;
    unsigned int grant_pte_flags = grant_to_pte_flags(flags, 0);

    /*
     * On top of the explicit settings done by create_grant_pv_mapping()
     * also open-code relevant parts of adjust_guest_l1e(). Don't mirror
     * available and cachability flags, though.
     */
    if ( !is_pv_32bit_domain(currd) )
        grant_pte_flags |= (grant_pte_flags & _PAGE_USER)
                           ? _PAGE_GLOBAL
                           : _PAGE_GUEST_KERNEL | _PAGE_USER;

    /*
     * addr comes from Xen's active_entry tracking, and was used successfully
     * to create a grant.
     *
     * The meaning of addr depends on GNTMAP_contains_pte.  It is either a
     * machine address of an L1e the guest has nominated to be altered, or a
     * linear address we need to look up the appropriate L1e for.
     */
    if ( flags & GNTMAP_contains_pte )
    {
        /* Replace not available in this addressing mode. */
        if ( new_addr )
            goto out;

        /* Sanity check that we won't clobber the pagetable. */
        if ( !IS_ALIGNED(addr, sizeof(nl1e)) )
        {
            ASSERT_UNREACHABLE();
            goto out;
        }

        gl1mfn = _mfn(addr >> PAGE_SHIFT);

        if ( !get_page_from_mfn(gl1mfn, currd) )
            goto out;

        pl1e = map_domain_page(gl1mfn) + (addr & ~PAGE_MASK);
    }
    else
    {
        if ( is_pv_32bit_domain(currd) )
        {
            if ( addr != (uint32_t)addr )
            {
                ASSERT_UNREACHABLE();
                goto out;
            }

            /* Guest trying to pass an out-of-range linear address? */
            if ( new_addr != (uint32_t)new_addr )
                goto out;
        }

        if ( new_addr && !steal_linear_address(new_addr, &nl1e) )
            goto out;

        pl1e = map_guest_l1e(addr, &gl1mfn);

        if ( !pl1e )
            goto out;

        if ( !get_page_from_mfn(gl1mfn, currd) )
            goto out_unmap;
    }

    page = mfn_to_page(gl1mfn);

    if ( !page_lock(page) )
        goto out_put;

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
        goto out_unlock;

    ol1e = *pl1e;

    /*
     * Check that the address supplied is actually mapped to frame (with
     * appropriate permissions).
     */
    if ( unlikely(l1e_get_pfn(ol1e) != frame) ||
         unlikely((l1e_get_flags(ol1e) ^ grant_pte_flags) &
                  (_PAGE_PRESENT | _PAGE_RW)) )
    {
        gdprintk(XENLOG_ERR,
                 "PTE %"PRIpte" for %"PRIx64" doesn't match grant (%"PRIpte")\n",
                 l1e_get_intpte(ol1e), addr,
                 l1e_get_intpte(l1e_from_pfn(frame, grant_pte_flags)));
        goto out_unlock;
    }

    if ( unlikely((l1e_get_flags(ol1e) ^ grant_pte_flags) &
                  ~(_PAGE_AVAIL | PAGE_CACHE_ATTRS)) )
        gdprintk(XENLOG_WARNING,
                 "PTE flags %x for %"PRIx64" don't match grant (%x)\n",
                 l1e_get_flags(ol1e), addr, grant_pte_flags);

    if ( UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, mfn_x(gl1mfn), curr, 0) )
        rc = GNTST_okay;

 out_unlock:
    page_unlock(page);
 out_put:
    put_page(page);
 out_unmap:
    unmap_domain_page(pl1e);

 out:
    /* If there was an error, we are still responsible for the stolen pte. */
    if ( rc )
        put_page_from_l1e(nl1e, currd);

    return rc;
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
