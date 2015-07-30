/******************************************************************************
 * arch/x86/mm/hap/nested_hap.c
 *
 * Code for Nested Virtualization
 * Copyright (c) 2011 Advanced Micro Devices
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

#include <xen/vm_event.h>
#include <xen/event.h>
#include <public/vm_event.h>
#include <asm/domain.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/mem_sharing.h>
#include <asm/hap.h>
#include <asm/hvm/support.h>

#include <asm/hvm/nestedhvm.h>

#include "private.h"

/* AlGORITHM for NESTED PAGE FAULT 
 * 
 * NOTATION
 * Levels: L0, L1, L2
 * Guests: L1 guest, L2 guest
 * Hypervisor: L0 hypervisor
 * Addresses: L2-GVA, L2-GPA, L1-GVA, L1-GPA, MPA
 *
 * On L0, when #NPF happens, the handler function should do:
 * hap_page_fault(GPA)
 * {
 *    1. If #NPF is from L1 guest, then we crash the guest VM (same as old 
 *       code)
 *    2. If #NPF is from L2 guest, then we continue from (3)
 *    3. Get np2m base from L1 guest. Map np2m base into L0 hypervisor address
 *       space.
 *    4. Walk the np2m's  page table
 *    5.    - if not present or permission check failure, then we inject #NPF
 *            back to L1 guest and
 *            re-launch L1 guest (L1 guest will either treat this #NPF as MMIO,
 *            or fix its p2m table for L2 guest)
 *    6.    - if present, then we will get the a new translated value L1-GPA 
 *            (points to L1 machine memory)
 *    7.        * Use L1-GPA to walk L0 P2M table
 *    8.            - if not present, then crash the guest (should not happen)
 *    9.            - if present, then we get a new translated value MPA 
 *                    (points to real machine memory)
 *   10.                * Finally, use GPA and MPA to walk nested_p2m 
 *                        and fix the bits.
 * }
 * 
 */


/********************************************/
/*        NESTED VIRT P2M FUNCTIONS         */
/********************************************/
/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

void
nestedp2m_write_p2m_entry(struct p2m_domain *p2m, unsigned long gfn,
    l1_pgentry_t *p, l1_pgentry_t new, unsigned int level)
{
    struct domain *d = p2m->domain;
    uint32_t old_flags;

    paging_lock(d);

    old_flags = l1e_get_flags(*p);
    safe_write_pte(p, new);

    if (old_flags & _PAGE_PRESENT)
        flush_tlb_mask(p2m->dirty_cpumask);

    paging_unlock(d);
}

/********************************************/
/*          NESTED VIRT FUNCTIONS           */
/********************************************/
static void
nestedhap_fix_p2m(struct vcpu *v, struct p2m_domain *p2m, 
                  paddr_t L2_gpa, paddr_t L0_gpa,
                  unsigned int page_order, p2m_type_t p2mt, p2m_access_t p2ma)
{
    int rc = 0;
    ASSERT(p2m);
    ASSERT(p2m->set_entry);

    p2m_lock(p2m);

    /* If this p2m table has been flushed or recycled under our feet, 
     * leave it alone.  We'll pick up the right one as we try to 
     * vmenter the guest. */
    if ( p2m->np2m_base == nhvm_vcpu_p2m_base(v) )
    {
        unsigned long gfn, mask;
        mfn_t mfn;

        /* If this is a superpage mapping, round down both addresses
         * to the start of the superpage. */
        mask = ~((1UL << page_order) - 1);

        gfn = (L2_gpa >> PAGE_SHIFT) & mask;
        mfn = _mfn((L0_gpa >> PAGE_SHIFT) & mask);

        rc = p2m_set_entry(p2m, gfn, mfn, page_order, p2mt, p2ma);
    }

    p2m_unlock(p2m);

    if ( rc )
    {
        gdprintk(XENLOG_ERR,
                 "failed to set entry for %#"PRIx64" -> %#"PRIx64" rc:%d\n",
                 L2_gpa, L0_gpa, rc);
        domain_crash(p2m->domain);
    }
}

/* This function uses L2_gpa to walk the P2M page table in L1. If the
 * walk is successful, the translated value is returned in
 * L1_gpa. The result value tells what to do next.
 */
static int
nestedhap_walk_L1_p2m(struct vcpu *v, paddr_t L2_gpa, paddr_t *L1_gpa,
                      unsigned int *page_order, uint8_t *p2m_acc,
                      bool_t access_r, bool_t access_w, bool_t access_x)
{
    ASSERT(hvm_funcs.nhvm_hap_walk_L1_p2m);

    return hvm_funcs.nhvm_hap_walk_L1_p2m(v, L2_gpa, L1_gpa, page_order,
        p2m_acc, access_r, access_w, access_x);
}


/* This function uses L1_gpa to walk the P2M table in L0 hypervisor. If the
 * walk is successful, the translated value is returned in L0_gpa. The return 
 * value tells the upper level what to do.
 */
static int
nestedhap_walk_L0_p2m(struct p2m_domain *p2m, paddr_t L1_gpa, paddr_t *L0_gpa,
                      p2m_type_t *p2mt, p2m_access_t *p2ma,
                      unsigned int *page_order,
                      bool_t access_r, bool_t access_w, bool_t access_x)
{
    mfn_t mfn;
    int rc;

    /* walk L0 P2M table */
    mfn = get_gfn_type_access(p2m, L1_gpa >> PAGE_SHIFT, p2mt, p2ma,
                              0, page_order);

    rc = NESTEDHVM_PAGEFAULT_DIRECT_MMIO;
    if ( *p2mt == p2m_mmio_direct )
        goto direct_mmio_out;
    rc = NESTEDHVM_PAGEFAULT_MMIO;
    if ( *p2mt == p2m_mmio_dm )
        goto out;

    rc = NESTEDHVM_PAGEFAULT_L0_ERROR;
    if ( access_w && p2m_is_readonly(*p2mt) )
        goto out;

    if ( p2m_is_paging(*p2mt) || p2m_is_shared(*p2mt) || !p2m_is_ram(*p2mt) )
        goto out;

    if ( !mfn_valid(mfn) )
        goto out;

    rc = NESTEDHVM_PAGEFAULT_DONE;
direct_mmio_out:
    *L0_gpa = (mfn_x(mfn) << PAGE_SHIFT) + (L1_gpa & ~PAGE_MASK);
out:
    __put_gfn(p2m, L1_gpa >> PAGE_SHIFT);
    return rc;
}

/*
 * The following function, nestedhap_page_fault(), is for steps (3)--(10).
 *
 * Returns:
 */
int
nestedhvm_hap_nested_page_fault(struct vcpu *v, paddr_t *L2_gpa,
    bool_t access_r, bool_t access_w, bool_t access_x)
{
    int rv;
    paddr_t L1_gpa, L0_gpa;
    struct domain *d = v->domain;
    struct p2m_domain *p2m, *nested_p2m;
    unsigned int page_order_21, page_order_10, page_order_20;
    p2m_type_t p2mt_10;
    p2m_access_t p2ma_10 = p2m_access_rwx;
    uint8_t p2ma_21 = p2m_access_rwx;

    p2m = p2m_get_hostp2m(d); /* L0 p2m */
    nested_p2m = p2m_get_nestedp2m(v, nhvm_vcpu_p2m_base(v));

    /* walk the L1 P2M table */
    rv = nestedhap_walk_L1_p2m(v, *L2_gpa, &L1_gpa, &page_order_21, &p2ma_21,
        access_r, access_w, access_x);

    /* let caller to handle these two cases */
    switch (rv) {
    case NESTEDHVM_PAGEFAULT_INJECT:
    case NESTEDHVM_PAGEFAULT_RETRY:
    case NESTEDHVM_PAGEFAULT_L1_ERROR:
        return rv;
    case NESTEDHVM_PAGEFAULT_DONE:
        break;
    default:
        BUG();
        break;
    }

    /* ==> we have to walk L0 P2M */
    rv = nestedhap_walk_L0_p2m(p2m, L1_gpa, &L0_gpa,
        &p2mt_10, &p2ma_10, &page_order_10,
        access_r, access_w, access_x);

    /* let upper level caller to handle these two cases */
    switch (rv) {
    case NESTEDHVM_PAGEFAULT_INJECT:
        return rv;
    case NESTEDHVM_PAGEFAULT_L0_ERROR:
        *L2_gpa = L1_gpa;
        return rv;
    case NESTEDHVM_PAGEFAULT_DONE:
        break;
    case NESTEDHVM_PAGEFAULT_MMIO:
        return rv;
    case NESTEDHVM_PAGEFAULT_DIRECT_MMIO:
        break;
    default:
        BUG();
        break;
    }

    page_order_20 = min(page_order_21, page_order_10);

    ASSERT(p2ma_10 <= p2m_access_n2rwx);
    /*NOTE: if assert fails, needs to handle new access type here */

    switch ( p2ma_10 )
    {
    case p2m_access_rwx ... p2m_access_n:
        break;
    case p2m_access_rx2rw:
        p2ma_10 = p2m_access_rx;
        break;
    case p2m_access_n2rwx:
        p2ma_10 = p2m_access_n;
        break;
    default:
        p2ma_10 = p2m_access_n;
        /* For safety, remove all permissions. */
        gdprintk(XENLOG_ERR, "Unhandled p2m access type:%d\n", p2ma_10);
    }
    /* Use minimal permission for nested p2m. */
    p2ma_10 &= (p2m_access_t)p2ma_21;

    /* fix p2m_get_pagetable(nested_p2m) */
    nestedhap_fix_p2m(v, nested_p2m, *L2_gpa, L0_gpa, page_order_20,
        p2mt_10, p2ma_10);

    return NESTEDHVM_PAGEFAULT_DONE;
}

/********************************************/
/*     NESTED VIRT INITIALIZATION FUNCS     */
/********************************************/

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
