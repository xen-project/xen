/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/hap/nested_hap.c
 *
 * Code for Nested Virtualization
 * Copyright (c) 2011 Advanced Micro Devices
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

void cf_check
nestedp2m_write_p2m_entry_post(struct p2m_domain *p2m, unsigned int oflags)
{
    if ( oflags & _PAGE_PRESENT )
        guest_flush_tlb_mask(p2m->domain, p2m->dirty_cpumask);
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
    unsigned long gfn, mask;
    mfn_t mfn;

    ASSERT(p2m);
    ASSERT(p2m->set_entry);
    ASSERT(p2m_locked_by_me(p2m));

    /*
     * If this is a superpage mapping, round down both addresses to
     * the start of the superpage.
     */
    mask = ~((1UL << page_order) - 1);
    gfn = (L2_gpa >> PAGE_SHIFT) & mask;
    mfn = _mfn((L0_gpa >> PAGE_SHIFT) & mask);

    rc = p2m_set_entry(p2m, _gfn(gfn), mfn, page_order, p2mt, p2ma);

    if ( rc )
    {
        gdprintk(XENLOG_ERR,
                 "failed to set entry for %#"PRIx64" -> %#"PRIx64" rc:%d\n",
                 L2_gpa, L0_gpa, rc);
        domain_crash(p2m->domain);
    }
}

/* This function uses L1_gpa to walk the P2M table in L0 hypervisor. If the
 * walk is successful, the translated value is returned in L0_gpa. The return 
 * value tells the upper level what to do.
 */
static int nestedhap_walk_L0_p2m(
    struct p2m_domain *p2m, paddr_t L1_gpa, paddr_t *L0_gpa, p2m_type_t *p2mt,
    p2m_access_t *p2ma, unsigned int *page_order, struct npfec npfec)
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
    if ( npfec.write_access && p2m_is_readonly(*p2mt) )
        goto out;

    if ( p2m_is_paging(*p2mt) || p2m_is_shared(*p2mt) || !p2m_is_ram(*p2mt) )
        goto out;

    if ( !mfn_valid(mfn) )
        goto out;

    rc = NESTEDHVM_PAGEFAULT_DONE;
direct_mmio_out:
    *L0_gpa = mfn_to_maddr(mfn) + (L1_gpa & ~PAGE_MASK);
out:
    p2m_put_gfn(p2m, gaddr_to_gfn(L1_gpa));
    return rc;
}

/*
 * The following function, nestedhap_page_fault(), is for steps (3)--(10).
 *
 * Returns:
 */
int nestedhvm_hap_nested_page_fault(
    struct vcpu *v, paddr_t *L2_gpa, struct npfec npfec)
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

    /* walk the L1 P2M table */
    rv = nhvm_hap_walk_L1_p2m(v, *L2_gpa, &L1_gpa, &page_order_21, &p2ma_21,
                              npfec);

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
    rv = nestedhap_walk_L0_p2m(p2m, L1_gpa, &L0_gpa, &p2mt_10, &p2ma_10,
                               &page_order_10, npfec);

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
    case p2m_access_n ... p2m_access_rwx:
        break;
    case p2m_access_rx2rw:
        p2ma_10 = p2m_access_rx;
        break;
    case p2m_access_n2rwx:
        p2ma_10 = p2m_access_n;
        break;
    case p2m_access_r_pw:
        p2ma_10 = p2m_access_r;
        break;
    default:
        p2ma_10 = p2m_access_n;
        /* For safety, remove all permissions. */
        gdprintk(XENLOG_ERR, "Unhandled p2m access type:%d\n", p2ma_10);
        break;
    }
    /* Use minimal permission for nested p2m. */
    p2ma_10 &= (p2m_access_t)p2ma_21;

    /* fix p2m_get_pagetable(nested_p2m) */
    nested_p2m = p2m_get_nestedp2m_locked(v);
    nestedhap_fix_p2m(v, nested_p2m, *L2_gpa, L0_gpa, page_order_20,
        p2mt_10, p2ma_10);
    p2m_unlock(nested_p2m);

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
