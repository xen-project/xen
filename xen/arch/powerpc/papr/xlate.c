/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#undef DEBUG
#undef DEBUG_FAIL

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/papr.h>
#include <asm/hcalls.h>

static void not_yet(struct cpu_user_regs *regs)
{
    printk("not implemented yet: 0x%lx\n", regs->gprs[3]);
    for (;;);
}

#ifdef USE_PTE_INSERT
static inline void pte_insert(union pte volatile *pte,
        ulong vsid, ulong rpn, ulong lrpn)
{
    /*
     * It's required that external locking be done to provide
     * exclusion between the choices of insertion points.  Any valid
     * choice of pte requires that the pte be invalid upon entry to
     * this function.
     */

    ASSERT( (pte->bits.v == 0) );

    /* Set shadow word. */
    (void)lrpn;

    /* Set the second word first so the valid bit is the last thing set */
    pte->words.rpn = rpn;

    /* Guarantee the second word is visible before the valid bit */
    __asm__ __volatile__("eieio" : : : "memory");

    /* Now set the first word including the valid bit */
    pte->words.vsid = vsid;
    /* Architecturally this instruction will cause a heavier operation
     * if this one is not supported.  note: on come machines like Cell
     * this coul dbe a nop */
    __asm__ __volatile__("ptesync" : : : "memory");
}
#endif

static void pte_tlbie(union pte volatile *pte, ulong ptex)
{
    ulong va;
    ulong vsid;
    ulong group;
    ulong pi;
    ulong pi_high;

    vsid = pte->bits.avpn >> 5;
    group = ptex >> 3;
    if (pte->bits.h) {
        group = ~group;
    }
    pi = (vsid ^ group) & 0x7ff;
    pi_high = (pte->bits.avpn & 0x1f) << 11;
    pi |= pi_high;
    va = (pi << 12) | (vsid << 28);
    va &= ~(0xffffULL << 48);

#ifndef FLUSH_THE_WHOLE_THING
    if (pte->bits.l) {
        va |= (pte->bits.rpn & 1);
        asm volatile("ptesync ;tlbie %0,1" : : "r"(va) : "memory");
    } else {
        asm volatile("ptesync; tlbie %0,0" : : "r"(va) : "memory");
    }
    asm volatile("eieio; tlbsync; ptesync" : : : "memory");
#else
    {
        unsigned i;
        ulong rb;

        for (i = 0; i < 256; i++) {
            rb = i;
            rb <<= 12;
            asm volatile("ptesync; tlbie %0,0; eieio; tlbsync; ptesync; isync"
                    : "=r" (rb): : "memory");
            asm volatile("ptesync; tlbie %0,1; eieio; tlbsync; ptesync; isync"
                    : "=r" (rb): : "memory");
        }
    }
#endif

}

static void h_enter(struct cpu_user_regs *regs)
{
    ulong flags = regs->gprs[4];
    ulong ptex = regs->gprs[5];

    union pte pte;
    union pte volatile *ppte;
    struct domain_htab *htab;
    int lp_bits = 0;
    int pgshift = PAGE_SHIFT;
    ulong idx;
    int limit = 0;                /* how many PTEs to examine in the PTEG */
    ulong lpn;
    ulong rpn;
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    int mtype;

    htab = &d->arch.htab;
    if (ptex > (1UL << htab->log_num_ptes)) {
        regs->gprs[3] = H_Parameter;
        printk("%s: bad ptex: 0x%lx\n", __func__, ptex);
        return;
    }

    /* use local HPTE to avoid manual shifting & masking */
    pte.words.vsid = regs->gprs[6];
    pte.words.rpn = regs->gprs[7];

    if ( pte.bits.l ) {        /* large page? */
        /* figure out the page size for the selected large page */
        ulong lp_rpn = pte.bits.rpn;
        uint lp_size = 0;

        while ( lp_rpn & 0x1 ) {
            lp_rpn >>= 1;
            lp_bits = ((lp_bits << 1) | 0x1);
            lp_size++;
        }

        if ( lp_size >= d->arch.large_page_sizes ) {
            printk("%s: attempt to use unsupported lp_size %d\n",
                   __func__, lp_size);
            regs->gprs[3] = H_Parameter;
            return;
        }

        /* get correct pgshift value */
        pgshift = d->arch.large_page_shift[lp_size];
    }

    /* get the correct logical RPN in terms of 4K pages need to mask
     * off lp bits and unused arpn bits if this is a large page */

    lpn = ~0ULL << (pgshift - 12);
    lpn = pte.bits.rpn & lpn;

    rpn = pfn2mfn(d, lpn, &mtype);

    if (mtype == PFN_TYPE_IO) {
        /* only a privilaged dom can access outside IO space */
        if ( !test_bit(_DOMF_privileged, &d->domain_flags) ) {
            regs->gprs[3] =  H_Privilege;
            printk("%s: unprivileged access to logical page: 0x%lx\n",
                   __func__, lpn);
            return;
        }

        if ( !((pte.bits.w == 0)
             && (pte.bits.i == 1)
             && (pte.bits.g == 1)) ) {
#ifdef DEBUG_FAIL
            printk("%s: expecting an IO WIMG "
                   "w=%x i=%d m=%d, g=%d\n word 0x%lx\n", __func__,
                   pte.bits.w, pte.bits.i, pte.bits.m, pte.bits.g,
                   pte.words.rpn);
#endif
            regs->gprs[3] =  H_Parameter;
            return;
        }
    }
    /* fixup the RPN field of our local PTE copy */
    pte.bits.rpn = rpn | lp_bits;

    /* clear reserved bits in high word */
    pte.bits.lock = 0x0;
    pte.bits.res = 0x0;

    /* clear reserved bits in low word */
    pte.bits.pp0 = 0x0;
    pte.bits.ts = 0x0;
    pte.bits.res2 = 0x0;

    if ( !(flags & H_EXACT) ) {
        /* PTEG (not specific PTE); clear 3 lowest bits */
        ptex &= ~0x7UL;
        limit = 7;
    }

        /* data manipulations should be done prior to the pte insertion. */
    if ( flags & H_ZERO_PAGE ) {
        memset((void *)(rpn << PAGE_SHIFT), 0, 1UL << pgshift);
    }

    if ( flags & H_ICACHE_INVALIDATE ) {
        ulong k;
        ulong addr = rpn << PAGE_SHIFT;

        for (k = 0; k < (1UL << pgshift); k += L1_CACHE_BYTES) {
            dcbst(addr + k);
            sync();
            icbi(addr + k);
            sync();
            isync();
        }
    }

    if ( flags & H_ICACHE_SYNCHRONIZE ) {
        ulong k;
        ulong addr = rpn << PAGE_SHIFT;
        for (k = 0; k < (1UL << pgshift); k += L1_CACHE_BYTES) {
            icbi(addr + k);
            sync();
            isync();
        }
    }

    for (idx = ptex; idx <= ptex + limit; idx++) {
        ppte = &htab->map[idx];

        if ( ppte->bits.v == 0 && ppte->bits.lock == 0) {
            /* got it */

            asm volatile(
                "std %1, 8(%0); eieio; std %2, 0(%0); ptesync"
                : 
                : "b" (ppte), "r" (pte.words.rpn), "r" (pte.words.vsid)
                : "memory");

            regs->gprs[3] = H_Success;
            regs->gprs[4] = idx;

            return;
        }
    }

    /* If the PTEG is full then no additional values are returned. */
    printk("%s: PTEG FULL\n", __func__);

    regs->gprs[3] = H_PTEG_Full;
}

static void h_protect(struct cpu_user_regs *regs)
{
    ulong flags = regs->gprs[4];
    ulong ptex = regs->gprs[5];
    ulong avpn = regs->gprs[6];
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    struct domain_htab *htab = &d->arch.htab;
    union pte volatile *ppte;
    union pte lpte;

#ifdef DEBUG
    printk("%s: flags: 0x%lx ptex: 0x%lx avpn: 0x%lx\n", __func__,
           flags, ptex, avpn);
#endif
    if ( ptex > (1UL << htab->log_num_ptes) ) {
        regs->gprs[3] = H_Parameter;
        printk("%s: bad ptex: 0x%lx\n", __func__, ptex);
        return;
    }
    ppte = &htab->map[ptex];

    lpte.words.vsid = ppte->words.vsid;
    lpte.words.rpn = ppte->words.rpn;

    /* the AVPN param occupies the bit-space of the word */
    if ( (flags & H_AVPN) && lpte.bits.avpn != avpn >> 7 ) {
#ifdef DEBUG_FAIL
        printk("%s: %p: AVPN check failed: 0x%lx, 0x%lx\n", __func__,
                ppte, lpte.words.vsid, lpte.words.rpn);
#endif
        regs->gprs[3] = H_Not_Found;
        return;
    }

    if (lpte.bits.v == 0) {
        /* the PAPR does not specify what to do here, this is because
         * we invalidate entires where the PAPR says to 0 the whole hi
         * dword, so the AVPN should catch this first */

#ifdef DEBUG_FAIL
        printk("%s: pte invalid\n", __func__);
#endif
        regs->gprs[3] =  H_Not_Found;
        return;
    }

    lpte.bits.v = 0;
    
    /* ppte->words.vsid = lpte.words.vsid; */
    asm volatile(
        "eieio; std %1, 0(%0); ptesync"
        : 
        : "b" (ppte), "r" (0)
        : "memory");

    pte_tlbie(&lpte, ptex);

    /* We never touch pp0, and PP bits in flags are in the right
     * order */
    lpte.bits.pp1 = flags & (H_PP1 | H_PP2);
    lpte.bits.n = (flags & H_N) ? 1 : 0;

    lpte.bits.v = 1;
    lpte.bits.r = 0;

    asm volatile(
        "std  %1, 8(%0); eieio; std %2, 0(%0); ptesync"
        : 
        : "b" (ppte), "r" (lpte.words.rpn), "r" (lpte.words.vsid)
        : "memory");

    regs->gprs[3] = H_Success;
}

static void h_clear_ref(struct cpu_user_regs *regs)
{
    ulong flags = regs->gprs[4];
    ulong ptex = regs->gprs[5];
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    struct domain_htab *htab = &d->arch.htab;
    union pte volatile *pte;
    union pte lpte;

#ifdef DEBUG
    printk("%s: flags: 0x%lx ptex: 0x%lx\n", __func__,
           flags, ptex);
#endif

    if (flags != 0) {
        printk("WARNING: %s: "
                "flags are undefined and should be 0: 0x%lx\n",
                __func__, flags);
    }

    if (ptex > (1UL << htab->log_num_ptes)) {
        regs->gprs[3] = H_Parameter;
        printk("%s: bad ptex: 0x%lx\n", __func__, ptex);
        return;
    }
    pte = &htab->map[ptex];
    lpte.words.rpn = pte->words.rpn;

    regs->gprs[4] = lpte.words.rpn;

    if (lpte.bits.r != 0) {
        lpte.bits.r = 0;

        asm volatile("std  %1, 8(%0); eieio; ptesync"
                : 
                : "b" (pte), "r" (lpte.words.rpn) : "memory");

        pte_tlbie(&lpte, ptex);
    }
    regs->gprs[3] = H_Success;
}

static void h_clear_mod(struct cpu_user_regs *regs)
{
    ulong flags = regs->gprs[4];
    ulong ptex = regs->gprs[5];
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    struct domain_htab *htab = &d->arch.htab;
    union pte volatile *pte;
    union pte lpte;

#ifdef DEBUG
    printk("%s: flags: 0x%lx ptex: 0x%lx\n", __func__,
           flags, ptex);
#endif
    if (flags != 0) {
        printk("WARNING: %s: "
                "flags are undefined and should be 0: 0x%lx\n",
                __func__, flags);
    }
    
    if (ptex > (1UL << htab->log_num_ptes)) {
        regs->gprs[3] = H_Parameter;
        printk("%s: bad ptex: 0x%lx\n", __func__, ptex);
        return;
    }
    pte = &htab->map[ptex];
    lpte.words.vsid = pte->words.vsid;
    lpte.words.rpn = pte->words.rpn;

    regs->gprs[3] = H_Success;
    regs->gprs[4] = lpte.words.rpn;

    if (lpte.bits.c != 0) {
        /* invalidate */
        asm volatile(
                "eieio; std %1, 0(%0); ptesync"
                : 
                : "b" (pte), "r" (0)
                : "memory");

        pte_tlbie(&lpte, ptex);

        lpte.bits.c = 0;
        asm volatile(
                "std  %1, 8(%0); eieio; std %2, 0(%0); ptesync"
                : 
                : "b" (pte), "r" (lpte.words.rpn), "r" (lpte.words.vsid)
                : "memory");
    }
}

static void h_remove(struct cpu_user_regs *regs)
{
    ulong flags = regs->gprs[4];
    ulong ptex = regs->gprs[5];
    ulong avpn = regs->gprs[6];
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    struct domain_htab *htab = &d->arch.htab;
    union pte volatile *pte;
    union pte lpte;

#ifdef DEBUG
    printk("%s: flags: 0x%lx ptex: 0x%lx avpn: 0x%lx\n", __func__,
           flags, ptex, avpn);
#endif
    if ( ptex > (1UL << htab->log_num_ptes) ) {
        regs->gprs[3] = H_Parameter;
        printk("%s: bad ptex: 0x%lx\n", __func__, ptex);
        return;
    }
    pte = &htab->map[ptex];
    lpte.words.vsid = pte->words.vsid;
    lpte.words.rpn = pte->words.rpn;

    if ((flags & H_AVPN) && lpte.bits.avpn != (avpn >> 7)) {
#ifdef DEBUG_FAIL
        printk("%s: avpn doesn not match\n", __func__);
#endif
        regs->gprs[3] = H_Not_Found;
        return;
    }

    if ((flags & H_ANDCOND) && ((avpn & pte->words.vsid) != 0)) {
#ifdef DEBUG_FAIL
        printk("%s: andcond does not match\n", __func__);
#endif
        regs->gprs[3] = H_Not_Found;
        return;
    }

    regs->gprs[3] = H_Success;
    /* return old PTE in regs 4 and 5 */
    regs->gprs[4] = lpte.words.vsid;
    regs->gprs[5] = lpte.words.rpn;

    /* XXX - I'm very skeptical of doing ANYTHING if not bits.v */
    /* XXX - I think the spec should be questioned in this case (MFM) */
    if (pte->bits.v == 0) {
        printk("%s: removing invalid entry\n", __func__);
    }
    asm volatile("eieio; std %1, 0(%0); ptesync"
            :
            : "b" (pte), "r" (0)
            : "memory");

    pte_tlbie(&lpte, ptex);
}

__init_papr_hcall(H_ENTER, h_enter);
__init_papr_hcall(H_READ, not_yet);
__init_papr_hcall(H_REMOVE, h_remove);
__init_papr_hcall(H_CLEAR_MOD, h_clear_mod);
__init_papr_hcall(H_CLEAR_REF, h_clear_ref);
__init_papr_hcall(H_PROTECT, h_protect);
