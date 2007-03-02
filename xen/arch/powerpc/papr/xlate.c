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
#undef DEBUG_LOW

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/papr.h>
#include <asm/hcalls.h>
#include <asm/platform.h>

#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
#else
#define DBG(fmt...)
#endif
#ifdef DEBUG_LOW
#define DBG_LOW(fmt...) printk(fmt)
#else
#define DBG_LOW(fmt...)
#endif

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

/*
 * POWER Arch 2.03 Sec 4.12.1 (Yes 970 is one)
 *
 *   when a tlbsync instruction has been executed by a processor in a
 *   given partition, a ptesync instruction must be executed by that
 *   processor before a tlbie or tlbsync instruction is executed by
 *   another processor in that partition.
 *
 * So for now, here is a BFLock to deal with it, the lock should be per-domain.
 *
 * XXX Will need to audit all tlb usege soon enough.
 */

static DEFINE_SPINLOCK(native_tlbie_lock);
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

    spin_lock(&native_tlbie_lock);
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
    spin_unlock(&native_tlbie_lock);
}

long pte_enter(ulong flags, ulong ptex, ulong vsid, ulong rpn)
{
    union pte pte;
    union pte volatile *ppte;
    struct domain_htab *htab;
    int lp_bits = 0;
    int pgshift = PAGE_SHIFT;
    ulong idx;
    int limit = 0;                /* how many PTEs to examine in the PTEG */
    ulong pfn;
    ulong mfn;
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    int mtype;
    struct page_info *pg = NULL;
    struct domain *f = NULL;


    htab = &d->arch.htab;
    if (ptex > (1UL << htab->log_num_ptes)) {
        DBG("%s: bad ptex: 0x%lx\n", __func__, ptex);
        return H_Parameter;
    }

    /* use local HPTE to avoid manual shifting & masking */
    pte.words.vsid = vsid;
    pte.words.rpn = rpn;

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
            DBG("%s: attempt to use unsupported lp_size %d\n",
                __func__, lp_size);
            return H_Parameter;
        }

        /* get correct pgshift value */
        pgshift = d->arch.large_page_order[lp_size] + PAGE_SHIFT;
    }

    /* get the correct logical RPN in terms of 4K pages need to mask
     * off lp bits and unused arpn bits if this is a large page */

    pfn = ~0ULL << (pgshift - PAGE_SHIFT);
    pfn = pte.bits.rpn & pfn;

    mfn = pfn2mfn(d, pfn, &mtype);
    if (mfn == INVALID_MFN) {
        DBG("%s: Bad PFN: 0x%lx\n", __func__, pfn);
        return H_Parameter;
    }

    if (mtype == PFN_TYPE_IO && !d->is_privileged) {
        /* only a privilaged dom can access outside IO space */
        DBG("%s: unprivileged access to physical page: 0x%lx\n",
            __func__, pfn);
        return H_Privilege;
    }
    if (mtype == PFN_TYPE_IO) {
        if ( !((pte.bits.w == 0)
             && (pte.bits.i == 1)
             && (pte.bits.g == 1)) ) {
            DBG("%s: expecting an IO WIMG "
                "w=%x i=%d m=%d, g=%d\n word 0x%lx\n", __func__,
                pte.bits.w, pte.bits.i, pte.bits.m, pte.bits.g,
                pte.words.rpn);
            return H_Parameter;
        }
    }
    if (mtype == PFN_TYPE_GNTTAB) {
        DBG("%s: Dom[%d] mapping grant table: 0x%lx\n",
            __func__, d->domain_id, pfn << PAGE_SHIFT);
        pte.bits.i = 0;
        pte.bits.g = 0;
    }
    /* fixup the RPN field of our local PTE copy */
    pte.bits.rpn = mfn | lp_bits;

    /* clear reserved bits in high word */
    pte.bits.lock = 0x0;
    pte.bits.res = 0x0;

    /* clear reserved bits in low word */
    pte.bits.pp0 = 0x0;
    pte.bits.ts = 0x0;
    pte.bits.res2 = 0x0;

    if (mtype == PFN_TYPE_FOREIGN) {
        pg = mfn_to_page(mfn);
        f = page_get_owner(pg);
        
        BUG_ON(f == d);

        if (unlikely(!get_domain(f))) {
            DBG("%s: Rescinded, no domain: 0x%lx\n",  __func__, pfn);
            return H_Rescinded;
        }
        if (unlikely(!get_page(pg, f))) {
            put_domain(f);
            DBG("%s: Rescinded, no page: 0x%lx\n",  __func__, pfn);
            return H_Rescinded;
        }
    }

    if ( !(flags & H_EXACT) ) {
        /* PTEG (not specific PTE); clear 3 lowest bits */
        ptex &= ~0x7UL;
        limit = 7;
    }

    /* data manipulations should be done prior to the pte insertion. */
    if ( flags & H_ZERO_PAGE ) {
        ulong pg = mfn << PAGE_SHIFT;
        ulong pgs = 1UL << pgshift;

        while (pgs > 0) {
            clear_page((void *)pg);
            pg += PAGE_SIZE;
            --pgs;
        }
    }

    if ( flags & H_ICACHE_INVALIDATE ) {
        ulong k;
        ulong addr = mfn << PAGE_SHIFT;

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
        ulong addr = mfn << PAGE_SHIFT;
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

            return idx;
        }
    }

    /* If the PTEG is full then no additional values are returned. */
    DBG("%s: PTEG FULL\n", __func__);

    if (pg != NULL)
        put_page(pg);

    if (f != NULL)
        put_domain(f);

    return H_PTEG_Full;
}

static void h_enter(struct cpu_user_regs *regs)
{
    ulong flags = regs->gprs[4];
    ulong ptex = regs->gprs[5];
    ulong vsid = regs->gprs[6];
    ulong rpn = regs->gprs[7];
    long ret;

    ret = pte_enter(flags, ptex, vsid, rpn);

    if (ret >= 0) {
        regs->gprs[3] = H_Success;
        regs->gprs[4] = ret;
    } else
        regs->gprs[3] = ret;
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

    DBG_LOW("%s: flags: 0x%lx ptex: 0x%lx avpn: 0x%lx\n", __func__,
            flags, ptex, avpn);
    if ( ptex > (1UL << htab->log_num_ptes) ) {
        DBG("%s: bad ptex: 0x%lx\n", __func__, ptex);
        regs->gprs[3] = H_Parameter;
        return;
    }
    ppte = &htab->map[ptex];

    lpte.words.vsid = ppte->words.vsid;
    lpte.words.rpn = ppte->words.rpn;

    /* the AVPN param occupies the bit-space of the word */
    if ( (flags & H_AVPN) && lpte.bits.avpn != avpn >> 7 ) {
        DBG_LOW("%s: %p: AVPN check failed: 0x%lx, 0x%lx\n", __func__,
            ppte, lpte.words.vsid, lpte.words.rpn);
        regs->gprs[3] = H_Not_Found;
        return;
    }

    if (lpte.bits.v == 0) {
        /* the PAPR does not specify what to do here, this is because
         * we invalidate entires where the PAPR says to 0 the whole hi
         * dword, so the AVPN should catch this first */

        DBG("%s: pte invalid\n", __func__);
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
    ulong ptex = regs->gprs[5];
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    struct domain_htab *htab = &d->arch.htab;
    union pte volatile *pte;
    union pte lpte;

    DBG_LOW("%s: flags: 0x%lx ptex: 0x%lx\n", __func__,
            regs->gprs[4], ptex);

#ifdef DEBUG
    if (regs->gprs[4] != 0) {
        DBG("WARNING: %s: "
            "flags are undefined and should be 0: 0x%lx\n",
            __func__, regs->gprs[4]);
    }
#endif

    if (ptex > (1UL << htab->log_num_ptes)) {
        DBG("%s: bad ptex: 0x%lx\n", __func__, ptex);
        regs->gprs[3] = H_Parameter;
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
    ulong ptex = regs->gprs[5];
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    struct domain_htab *htab = &d->arch.htab;
    union pte volatile *pte;
    union pte lpte;

    DBG_LOW("%s: flags: 0x%lx ptex: 0x%lx\n", __func__,
          regs->gprs[4], ptex);

#ifdef DEBUG
    if (regs->gprs[4] != 0) {
        DBG("WARNING: %s: "
            "flags are undefined and should be 0: 0x%lx\n",
            __func__, regs->gprs[4]);
    }
#endif

    if (ptex > (1UL << htab->log_num_ptes)) {
        DBG("%s: bad ptex: 0x%lx\n", __func__, ptex);
        regs->gprs[3] = H_Parameter;
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

long pte_remove(ulong flags, ulong ptex, ulong avpn, ulong *hi, ulong *lo)
{
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    struct domain_htab *htab = &d->arch.htab;
    union pte volatile *pte;
    union pte lpte;

    DBG_LOW("%s: flags: 0x%lx ptex: 0x%lx avpn: 0x%lx\n", __func__,
            flags, ptex, avpn);

    if ( ptex > (1UL << htab->log_num_ptes) ) {
        DBG("%s: bad ptex: 0x%lx\n", __func__, ptex);
        return H_Parameter;
    }
    pte = &htab->map[ptex];
    lpte.words.vsid = pte->words.vsid;
    lpte.words.rpn = pte->words.rpn;

    if ((flags & H_AVPN) && lpte.bits.avpn != (avpn >> 7)) {
        DBG_LOW("%s: AVPN does not match\n", __func__);
        return H_Not_Found;
    }

    if ((flags & H_ANDCOND) && ((avpn & pte->words.vsid) != 0)) {
        DBG("%s: andcond does not match\n", __func__);
        return H_Not_Found;
    }

    /* return old PTE in regs 4 and 5 */
    *hi = lpte.words.vsid;
    *lo = lpte.words.rpn;

#ifdef DEBUG_LOW
    /* XXX - I'm very skeptical of doing ANYTHING if not bits.v */
    /* XXX - I think the spec should be questioned in this case (MFM) */
    if (lpte.bits.v == 0) {
        DBG_LOW("%s: removing invalid entry\n", __func__);
    }
#endif

    if (lpte.bits.v) {
        ulong mfn = lpte.bits.rpn;
        if (!platform_io_mfn(mfn)) {
            struct page_info *pg = mfn_to_page(mfn);
            struct domain *f = page_get_owner(pg);
            
            if (f != d) {
                put_domain(f);
                put_page(pg);
            }
        }
    }

    asm volatile("eieio; std %1, 0(%0); ptesync"
            :
            : "b" (pte), "r" (0)
            : "memory");

    pte_tlbie(&lpte, ptex);

    return H_Success;
}

static void h_remove(struct cpu_user_regs *regs)
{
    ulong flags = regs->gprs[4];
    ulong ptex = regs->gprs[5];
    ulong avpn = regs->gprs[6];
    ulong hi, lo;
    long ret;

    ret = pte_remove(flags, ptex, avpn, &hi, &lo);

    regs->gprs[3] = ret;

    if (ret == H_Success) {
        regs->gprs[4] = hi;
        regs->gprs[5] = lo;
    }
    return;
}

static void h_read(struct cpu_user_regs *regs)
{
    ulong flags = regs->gprs[4];
    ulong ptex = regs->gprs[5];
    struct vcpu *v = get_current();
    struct domain *d = v->domain;
    struct domain_htab *htab = &d->arch.htab;
    union pte volatile *pte;

    if (flags & H_READ_4)
        ptex &= ~0x3UL;

    if (ptex > (1UL << htab->log_num_ptes)) {
        DBG("%s: bad ptex: 0x%lx\n", __func__, ptex);
        regs->gprs[3] = H_Parameter;
        return;
    }
    pte = &htab->map[ptex];
    regs->gprs[4] = pte[0].words.vsid;
    regs->gprs[5] = pte[0].words.rpn;

    if (!(flags & H_READ_4)) {
        /* dump another 3 PTEs */
        regs->gprs[6] = pte[1].words.vsid;
        regs->gprs[7] = pte[1].words.rpn;
        regs->gprs[8] = pte[2].words.vsid;
        regs->gprs[9] = pte[2].words.rpn;
        regs->gprs[10] = pte[3].words.vsid;
        regs->gprs[11] = pte[3].words.rpn;
    }

    regs->gprs[3] = H_Success;
}

__init_papr_hcall(H_ENTER, h_enter);
__init_papr_hcall(H_READ, h_read);
__init_papr_hcall(H_REMOVE, h_remove);
__init_papr_hcall(H_CLEAR_MOD, h_clear_mod);
__init_papr_hcall(H_CLEAR_REF, h_clear_ref);
__init_papr_hcall(H_PROTECT, h_protect);
