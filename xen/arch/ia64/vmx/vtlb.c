/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vtlb.c: guest virtual tlb handling module.
 * Copyright (c) 2004, Intel Corporation.
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
 *
 *  Yaozu Dong (Eddie Dong) (Eddie.dong@intel.com)
 *  XiaoYan Feng (Fleming Feng) (Fleming.feng@intel.com)
 */

#include <asm/vmx_vcpu.h>
#include <asm/vmx_phy_mode.h>
#include <asm/shadow.h>

static u64 translate_phy_pte(VCPU *v, u64 pte, u64 itir, u64 va);
static thash_data_t *__alloc_chain(thash_cb_t *);

static inline void cch_mem_init(thash_cb_t *hcb)
{
    hcb->cch_free_idx = 0;
    hcb->cch_freelist = NULL;
}

static thash_data_t *cch_alloc(thash_cb_t *hcb)
{
    thash_data_t *p;
    if ( (p = hcb->cch_freelist) != NULL ) {
        hcb->cch_freelist = p->next;
        return p;
    }
    if (hcb->cch_free_idx < hcb->cch_sz/sizeof(thash_data_t)) {
        p = &((thash_data_t *)hcb->cch_buf)[hcb->cch_free_idx++];
        p->page_flags = 0;
        p->itir = 0;
        p->next = NULL;
        return p;
    }
    return NULL;
}

/*
 * Check to see if the address rid:va is translated by the TLB
 */

static inline int __is_tr_translated(thash_data_t *trp, u64 rid, u64 va)
{
    return (trp->p) && (trp->rid == rid) && ((va-trp->vadr) < PSIZE(trp->ps));
}

/*
 * Only for GUEST TR format.
 */
static int
__is_tr_overlap(thash_data_t *trp, u64 rid, u64 sva, u64 eva)
{
    uint64_t sa1, ea1;

    if (!trp->p || trp->rid != rid ) {
        return 0;
    }
    sa1 = trp->vadr;
    ea1 = sa1 + PSIZE(trp->ps) - 1;
    eva -= 1;
    if (sva > ea1 || sa1 > eva)
        return 0;
    else
        return 1;

}

static thash_data_t *__vtr_lookup(VCPU *vcpu, u64 va, int is_data)
{

    thash_data_t *trp;
    int i;
    u64 rid;

    vcpu_get_rr(vcpu, va, &rid);
    rid &= RR_RID_MASK;
    if (is_data) {
        if (vcpu_quick_region_check(vcpu->arch.dtr_regions,va)) {
            trp = (thash_data_t *)vcpu->arch.dtrs;
            for (i = 0;  i < NDTRS; i++, trp++) {
                if (__is_tr_translated(trp, rid, va)) {
                    return trp;
                }
            }
        }
    }
    else {
        if (vcpu_quick_region_check(vcpu->arch.itr_regions,va)) {
            trp = (thash_data_t *)vcpu->arch.itrs;
            for (i = 0; i < NITRS; i++, trp++) {
                if (__is_tr_translated(trp, rid, va)) {
                    return trp;
                }
            }
        }
    }
    return NULL;
}

static void thash_recycle_cch(thash_cb_t *hcb, thash_data_t *hash,
                              thash_data_t *tail)
{
    thash_data_t *head = hash->next;

    hash->next = 0;
    tail->next = hcb->cch_freelist;
    hcb->cch_freelist = head;
}

static void vmx_vhpt_insert(thash_cb_t *hcb, u64 pte, u64 itir, u64 ifa)
{
    u64 tag, len;
    ia64_rr rr;
    thash_data_t *head, *cch;

    pte &= ((~PAGE_FLAGS_RV_MASK)|_PAGE_VIRT_D);
    rr.rrval = ia64_get_rr(ifa);
    head = (thash_data_t *)ia64_thash(ifa);
    tag = ia64_ttag(ifa);

    if (!INVALID_VHPT(head)) {
        /* Find a free (ie invalid) entry.  */
        len = 0;
        cch = head;
        do {
            ++len;
            if (cch->next == NULL) {
                if (len >= MAX_CCN_DEPTH) {
                    thash_recycle_cch(hcb, head, cch);
                    cch = cch_alloc(hcb);
                } else {
                    cch = __alloc_chain(hcb);
                }
                cch->next = head->next;
                head->next = cch;
                break;
            }
            cch = cch->next;
        } while (!INVALID_VHPT(cch));

        /* As we insert in head, copy head.  */
        local_irq_disable();
        cch->page_flags = head->page_flags;
        cch->itir = head->itir;
        cch->etag = head->etag;
        head->ti = 1;
        local_irq_enable();
    }
    /* here head is invalid. */
    wmb();
    head->page_flags=pte;
    head->itir = rr.ps << 2;
    *(volatile unsigned long*)&head->etag = tag;
    return;
}

void thash_vhpt_insert(VCPU *v, u64 pte, u64 itir, u64 va, int type)
{
    u64 phy_pte, psr;
    ia64_rr mrr;

    phy_pte = translate_phy_pte(v, pte, itir, va);
    mrr.rrval = ia64_get_rr(va);

    if (itir_ps(itir) >= mrr.ps && VMX_MMU_MODE(v) != VMX_MMU_PHY_D) {
        vmx_vhpt_insert(vcpu_get_vhpt(v), phy_pte, itir, va);
    } else {
        if (VMX_MMU_MODE(v) == VMX_MMU_PHY_D)
            itir = (itir & ~RR_PS_MASK) | (mrr.rrval & RR_PS_MASK);
        phy_pte &= ~PAGE_FLAGS_RV_MASK; /* Clear reserved fields.  */
        psr = ia64_clear_ic();
        ia64_itc(type + 1, va, phy_pte, itir);
        ia64_set_psr(psr);
        ia64_srlz_i();
    }
}

/* On itr.d, old entries are not purged (optimization for Linux - see
   vmx_vcpu_itr_d).  Fixup possible mismatch.  */
int vhpt_access_rights_fixup(VCPU *v, u64 ifa, int is_data)
{
    thash_data_t *trp, *data;
    u64 ps, tag, mask;

    trp = __vtr_lookup(v, ifa, is_data);
    if (trp) {
        ps = _REGION_PAGE_SIZE(ia64_get_rr(ifa));
        if (trp->ps < ps)
            return 0;
        ifa = PAGEALIGN(ifa, ps);
        data = (thash_data_t *)ia64_thash(ifa);
        tag = ia64_ttag(ifa);
        do {
            if (data->etag == tag) {
                mask = trp->page_flags & PAGE_FLAGS_AR_PL_MASK;
                if (mask != (data->page_flags & PAGE_FLAGS_AR_PL_MASK)) {
                    data->page_flags &= ~PAGE_FLAGS_AR_PL_MASK;
                    data->page_flags |= mask;
                    machine_tlb_purge(ifa, ps);
                    return 1;
                }
                return 0;
            }
            data = data->next;
        } while(data);
    }
    return 0;
}

/*
 *   vhpt lookup
 */

thash_data_t * vhpt_lookup(u64 va)
{
    thash_data_t *hash, *head;
    u64 tag, pte, itir;

    head = (thash_data_t *)ia64_thash(va);
    hash = head;
    tag = ia64_ttag(va);
    do {
        if (hash->etag == tag)
            break;
        hash = hash->next;
    } while(hash);
    if (hash && hash != head) {
        /* Put the entry on the front of the list (ie swap hash and head).  */
        pte = hash->page_flags;
        hash->page_flags = head->page_flags;
        head->page_flags = pte;

        tag = hash->etag;
        hash->etag = head->etag;
        head->etag = tag;

        itir = hash->itir;
        hash->itir = head->itir;
        head->itir = itir;

        return head;
    }
    return hash;
}

u64 guest_vhpt_lookup(u64 iha, u64 *pte)
{
    u64 ret, tmp;
    thash_data_t * data;

    /* Try to fill mTLB for the gVHPT entry.  */
    data = vhpt_lookup(iha);
    if (data == NULL) {
        data = __vtr_lookup(current, iha, DSIDE_TLB);
        if (data != NULL)
            thash_vhpt_insert(current, data->page_flags, data->itir,
                              iha, DSIDE_TLB);
    }

    asm volatile ("rsm psr.ic|psr.i;;"
                  "srlz.d;;"
                  "ld8.s %1=[%2];;"		/* Read VHPT entry.  */
                  "tnat.nz p6,p7=%1;;"		/* Success ?  */
                  "(p6) mov %0=1;"		/* No -> ret = 1.  */
                  "(p6) mov %1=r0;"
                  "(p7) extr.u %1=%1,0,53;;"	/* Yes -> mask ig bits.  */
                  "(p7) mov %0=r0;"		/*     -> ret = 0.  */
                  "(p7) st8 [%3]=%1;;"		/*     -> save.  */
                  "ssm psr.ic;;"
                  "srlz.d;;"
                  "ssm psr.i;;"
                  : "=r"(ret), "=r"(tmp)
                  : "r"(iha), "r"(pte):"memory","p6","p7");
    return ret;
}

static thash_data_t * vtlb_thash(PTA vpta, u64 va, u64 vrr, u64 *tag)
{
    u64 index, pfn, rid;

    pfn = REGION_OFFSET(va) >> _REGION_PAGE_SIZE(vrr);
    rid = _REGION_ID(vrr);
    index = (pfn ^ rid) & ((1UL << (vpta.size - 5)) - 1);
    *tag = pfn ^ (rid << 39);
    return (thash_data_t *)((vpta.base << PTA_BASE_SHIFT) + (index << 5));
}

/*
 *  purge software guest tlb
 */

static void vtlb_purge(VCPU *v, u64 va, u64 ps)
{
    thash_data_t *cur;
    u64 start, curadr, size, psbits, tag, rr_ps, num;
    ia64_rr vrr;
    thash_cb_t *hcb = &v->arch.vtlb;

    vcpu_get_rr(v, va, &vrr.rrval);
    psbits = VMX(v, psbits[(va >> 61)]);
    start = va & ~((1UL << ps) - 1);
    while (psbits) {
        curadr = start;
        rr_ps = __ffs(psbits);
        psbits &= ~(1UL << rr_ps);
        num = 1UL << ((ps < rr_ps) ? 0 : (ps - rr_ps));
        size = PSIZE(rr_ps);
        vrr.ps = rr_ps;
        while (num) {
            cur = vtlb_thash(hcb->pta, curadr, vrr.rrval, &tag);
            while (cur) {
                if (cur->etag == tag && cur->ps == rr_ps) {
                    cur->etag = 1UL << 63;
                    break;
                }
                cur = cur->next;
            }
            curadr += size;
            num--;
        }
    }
}


/*
 *  purge VHPT and machine TLB
 */
static void vhpt_purge(VCPU *v, u64 va, u64 ps)
{
    //thash_cb_t *hcb = &v->arch.vhpt;
    thash_data_t *cur;
    u64 start, size, tag, num;
    ia64_rr rr;
    
    start = va & ~((1UL << ps) - 1);
    rr.rrval = ia64_get_rr(va);  
    size = PSIZE(rr.ps);
    num = 1UL << ((ps < rr.ps) ? 0 : (ps - rr.ps));
    while (num) {
        cur = (thash_data_t *)ia64_thash(start);
        tag = ia64_ttag(start);
        while (cur) {
            if (cur->etag == tag) {
                cur->etag = 1UL << 63; 
                break;
            }
            cur = cur->next;
        }
        start += size;
        num--;
    }
    machine_tlb_purge(va, ps);
}

/*
 * Recycle all collisions chain in VTLB or VHPT.
 *
 */
void thash_recycle_cch_all(thash_cb_t *hcb)
{
    int num;
    thash_data_t *head;

    head = hcb->hash;
    num = (hcb->hash_sz/sizeof(thash_data_t));
    do {
        head->next = 0;
        head++;
        num--;
    } while(num);
    cch_mem_init(hcb);
}


static thash_data_t *__alloc_chain(thash_cb_t *hcb)
{
    thash_data_t *cch;

    cch = cch_alloc(hcb);
    if (cch == NULL) {
        thash_recycle_cch_all(hcb);
        cch = cch_alloc(hcb);
    }
    return cch;
}

/*
 * Insert an entry into hash TLB or VHPT.
 * NOTES:
 *  1: When inserting VHPT to thash, "va" is a must covered
 *  address by the inserted machine VHPT entry.
 *  2: The format of entry is always in TLB.
 *  3: The caller need to make sure the new entry will not overlap
 *     with any existed entry.
 */
static void vtlb_insert(VCPU *v, u64 pte, u64 itir, u64 va)
{
    thash_data_t *hash_table, *cch, *tail;
    /* int flag; */
    ia64_rr vrr;
    /* u64 gppn, ppns, ppne; */
    u64 tag, len;
    thash_cb_t *hcb = &v->arch.vtlb;

    vcpu_quick_region_set(PSCBX(v, tc_regions), va);

    vcpu_get_rr(v, va, &vrr.rrval);
    vrr.ps = itir_ps(itir);
    VMX(v, psbits[va >> 61]) |= (1UL << vrr.ps);
    hash_table = vtlb_thash(hcb->pta, va, vrr.rrval, &tag);
    len = 0;
    cch = hash_table;
    do {
        if (INVALID_TLB(cch)) {
            cch->page_flags = pte;
            cch->itir = itir;
            cch->etag = tag;
            return;
        }
        ++len;
        tail = cch;
        cch = cch->next;
    } while(cch);
    if (len >= MAX_CCN_DEPTH) {
        thash_recycle_cch(hcb, hash_table, tail);
        cch = cch_alloc(hcb);
    }
    else {
        cch = __alloc_chain(hcb);
    }
    cch->page_flags = pte;
    cch->itir = itir;
    cch->etag = tag;
    cch->next = hash_table->next;
    wmb();
    hash_table->next = cch;
    return;
}


int vtr_find_overlap(VCPU *vcpu, u64 va, u64 ps, int is_data)
{
    thash_data_t  *trp;
    int  i;
    u64 end, rid;

    vcpu_get_rr(vcpu, va, &rid);
    rid &= RR_RID_MASK;
    end = va + PSIZE(ps);
    if (is_data) {
        if (vcpu_quick_region_check(vcpu->arch.dtr_regions, va)) {
            trp = (thash_data_t *)vcpu->arch.dtrs;
            for (i = 0; i < NDTRS; i++, trp++) {
                if (__is_tr_overlap(trp, rid, va, end )) {
                    return i;
                }
            }
        }
    }
    else {
        if (vcpu_quick_region_check(vcpu->arch.itr_regions,va)) {
            trp = (thash_data_t *)vcpu->arch.itrs;
            for (i = 0; i < NITRS; i++, trp++) {
                if (__is_tr_overlap(trp, rid, va, end )) {
                    return i;
                }
            }
        }
    }
    return -1;
}

/*
 * Purge entries in VTLB and VHPT
 */
void thash_purge_entries(VCPU *v, u64 va, u64 ps)
{
    if (vcpu_quick_region_check(v->arch.tc_regions, va))
        vtlb_purge(v, va, ps);
    vhpt_purge(v, va, ps);
}

void thash_purge_entries_remote(VCPU *v, u64 va, u64 ps)
{
    u64 old_va = va;
    va = REGION_OFFSET(va);
    if (vcpu_quick_region_check(v->arch.tc_regions, old_va))
        vtlb_purge(v, va, ps);
    vhpt_purge(v, va, ps);
}

static u64 translate_phy_pte(VCPU *v, u64 pte, u64 itir, u64 va)
{
    u64 ps, ps_mask, paddr, maddr;
    union pte_flags phy_pte;
    struct domain *d = v->domain;

    ps = itir_ps(itir);
    ps_mask = ~((1UL << ps) - 1);
    phy_pte.val = pte;
    paddr = ((pte & _PAGE_PPN_MASK) & ps_mask) | (va & ~ps_mask);
    maddr = lookup_domain_mpa(d, paddr, NULL);
    if (maddr & _PAGE_IO)
        return -1;

    /* Ensure WB attribute if pte is related to a normal mem page,
     * which is required by vga acceleration since qemu maps shared
     * vram buffer with WB.
     */
    if (mfn_valid(pte_pfn(__pte(maddr))) && phy_pte.ma != VA_MATTR_NATPAGE)
        phy_pte.ma = VA_MATTR_WB;

    maddr = ((maddr & _PAGE_PPN_MASK) & PAGE_MASK) | (paddr & ~PAGE_MASK);
    phy_pte.ppn = maddr >> ARCH_PAGE_SHIFT;

    /* If shadow mode is enabled, virtualize dirty bit.  */
    if (shadow_mode_enabled(d) && phy_pte.d) {
        u64 gpfn = paddr >> PAGE_SHIFT;
        phy_pte.val |= _PAGE_VIRT_D;

        /* If the page is not already dirty, don't set the dirty bit! */
        if (gpfn < d->arch.shadow_bitmap_size * 8
            && !test_bit(gpfn, d->arch.shadow_bitmap))
            phy_pte.d = 0;
    }

    return phy_pte.val;
}


/*
 * Purge overlap TCs and then insert the new entry to emulate itc ops.
 *    Notes: Only TC entry can purge and insert.
 *    1 indicates this is MMIO
 */
int thash_purge_and_insert(VCPU *v, u64 pte, u64 itir, u64 ifa, int type)
{
    u64 ps, phy_pte, psr;
    ia64_rr mrr;

    ps = itir_ps(itir);
    mrr.rrval = ia64_get_rr(ifa);

    phy_pte = translate_phy_pte(v, pte, itir, ifa);

    vtlb_purge(v, ifa, ps);
    vhpt_purge(v, ifa, ps);

    if (phy_pte == -1) {
        vtlb_insert(v, pte, itir, ifa);
        return 1;
    }

    if (ps != mrr.ps)
        vtlb_insert(v, pte, itir, ifa);

    if (ps >= mrr.ps) {
        vmx_vhpt_insert(&v->arch.vhpt, phy_pte, itir, ifa);
    } else { /* Subpaging */
        phy_pte &= ~PAGE_FLAGS_RV_MASK;
        psr = ia64_clear_ic();
        ia64_itc(type + 1, ifa, phy_pte, IA64_ITIR_PS_KEY(ps, 0));
        ia64_set_psr(psr);
        ia64_srlz_i();
    }
    return 0;
}

/*
 * Purge all TCs or VHPT entries including those in Hash table.
 *
 */

//TODO: add sections.
void thash_purge_all(VCPU *v)
{
    int num;
    thash_data_t *head;
    thash_cb_t  *vtlb,*vhpt;
    vtlb = &v->arch.vtlb;
    vhpt = &v->arch.vhpt;

    for (num = 0; num < 8; num++)
        VMX(v, psbits[num]) = 0;
    
    head = vtlb->hash;
    num = (vtlb->hash_sz/sizeof(thash_data_t));
    do{
        head->page_flags = 0;
        head->etag = 1UL<<63;
        head->itir = 0;
        head->next = 0;
        head++;
        num--;
    } while(num);
    cch_mem_init(vtlb);
    
    head = vhpt->hash;
    num = (vhpt->hash_sz/sizeof(thash_data_t));
    do{
        head->page_flags = 0;
        head->etag = 1UL<<63;
        head->next = 0;
        head++;
        num--;
    } while(num);
    cch_mem_init(vhpt);
    local_flush_tlb_all();
}

static void __thash_purge_all(void *arg)
{
    struct vcpu *v = arg;

    BUG_ON(vcpu_runnable(v) || v->is_running);
    thash_purge_all(v);
}

void vmx_vcpu_flush_vtlb_all(VCPU *v)
{
    if (v == current) {
        thash_purge_all(v);
        return;
    }

    /* SMP safe */
    vcpu_pause(v);
    if (v->processor == smp_processor_id())
        __thash_purge_all(v);
    else
        smp_call_function_single(v->processor, __thash_purge_all, v, 1);
    vcpu_unpause(v);
}


/*
 * Lookup the hash table and its collision chain to find an entry
 * covering this address rid:va or the entry.
 *
 * INPUT:
 *  in: TLB format for both VHPT & TLB.
 */

thash_data_t *vtlb_lookup(VCPU *v, u64 va,int is_data)
{
    thash_data_t *cch;
    u64 psbits, ps, tag;
    ia64_rr vrr;
    thash_cb_t *hcb = &v->arch.vtlb;

    cch = __vtr_lookup(v, va, is_data);
    if (cch)
        return cch;

    if (vcpu_quick_region_check(v->arch.tc_regions, va) == 0)
        return NULL;
    psbits = VMX(v, psbits[(va >> 61)]);
    vcpu_get_rr(v, va, &vrr.rrval);
    while (psbits) {
        ps = __ffs(psbits);
        psbits &= ~(1UL << ps);
        vrr.ps = ps;
        cch = vtlb_thash(hcb->pta, va, vrr.rrval, &tag);
        do {
            if (cch->etag == tag && cch->ps == ps)
                goto found;
            cch = cch->next;
        } while(cch);
    }
    return NULL;
found:
    if (unlikely(!cch->ed && is_data == ISIDE_TLB)) {
        /*The case is very rare, and it may lead to incorrect setting
          for itlb's ed bit! Purge it from hash vTLB and let guest os
          determin the ed bit of the itlb entry.*/
        vtlb_purge(v, va, ps);
        cch = NULL;
    }
    return cch;
}


/*
 * Initialize internal control data before service.
 */
static void thash_init(thash_cb_t *hcb, u64 sz)
{
    int num;
    thash_data_t *head;

    hcb->pta.val = (unsigned long)hcb->hash;
    hcb->pta.vf = 1;
    hcb->pta.ve = 1;
    hcb->pta.size = sz;
    
    head = hcb->hash;
    num = (hcb->hash_sz/sizeof(thash_data_t));
    do {
        head->page_flags = 0;
        head->itir = 0;
        head->etag = 1UL << 63;
        head->next = 0;
        head++;
        num--;
    } while(num);

    hcb->cch_free_idx = 0;
    hcb->cch_freelist = NULL;
}

int thash_alloc(thash_cb_t *hcb, u64 sz_log2, char *what)
{
    struct page_info *page;
    void * vbase;
    u64 sz = 1UL << sz_log2;

    page = alloc_domheap_pages(NULL, (sz_log2 + 1 - PAGE_SHIFT), 0);
    if (page == NULL) {
        printk("No enough contiguous memory(%ldKB) for init_domain_%s\n", 
               sz >> (10 - 1), what);
        return -ENOMEM;
    }
    vbase = page_to_virt(page);
    memset(vbase, 0, sz + sz); // hash + collisions chain
    if (sz_log2 >= 20 - 1)
        printk(XENLOG_DEBUG "Allocate domain %s at 0x%p(%ldMB)\n", 
               what, vbase, sz >> (20 - 1));
    else
        printk(XENLOG_DEBUG "Allocate domain %s at 0x%p(%ldKB)\n",
               what, vbase, sz >> (10 - 1));
    
    hcb->hash = vbase;
    hcb->hash_sz = sz;
    hcb->cch_buf = (void *)((u64)vbase + hcb->hash_sz);
    hcb->cch_sz = sz;
    thash_init(hcb, sz_log2);
    return 0;
}

void thash_free(thash_cb_t *hcb)
{
    struct page_info *page;

    if (hcb->hash) {
        page = virt_to_page(hcb->hash);
        free_domheap_pages(page, hcb->pta.size + 1 - PAGE_SHIFT);
        hcb->hash = 0;
    }
}
