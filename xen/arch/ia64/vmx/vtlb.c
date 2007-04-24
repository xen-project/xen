
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

#include <linux/sched.h>
#include <asm/tlb.h>
#include <xen/mm.h>
#include <asm/vmx_mm_def.h>
#include <asm/gcc_intrin.h>
#include <linux/interrupt.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_phy_mode.h>
#include <asm/vmmu.h>
#include <asm/tlbflush.h>
#include <asm/regionreg.h>
#define  MAX_CCH_LENGTH     40

thash_data_t *__alloc_chain(thash_cb_t *);

static void cch_mem_init(thash_cb_t *hcb)
{
    int num;
    thash_data_t *p;

    hcb->cch_freelist = p = hcb->cch_buf;
    num = (hcb->cch_sz/sizeof(thash_data_t))-1;
    do{
        p->next =p+1;
        p++;
        num--;
    }while(num);
    p->next = NULL;
}

static thash_data_t *cch_alloc(thash_cb_t *hcb)
{
    thash_data_t *p;
    if ( (p = hcb->cch_freelist) != NULL ) {
        hcb->cch_freelist = p->next;
    }
    return p;
}

/*
 * Check to see if the address rid:va is translated by the TLB
 */

static inline int __is_tr_translated(thash_data_t *trp, u64 rid, u64 va)
{
    return ((trp->p) && (trp->rid == rid) && ((va-trp->vadr)<PSIZE(trp->ps)));
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
    ea1 = sa1 + PSIZE(trp->ps) -1;
    eva -= 1;
    if ( (sva>ea1) || (sa1>eva) )
        return 0;
    else
        return 1;

}

thash_data_t *__vtr_lookup(VCPU *vcpu, u64 va, int is_data)
{

    thash_data_t  *trp;
    int  i;
    u64 rid;
    vcpu_get_rr(vcpu, va, &rid);
    rid = rid&RR_RID_MASK;;
    if (is_data) {
        if (vcpu_quick_region_check(vcpu->arch.dtr_regions,va)) {
            for (trp =(thash_data_t *) vcpu->arch.dtrs,i=0; i<NDTRS; i++, trp++) {
                if (__is_tr_translated(trp, rid, va)) {
                    return trp;
                }
            }
        }
    }
    else {
        if (vcpu_quick_region_check(vcpu->arch.itr_regions,va)) {
            for (trp =(thash_data_t *) vcpu->arch.itrs,i=0; i<NITRS; i++, trp++) {
                if (__is_tr_translated(trp, rid, va)) {
                    return trp;
                }
            }
        }
    }
    return NULL;
}


static void thash_recycle_cch(thash_cb_t *hcb, thash_data_t *hash)
{
    thash_data_t *p, *q;
    int i=0;
    
    p=hash;
    for(i=0; i < MAX_CCN_DEPTH; i++){
        p=p->next;
    }
    q=hash->next;
    hash->len=0;
    hash->next=0;
    p->next=hcb->cch_freelist;
    hcb->cch_freelist=q;
}




static void vmx_vhpt_insert(thash_cb_t *hcb, u64 pte, u64 itir, u64 ifa)
{
    u64 tag ,len;
    ia64_rr rr;
    thash_data_t *head, *cch;
    pte = pte & ~PAGE_FLAGS_RV_MASK;
    rr.rrval = ia64_get_rr(ifa);
    head = (thash_data_t *)ia64_thash(ifa);
    tag = ia64_ttag(ifa);
    cch = head;
    while (cch) {    
        if (INVALID_VHPT(cch)) {
            len = cch->len;
            cch->page_flags = pte;
            cch->len = len;
            cch->itir = rr.ps << 2;
            cch->etag = tag;
            return;
        }
        cch = cch->next;
    }

    if(head->len>=MAX_CCN_DEPTH){
        thash_recycle_cch(hcb, head);
        cch = cch_alloc(hcb);
    }
    else{
        cch = __alloc_chain(hcb);
    }
    local_irq_disable();
    *cch = *head;
    head->page_flags=pte;
    head->itir = rr.ps << 2;
    head->etag=tag;
    head->next = cch;
    head->len = cch->len+1;
    cch->len = 0;
    local_irq_enable();
    return;
}

void thash_vhpt_insert(VCPU *v, u64 pte, u64 itir, u64 va, int type)
{
    u64 phy_pte, psr;
    ia64_rr mrr;

    mrr.rrval = ia64_get_rr(va);
    phy_pte=translate_phy_pte(v, &pte, itir, va);

    if (itir_ps(itir) >= mrr.ps) {
        vmx_vhpt_insert(vcpu_get_vhpt(v), phy_pte, itir, va);
    } else {
        phy_pte  &= ~PAGE_FLAGS_RV_MASK;
        psr = ia64_clear_ic();
        ia64_itc(type + 1, va, phy_pte, itir_ps(itir));
        ia64_set_psr(psr);
        ia64_srlz_i();
    }
}

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
    hash=head;
    tag = ia64_ttag(va);
    do{
        if(hash->etag == tag)
            break;
        hash=hash->next;
    }while(hash);
    if(hash && hash!=head){
        pte = hash->page_flags;
        hash->page_flags = head->page_flags;
        head->page_flags = pte;
        tag = hash->etag;
        hash->etag = head->etag;
        head->etag = tag;
        itir = hash->itir;
        hash->itir = head->itir;
        head->itir = itir;
        head->len = hash->len;
        hash->len=0;
        return head;
    }
    return hash;
}

u64 guest_vhpt_lookup(u64 iha, u64 *pte)
{
    u64 ret;
    thash_data_t * data;

    data = vhpt_lookup(iha);
    if (data == NULL) {
        data = vtlb_lookup(current, iha, DSIDE_TLB);
        if (data != NULL)
            thash_vhpt_insert(current, data->page_flags, data->itir,
                              iha, DSIDE_TLB);
    }

    asm volatile ("rsm psr.ic|psr.i;;"
                  "srlz.d;;"
                  "ld8.s r9=[%1];;"
                  "tnat.nz p6,p7=r9;;"
                  "(p6) mov %0=1;"
                  "(p6) mov r9=r0;"
                  "(p7) extr.u r9=r9,0,53;;"
                  "(p7) mov %0=r0;"
                  "(p7) st8 [%2]=r9;;"
                  "ssm psr.ic;;"
                  "srlz.d;;"
                  "ssm psr.i;;"
                  : "=r"(ret) : "r"(iha), "r"(pte):"memory");
    return ret;
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
            cur = vsa_thash(hcb->pta, curadr, vrr.rrval, &tag);
            while (cur) {
                if (cur->etag == tag && cur->ps == rr_ps)
                    cur->etag = 1UL << 63;
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
            if (cur->etag == tag)
                cur->etag = 1UL << 63; 
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
    head=hcb->hash;
    num = (hcb->hash_sz/sizeof(thash_data_t));
    do{
        head->len = 0;
        head->next = 0;
        head++;
        num--;
    }while(num);
    cch_mem_init(hcb);
}


thash_data_t *__alloc_chain(thash_cb_t *hcb)
{
    thash_data_t *cch;

    cch = cch_alloc(hcb);
    if(cch == NULL){
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
void vtlb_insert(VCPU *v, u64 pte, u64 itir, u64 va)
{
    thash_data_t *hash_table, *cch;
    /* int flag; */
    ia64_rr vrr;
    /* u64 gppn, ppns, ppne; */
    u64 tag, len;
    thash_cb_t *hcb = &v->arch.vtlb;
    vcpu_get_rr(v, va, &vrr.rrval);
    vrr.ps = itir_ps(itir);
    VMX(v, psbits[va >> 61]) |= (1UL << vrr.ps);
    hash_table = vsa_thash(hcb->pta, va, vrr.rrval, &tag);
    cch = hash_table;
    while (cch) {
        if (INVALID_TLB(cch)) {
            len = cch->len;
            cch->page_flags = pte;
            cch->len = len;
            cch->itir=itir;
            cch->etag=tag;
            return;
        }
        cch = cch->next;
    }
    if (hash_table->len>=MAX_CCN_DEPTH){
        thash_recycle_cch(hcb, hash_table);
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
    hash_table->len += 1;
    return;
}


int vtr_find_overlap(VCPU *vcpu, u64 va, u64 ps, int is_data)
{
    thash_data_t  *trp;
    int  i;
    u64 end, rid;
    vcpu_get_rr(vcpu, va, &rid);
    rid = rid&RR_RID_MASK;;
    end = va + PSIZE(ps);
    if (is_data) {
        if (vcpu_quick_region_check(vcpu->arch.dtr_regions,va)) {
            for (trp =(thash_data_t *) vcpu->arch.dtrs,i=0; i<NDTRS; i++, trp++) {
                if (__is_tr_overlap(trp, rid, va, end )) {
                    return i;
                }
            }
        }
    }
    else {
        if (vcpu_quick_region_check(vcpu->arch.itr_regions,va)) {
            for (trp =(thash_data_t *) vcpu->arch.itrs,i=0; i<NITRS; i++, trp++) {
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
    if(vcpu_quick_region_check(v->arch.tc_regions,va))
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

u64 translate_phy_pte(VCPU *v, u64 *pte, u64 itir, u64 va)
{
    u64 ps, ps_mask, paddr, maddr;
//    ia64_rr rr;
    union pte_flags phy_pte;
    ps = itir_ps(itir);
    ps_mask = ~((1UL << ps) - 1);
    phy_pte.val = *pte;
    paddr = *pte;
    paddr = ((paddr & _PAGE_PPN_MASK) & ps_mask) | (va & ~ps_mask);
    maddr = lookup_domain_mpa(v->domain, paddr, NULL);
    if (maddr & GPFN_IO_MASK) {
        *pte |= VTLB_PTE_IO;
        return -1;
    }
//    rr.rrval = ia64_get_rr(va);
//    ps = rr.ps;
    maddr = ((maddr & _PAGE_PPN_MASK) & PAGE_MASK) | (paddr & ~PAGE_MASK);
    phy_pte.ppn = maddr >> ARCH_PAGE_SHIFT;
    return phy_pte.val;
}


/*
 * Purge overlap TCs and then insert the new entry to emulate itc ops.
 *    Notes: Only TC entry can purge and insert.
 */
void thash_purge_and_insert(VCPU *v, u64 pte, u64 itir, u64 ifa, int type)
{
    u64 ps;//, va;
    u64 phy_pte;
    ia64_rr vrr, mrr;
    ps = itir_ps(itir);
    vcpu_get_rr(current, ifa, &vrr.rrval);
    mrr.rrval = ia64_get_rr(ifa);
    if(VMX_DOMAIN(v)){
        /* Ensure WB attribute if pte is related to a normal mem page,
         * which is required by vga acceleration since qemu maps shared
         * vram buffer with WB.
         */
        if (!(pte & VTLB_PTE_IO) && ((pte & _PAGE_MA_MASK) != _PAGE_MA_NAT))
            pte &= ~_PAGE_MA_MASK;

        phy_pte = translate_phy_pte(v, &pte, itir, ifa);
        vtlb_purge(v, ifa, ps);
        vhpt_purge(v, ifa, ps);
        if (ps == mrr.ps) {
            if(!(pte&VTLB_PTE_IO)){
                vmx_vhpt_insert(&v->arch.vhpt, phy_pte, itir, ifa);
            }
            else{
                vtlb_insert(v, pte, itir, ifa);
                vcpu_quick_region_set(PSCBX(v,tc_regions),ifa);
            }
        }
        else if (ps > mrr.ps) {
            vtlb_insert(v, pte, itir, ifa);
            vcpu_quick_region_set(PSCBX(v,tc_regions),ifa);
            if(!(pte&VTLB_PTE_IO)){
                vmx_vhpt_insert(&v->arch.vhpt, phy_pte, itir, ifa);
            }
        }
        else {
            u64 psr;
            phy_pte  &= ~PAGE_FLAGS_RV_MASK;
            psr = ia64_clear_ic();
            ia64_itc(type + 1, ifa, phy_pte, ps);
            ia64_set_psr(psr);
            ia64_srlz_i();
            // ps < mrr.ps, this is not supported
            // panic_domain(NULL, "%s: ps (%lx) < mrr.ps \n", __func__, ps);
        }
    }
    else{
        phy_pte = translate_phy_pte(v, &pte, itir, ifa);
        if(ps!=PAGE_SHIFT){
            vtlb_insert(v, pte, itir, ifa);
            vcpu_quick_region_set(PSCBX(v,tc_regions),ifa);
        }
        machine_tlb_purge(ifa, ps);
        vmx_vhpt_insert(&v->arch.vhpt, phy_pte, itir, ifa);
    }
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
    vtlb =&v->arch.vtlb;
    vhpt =&v->arch.vhpt;

    for (num = 0; num < 8; num++)
        VMX(v, psbits[num]) = 0;
    
    head=vtlb->hash;
    num = (vtlb->hash_sz/sizeof(thash_data_t));
    do{
        head->page_flags = 0;
        head->etag = 1UL<<63;
        head->itir = 0;
        head->next = 0;
        head++;
        num--;
    }while(num);
    cch_mem_init(vtlb);
    
    head=vhpt->hash;
    num = (vhpt->hash_sz/sizeof(thash_data_t));
    do{
        head->page_flags = 0;
        head->etag = 1UL<<63;
        head->next = 0;
        head++;
        num--;
    }while(num);
    cch_mem_init(vhpt);
    local_flush_tlb_all();
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
    thash_data_t  *cch;
    u64     psbits, ps, tag;
    ia64_rr vrr;
    thash_cb_t * hcb= &v->arch.vtlb;

    cch = __vtr_lookup(v, va, is_data);;
    if ( cch ) return cch;

    if(vcpu_quick_region_check(v->arch.tc_regions,va)==0)
        return NULL;
    psbits = VMX(v, psbits[(va >> 61)]);
    vcpu_get_rr(v,va,&vrr.rrval);
    while (psbits) {
        ps = __ffs(psbits);
        psbits &= ~(1UL << ps);
        vrr.ps = ps;
        cch = vsa_thash(hcb->pta, va, vrr.rrval, &tag);
        do {
            if (cch->etag == tag && cch->ps == ps)
                return cch;
            cch = cch->next;
        } while(cch);
    }
    return NULL;
}


/*
 * Initialize internal control data before service.
 */
void thash_init(thash_cb_t *hcb, u64 sz)
{
    int num;
    thash_data_t *head, *p;

    hcb->pta.val = (unsigned long)hcb->hash;
    hcb->pta.vf = 1;
    hcb->pta.ve = 1;
    hcb->pta.size = sz;
    hcb->cch_rec_head = hcb->hash;
    
    head=hcb->hash;
    num = (hcb->hash_sz/sizeof(thash_data_t));
    do{
        head->page_flags = 0;
        head->itir = 0;
        head->etag = 1UL<<63;
        head->next = 0;
        head++;
        num--;
    }while(num);
    
    hcb->cch_freelist = p = hcb->cch_buf;
    num = hcb->cch_sz / sizeof(thash_data_t);
    do{
        p->page_flags = 0;
        p->itir = 0;
        p->next =p+1;
        p++;
        num--;
    }while(num);

    (p - 1)->next = NULL;
}
