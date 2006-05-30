
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
#include <asm/mm.h>
#include <asm/vmx_mm_def.h>
#include <asm/gcc_intrin.h>
#include <linux/interrupt.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmmu.h>
#include <asm/tlbflush.h>
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

static void cch_free(thash_cb_t *hcb, thash_data_t *cch)
{
    cch->next = hcb->cch_freelist;
    hcb->cch_freelist = cch;
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

/*
 * Delete an thash entry leading collision chain.
 */
static void __rem_hash_head(thash_cb_t *hcb, thash_data_t *hash)
{
    thash_data_t *next=hash->next;
    if ( next) {
        next->len=hash->len-1;
        *hash = *next;
        cch_free (hcb, next);
    }
    else {
        hash->ti=1;
    }
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
    thash_data_t *p;
    int i=0;
    
    p=hash;
    for(i=0; i < MAX_CCN_DEPTH; i++){
        p=p->next;
    }
    p->next=hcb->cch_freelist;
    hcb->cch_freelist=hash->next;
    hash->len=0;
    hash->next=0;
}




static void vmx_vhpt_insert(thash_cb_t *hcb, u64 pte, u64 itir, u64 ifa)
{
    u64 tag;
    thash_data_t *head, *cch;
    pte = pte & ~PAGE_FLAGS_RV_MASK;

    head = (thash_data_t *)ia64_thash(ifa);
    tag = ia64_ttag(ifa);
    if( INVALID_VHPT(head) ) {
        head->page_flags = pte;
        head->etag = tag;
        return;
    }

    if(head->len>=MAX_CCN_DEPTH){
        thash_recycle_cch(hcb, head);
        cch = cch_alloc(hcb);
    }
    else{
        cch = __alloc_chain(hcb);
    }
    cch->page_flags=head->page_flags;
    cch->etag=head->etag;
    cch->next=head->next;
    head->page_flags=pte;
    head->etag=tag;
    head->next = cch;
    head->len = cch->len+1;
    cch->len = 0;
    return;
}

void thash_vhpt_insert(VCPU *v, u64 pte, u64 itir, u64 va)
{
    u64 phy_pte;
    phy_pte=translate_phy_pte(v, &pte, itir, va);
    vmx_vhpt_insert(vcpu_get_vhpt(v), phy_pte, itir, va);
}
/*
 *   vhpt lookup
 */

thash_data_t * vhpt_lookup(u64 va)
{
    thash_data_t *hash, *head;
    u64 tag, pte;
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
        head->len = hash->len;
        hash->len=0;
        return head;
    }
    return hash;
}

u64 guest_vhpt_lookup(u64 iha, u64 *pte)
{
    u64 ret;
    vhpt_lookup(iha);
    asm volatile ("rsm psr.ic|psr.i;;"
                  "srlz.d;;"
                  "ld8.s r9=[%1];;"
                  "tnat.nz p6,p7=r9;;"
                  "(p6) mov %0=1;"
                  "(p6) mov r9=r0;"
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

static void vtlb_purge(thash_cb_t *hcb, u64 va, u64 ps)
{
    thash_data_t *hash_table, *prev, *next;
    u64 start, end, size, tag, rid, def_size;
    ia64_rr vrr;
    vcpu_get_rr(current, va, &vrr.rrval);
    rid = vrr.rid;
    size = PSIZE(ps);
    start = va & (-size);
    end = start + size;
    def_size = PSIZE(vrr.ps);
    while(start < end){
        hash_table = vsa_thash(hcb->pta, start, vrr.rrval, &tag);
        if(!INVALID_TLB(hash_table)){
            if(hash_table->etag == tag){
                __rem_hash_head(hcb, hash_table);
            }
            else{
                prev=hash_table;
                next=prev->next;
                while(next){
                    if(next->etag == tag){
                        prev->next=next->next;
                        cch_free(hcb,next);
                        hash_table->len--;
                        break;
                    }
                    prev=next;
                    next=next->next;
                }
            }
        }
        start += def_size;
    }
//    machine_tlb_purge(va, ps);
}
/*
 *  purge VHPT and machine TLB
 */
static void vhpt_purge(thash_cb_t *hcb, u64 va, u64 ps)
{
    thash_data_t *hash_table, *prev, *next;
    u64 start, end, size, tag;
    size = PSIZE(ps);
    start = va & (-size);
    end = start + size;
    while(start < end){
        hash_table = (thash_data_t *)ia64_thash(start);
        tag = ia64_ttag(start);
        if(hash_table->etag == tag ){
            __rem_hash_head(hcb, hash_table);
        }
        else{
            prev=hash_table;
            next=prev->next;
            while(next){
                if(next->etag == tag){
                    prev->next=next->next;
                    cch_free(hcb,next);
                    hash_table->len--;
                    break; 
                }
                prev=next;
                next=next->next;
            }
        }
        start += PAGE_SIZE;
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
void vtlb_insert(thash_cb_t *hcb, u64 pte, u64 itir, u64 va)
{
    thash_data_t    *hash_table, *cch;
    /* int flag; */
    ia64_rr vrr;
    /* u64 gppn, ppns, ppne; */
    u64 tag;
    vcpu_get_rr(current, va, &vrr.rrval);
#ifdef VTLB_DEBUG    
    if (vrr.ps != itir_ps(itir)) {
//        machine_tlb_insert(hcb->vcpu, entry);
        panic_domain(NULL, "not preferred ps with va: 0x%lx vrr.ps=%d ps=%ld\n",
             va, vrr.ps, itir_ps(itir));
        return;
    }
#endif
    hash_table = vsa_thash(hcb->pta, va, vrr.rrval, &tag);
    if( INVALID_TLB(hash_table) ) {
        hash_table->page_flags = pte;
        hash_table->itir=itir;
        hash_table->etag=tag;
        hash_table->next = 0;
        return;
    }
    if (hash_table->len>=MAX_CCN_DEPTH){
        thash_recycle_cch(hcb, hash_table);
        cch = cch_alloc(hcb);
    }
    else {
        cch = __alloc_chain(hcb);
    }
    *cch = *hash_table;
    hash_table->page_flags = pte;
    hash_table->itir=itir;
    hash_table->etag=tag;
    hash_table->next = cch;
    hash_table->len = cch->len + 1;
    cch->len = 0;
    return ;
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
        vtlb_purge(&v->arch.vtlb, va, ps);
    vhpt_purge(&v->arch.vhpt, va, ps);
}

u64 translate_phy_pte(VCPU *v, u64 *pte, u64 itir, u64 va)
{
    u64 ps, addr;
    union pte_flags phy_pte;
    ps = itir_ps(itir);
    phy_pte.val = *pte;
    addr = *pte;
    addr = ((addr & _PAGE_PPN_MASK)>>ps<<ps)|(va&((1UL<<ps)-1));
    addr = lookup_domain_mpa(v->domain, addr);
    if(addr & GPFN_IO_MASK){
        *pte |= VTLB_PTE_IO;
        return -1;
    }
    phy_pte.ppn = addr >> ARCH_PAGE_SHIFT;
    return phy_pte.val;
}


/*
 * Purge overlap TCs and then insert the new entry to emulate itc ops.
 *    Notes: Only TC entry can purge and insert.
 */
void thash_purge_and_insert(VCPU *v, u64 pte, u64 itir, u64 ifa)
{
    u64 ps;//, va;
    u64 phy_pte;
    ps = itir_ps(itir);

    if(VMX_DOMAIN(v)){
        phy_pte = translate_phy_pte(v, &pte, itir, ifa);
        if(ps==PAGE_SHIFT){
            if(!(pte&VTLB_PTE_IO)){
                vhpt_purge(&v->arch.vhpt, ifa, ps);
                vmx_vhpt_insert(&v->arch.vhpt, phy_pte, itir, ifa);
            }
            else{
                vhpt_purge(&v->arch.vhpt, ifa, ps);
                vtlb_insert(&v->arch.vtlb, pte, itir, ifa);
                vcpu_quick_region_set(PSCBX(v,tc_regions),ifa);
            }
        }
        else{
            vhpt_purge(&v->arch.vhpt, ifa, ps);
            vtlb_insert(&v->arch.vtlb, pte, itir, ifa);
            vcpu_quick_region_set(PSCBX(v,tc_regions),ifa);
            if(!(pte&VTLB_PTE_IO)){
                vmx_vhpt_insert(&v->arch.vhpt, phy_pte, itir, ifa);
            }
        }
    }
    else{
        phy_pte = translate_phy_pte(v, &pte, itir, ifa);
        if(ps!=PAGE_SHIFT){
            vtlb_insert(&v->arch.vtlb, pte, itir, ifa);
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

    head=vtlb->hash;
    num = (vtlb->hash_sz/sizeof(thash_data_t));
    do{
        head->page_flags = 0;
        head->etag = 1UL<<63;
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
    u64     tag;
    ia64_rr vrr;
    thash_cb_t * hcb= &v->arch.vtlb;
    ASSERT ( hcb->ht == THASH_TLB );

    cch = __vtr_lookup(v, va, is_data);;
    if ( cch ) return cch;

    if(vcpu_quick_region_check(v->arch.tc_regions,va)==0)
        return NULL;
    
    vcpu_get_rr(v,va,&vrr.rrval);
    cch = vsa_thash( hcb->pta, va, vrr.rrval, &tag);

    do{
        if(cch->etag == tag)
            return cch;
        cch = cch->next;
    }while(cch);
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
        head->itir = PAGE_SHIFT<<2;
        head->next = 0;
        head++;
        num--;
    }while(num);
    
    hcb->cch_freelist = p = hcb->cch_buf;
    num = (hcb->cch_sz/sizeof(thash_data_t))-1;
    do{
        p->itir = PAGE_SHIFT<<2;
        p->next =p+1;
        p++;
        num--;
    }while(num);
    p->itir = PAGE_SHIFT<<2;
    p->next = NULL;
}
