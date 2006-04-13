
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
    thash_cch_mem_t *p, *q;

    hcb->cch_freelist = p = hcb->cch_buf;

    for ( q=p+1; (u64)(q + 1) <= (u64)hcb->cch_buf + hcb->cch_sz;
        p++, q++ ) {
        p->next = q;
    }
    p->next = NULL;
}

static thash_data_t *cch_alloc(thash_cb_t *hcb)
{
    thash_cch_mem_t *p;

    if ( (p = hcb->cch_freelist) != NULL ) {
        hcb->cch_freelist = p->next;
        return (thash_data_t *)p;
    }else{
        return NULL;
    }
}

static void cch_free(thash_cb_t *hcb, thash_data_t *cch)
{
    thash_cch_mem_t *p = (thash_cch_mem_t*)cch;

    p->next = hcb->cch_freelist;
    hcb->cch_freelist = p;
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

/*    if ( hcb->remove_notifier ) {
        (hcb->remove_notifier)(hcb,hash);
    } */
    if ( next != NULL ) {
        next->len=hash->len-1;
        *hash = *next;
        cch_free (hcb, next);
    }
    else {
        INVALIDATE_HASH_HEADER(hcb, hash);
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


/*
 * Get the machine format of VHPT entry.
 *    PARAS:
 *  1: tlb: means the tlb format hash entry converting to VHPT.
 *  2: va means the guest virtual address that must be coverd by
 *     the translated machine VHPT.
 *  3: vhpt: means the machine format VHPT converting from tlb.
 *    NOTES:
 *  1: In case of the machine address is discontiguous,
 *     "tlb" needs to be covered by several machine VHPT. va
 *     is used to choice one of them.
 *  2: Foreign map is supported in this API.
 *    RETURN:
 *  0/1: means successful or fail.
 *
 */
int __tlb_to_vhpt(thash_cb_t *hcb, thash_data_t *vhpt, u64 va)
{
    u64 padr,pte;
    ASSERT ( hcb->ht == THASH_VHPT );
    padr = vhpt->ppn >>(vhpt->ps-ARCH_PAGE_SHIFT)<<vhpt->ps;
    padr += va&((1UL<<vhpt->ps)-1);
    pte=lookup_domain_mpa(current->domain,padr);
    if((pte>>56))
        return 0;
    vhpt->etag = ia64_ttag(va);
    vhpt->ps = PAGE_SHIFT;
    vhpt->ppn = (pte&((1UL<<IA64_MAX_PHYS_BITS)-(1UL<<PAGE_SHIFT)))>>ARCH_PAGE_SHIFT;
    vhpt->next = 0;
    return 1;
}

static void thash_remove_cch(thash_cb_t *hcb, thash_data_t *hash)
{
    thash_data_t *prev, *next;
    prev = hash; next= hash->next;
    while(next){
    	prev=next;
    	next=prev->next;
    	cch_free(hcb, prev);
    }
    hash->next = NULL;
    hash->len = 0;
}

/*  vhpt only has entries with PAGE_SIZE page size */

void thash_vhpt_insert(thash_cb_t *hcb, u64 pte, u64 itir, u64 ifa)
{
    thash_data_t   vhpt_entry, *hash_table, *cch;
    vhpt_entry.page_flags = pte & ~PAGE_FLAGS_RV_MASK;
    vhpt_entry.itir=itir;

//    ia64_rr vrr;

    if ( !__tlb_to_vhpt(hcb, &vhpt_entry, ifa) ) {
        return;
    //panic("Can't convert to machine VHPT entry\n");
    }

    hash_table = (thash_data_t *)ia64_thash(ifa);
    if( INVALID_VHPT(hash_table) ) {
        *hash_table = vhpt_entry;
        hash_table->next = 0;
	return;
    }

    cch = hash_table;
    while(cch){
        if(cch->etag == vhpt_entry.etag){
            if(cch->ppn == vhpt_entry.ppn)
                return;
            else
                while(1);
        }
        cch = cch->next;
    }

    if(hash_table->len>=MAX_CCN_DEPTH){
    	thash_remove_cch(hcb, hash_table);
    	cch = cch_alloc(hcb);
    	*cch = *hash_table;
        *hash_table = vhpt_entry;
    	hash_table->len = 1;
        hash_table->next = cch;
    	return;
    }

    // TODO: Add collision chain length limitation.
     cch = __alloc_chain(hcb);
     if(cch == NULL){
           *hash_table = vhpt_entry;
            hash_table->next = 0;
     }else{
            *cch = *hash_table;
            *hash_table = vhpt_entry;
            hash_table->next = cch;
    	    hash_table->len = cch->len + 1;
    	    cch->len = 0;

    }
    return /*hash_table*/;
}

/*
 *   vhpt lookup
 */

thash_data_t * vhpt_lookup(u64 va)
{
    thash_data_t *hash;
    u64 tag;
    hash = (thash_data_t *)ia64_thash(va);
    tag = ia64_ttag(va);
    while(hash){
    	if(hash->etag == tag)
	        return hash;
        hash=hash->next;
    }
    return NULL;
}


/*
 *  purge software guest tlb
 */

static void vtlb_purge(thash_cb_t *hcb, u64 va, u64 ps)
{
    thash_data_t *hash_table, *prev, *next;
    u64 start, end, size, tag, rid;
    ia64_rr vrr;
    vcpu_get_rr(current, va, &vrr.rrval);
    rid = vrr.rid;
    size = PSIZE(ps);
    start = va & (-size);
    end = start + size;
    while(start < end){
        hash_table = vsa_thash(hcb->pta, start, vrr.rrval, &tag);
//	    tag = ia64_ttag(start);
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
	    start += PAGE_SIZE;
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

void thash_recycle_cch(thash_cb_t *hcb)
{
    thash_data_t    *hash_table;

    hash_table = (thash_data_t*)((u64)hcb->hash + hcb->hash_sz);
    for (--hash_table;(u64)hash_table >= (u64)hcb->hash;hash_table--) {
        thash_remove_cch(hcb,hash_table);
    }
}

thash_data_t *__alloc_chain(thash_cb_t *hcb)
{
    thash_data_t *cch;

    cch = cch_alloc(hcb);
    if(cch == NULL){
        thash_recycle_cch(hcb);
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
    u64 tag, ps;
    ps = itir_ps(itir);
    vcpu_get_rr(current, va, &vrr.rrval);
    if (vrr.ps != ps) {
//        machine_tlb_insert(hcb->vcpu, entry);
    	panic_domain(NULL, "not preferred ps with va: 0x%lx vrr.ps=%d ps=%d\n",
		     va, vrr.ps, ps);
    	return;
    }
    hash_table = vsa_thash(hcb->pta, va, vrr.rrval, &tag);
    if( INVALID_TLB(hash_table) ) {
        hash_table->page_flags = pte;
        hash_table->itir=itir;
        hash_table->etag=tag;
        hash_table->next = 0;
    }
    else if (hash_table->len>=MAX_CCN_DEPTH){
        thash_remove_cch(hcb, hash_table);
        cch = cch_alloc(hcb);
        *cch = *hash_table;
        hash_table->page_flags = pte;
        hash_table->itir=itir;
        hash_table->etag=tag;
        hash_table->len = 1;
        hash_table->next = cch;
    }

    else {
        // TODO: Add collision chain length limitation.
        cch = __alloc_chain(hcb);
        if(cch == NULL){
            hash_table->page_flags = pte;
            hash_table->itir=itir;
            hash_table->etag=tag;
            hash_table->next = 0;
        }else{
            *cch = *hash_table;
            hash_table->page_flags = pte;
            hash_table->itir=itir;
            hash_table->etag=tag;
            hash_table->next = cch;
            hash_table->len = cch->len + 1;
            cch->len = 0;
        }
    }
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
void thash_purge_entries(thash_cb_t *hcb, u64 va, u64 ps)
{
    vtlb_purge(hcb, va, ps);
    vhpt_purge(hcb->vhpt, va, ps);
}


/*
 * Purge overlap TCs and then insert the new entry to emulate itc ops.
 *    Notes: Only TC entry can purge and insert.
 */
void thash_purge_and_insert(thash_cb_t *hcb, u64 pte, u64 itir, u64 ifa)
{
    u64 ps, va;
    ps = itir_ps(itir);
    va = PAGEALIGN(ifa,ps);
    vtlb_purge(hcb, va, ps);
    vhpt_purge(hcb->vhpt, va, ps);
    if((ps!=PAGE_SHIFT)||(pte&VTLB_PTE_IO))
        vtlb_insert(hcb, pte, itir, va);
    if(!(pte&VTLB_PTE_IO)){
        va = PAGEALIGN(ifa,PAGE_SHIFT);
        thash_vhpt_insert(hcb->vhpt, pte, itir, va);
    }
}



/*
 * Purge all TCs or VHPT entries including those in Hash table.
 *
 */

// TODO: add sections.
void thash_purge_all(thash_cb_t *hcb)
{
    thash_data_t    *hash_table;
    /* thash_data_t    *entry; */
    thash_cb_t  *vhpt;
    /* u64 i, start, end; */

#ifdef  VTLB_DEBUG
	extern u64  sanity_check;
    static u64 statistics_before_purge_all=0;
    if ( statistics_before_purge_all ) {
    	sanity_check = 1;
        check_vtlb_sanity(hcb);
    }
#endif
    ASSERT ( hcb->ht == THASH_TLB );

    hash_table = (thash_data_t*)((u64)hcb->hash + hcb->hash_sz);
    for (--hash_table;(u64)hash_table >= (u64)hcb->hash;hash_table--) {
        INVALIDATE_TLB_HEADER(hash_table);
    }
    cch_mem_init (hcb);

    vhpt = hcb->vhpt;
    hash_table = (thash_data_t*)((u64)vhpt->hash + vhpt->hash_sz);
    for (--hash_table;(u64)hash_table >= (u64)vhpt->hash;hash_table--) {
        INVALIDATE_VHPT_HEADER(hash_table);
    }
    cch_mem_init (vhpt);
    local_flush_tlb_all();
}


/*
 * Lookup the hash table and its collision chain to find an entry
 * covering this address rid:va or the entry.
 *
 * INPUT:
 *  in: TLB format for both VHPT & TLB.
 */

thash_data_t *vtlb_lookup(thash_cb_t *hcb, u64 va,int is_data)
{
    thash_data_t    *hash_table, *cch;
    u64     tag;
    ia64_rr vrr;

    ASSERT ( hcb->ht == THASH_TLB );

    cch = __vtr_lookup(hcb->vcpu, va, is_data);;
    if ( cch ) return cch;

    vcpu_get_rr(hcb->vcpu,va,&vrr.rrval);
    hash_table = vsa_thash( hcb->pta, va, vrr.rrval, &tag);

    if ( INVALID_ENTRY(hcb, hash_table ) )
        return NULL;


    for (cch=hash_table; cch; cch = cch->next) {
        if(cch->etag == tag)
            return cch;
    }
    return NULL;
}


/*
 * Initialize internal control data before service.
 */
void thash_init(thash_cb_t *hcb, u64 sz)
{
    thash_data_t    *hash_table;

    cch_mem_init (hcb);
    hcb->magic = THASH_CB_MAGIC;
    hcb->pta.val = (unsigned long)hcb->hash;
    hcb->pta.vf = 1;
    hcb->pta.ve = 1;
    hcb->pta.size = sz;
//    hcb->get_rr_fn = vmmu_get_rr;
    ASSERT ( hcb->hash_sz % sizeof(thash_data_t) == 0 );
    hash_table = (thash_data_t*)((u64)hcb->hash + hcb->hash_sz);

    for (--hash_table;(u64)hash_table >= (u64)hcb->hash;hash_table--) {
        INVALIDATE_HASH_HEADER(hcb,hash_table);
    }
}

#ifdef  VTLB_DEBUG
/*
static  u64 cch_length_statistics[MAX_CCH_LENGTH+1];
u64  sanity_check=0;
u64 vtlb_chain_sanity(thash_cb_t *vtlb, thash_cb_t *vhpt, thash_data_t *hash)
{
    thash_data_t *cch;
    thash_data_t    *ovl;
    search_section_t s_sect;
    u64     num=0;

    s_sect.v = 0;
    for (cch=hash; cch; cch=cch->next) {
        ovl = thash_find_overlap(vhpt, cch, s_sect);
        while ( ovl != NULL ) {
            ovl->checked = 1;
            ovl = (vhpt->next_overlap)(vhpt);
        };
        num ++;
    }
    if ( num >= MAX_CCH_LENGTH ) {
    	cch_length_statistics[MAX_CCH_LENGTH] ++;
    }
    else {
    	cch_length_statistics[num] ++;
    }
    return num;
}

void check_vtlb_sanity(thash_cb_t *vtlb)
{
//    struct page_info *page;
    u64  hash_num, i, psr;
    static u64 check_ok_num, check_fail_num,check_invalid;
//  void *vb1, *vb2;
    thash_data_t  *hash, *cch;
    thash_data_t    *ovl;
    search_section_t s_sect;
    thash_cb_t *vhpt = vtlb->vhpt;
    u64   invalid_ratio;
 
    if ( sanity_check == 0 ) return;
    sanity_check --;
    s_sect.v = 0;
//    page = alloc_domheap_pages (NULL, VCPU_TLB_ORDER, 0);
//    if ( page == NULL ) {
//        panic("No enough contiguous memory for init_domain_mm\n");
//    };
//    vb1 = page_to_virt(page);
//    printf("Allocated page=%lp vbase=%lp\n", page, vb1);
//    vb2 = vb1 + vtlb->hash_sz;
    hash_num = vhpt->hash_sz / sizeof(thash_data_t);
//    printf("vb2=%lp, size=%lx hash_num=%lx\n", vb2, vhpt->hash_sz, hash_num);
    printf("vtlb=%p, hash=%p size=0x%lx; vhpt=%p, hash=%p size=0x%lx\n", 
                vtlb, vtlb->hash,vtlb->hash_sz,
                vhpt, vhpt->hash, vhpt->hash_sz);
    //memcpy(vb1, vtlb->hash, vtlb->hash_sz);
    //memcpy(vb2, vhpt->hash, vhpt->hash_sz);
    for ( i=0; i < sizeof(cch_length_statistics)/sizeof(cch_length_statistics[0]); i++ ) {
    	cch_length_statistics[i] = 0;
    }

    local_irq_save(psr);

    hash = vhpt->hash;
    for (i=0; i < hash_num; i++) {
        if ( !INVALID_ENTRY(vhpt, hash) ) {
            for ( cch= hash; cch; cch=cch->next) {
                cch->checked = 0;
            }
        }
        hash ++;
    }
    printf("Done vhpt clear checked flag, hash_num=0x%lx\n", hash_num);
    check_invalid = 0;
    check_ok_num=0;
    hash = vtlb->hash;
    for ( i=0; i< hash_num; i++ ) {
        if ( !INVALID_ENTRY(vtlb, hash) ) {
            check_ok_num += vtlb_chain_sanity(vtlb, vhpt, hash);
        }
        else {
            check_invalid++;
        }
        hash ++;
    }
    printf("Done vtlb entry check, hash=%p\n", hash);
    printf("check_ok_num = 0x%lx check_invalid=0x%lx\n", check_ok_num,check_invalid);
    invalid_ratio = 1000*check_invalid / hash_num;
    printf("%02ld.%01ld%% entries are invalid\n", 
		invalid_ratio/10, invalid_ratio % 10 );
    for (i=0; i<NDTRS; i++) {
        ovl = thash_find_overlap(vhpt, &vtlb->ts->dtr[i], s_sect);
        while ( ovl != NULL ) {
            ovl->checked = 1;
            ovl = (vhpt->next_overlap)(vhpt);
        };
    }
    printf("Done dTR\n");
    for (i=0; i<NITRS; i++) {
        ovl = thash_find_overlap(vhpt, &vtlb->ts->itr[i], s_sect);
        while ( ovl != NULL ) {
            ovl->checked = 1;
            ovl = (vhpt->next_overlap)(vhpt);
        };
    }
    printf("Done iTR\n");
    check_fail_num = 0;
    check_invalid = 0;
    check_ok_num=0;
    hash = vhpt->hash;
    for (i=0; i < hash_num; i++) {
        if ( !INVALID_ENTRY(vhpt, hash) ) {
            for ( cch= hash; cch; cch=cch->next) {
                if ( !cch->checked ) {
                    printf ("!!!Hash=%p cch=%p not within vtlb\n", hash, cch);
                    check_fail_num ++;
                }
                else {
                    check_ok_num++;
                }
            }
        }
        else {
            check_invalid ++;
        }
        hash ++;
    }
    local_irq_restore(psr);
    printf("check_ok_num=0x%lx check_fail_num=0x%lx check_invalid=0x%lx\n", 
            check_ok_num, check_fail_num, check_invalid);
    //memcpy(vtlb->hash, vb1, vtlb->hash_sz);
    //memcpy(vhpt->hash, vb2, vhpt->hash_sz);
    printf("The statistics of collision chain length is listed\n");
    for ( i=0; i < sizeof(cch_length_statistics)/sizeof(cch_length_statistics[0]); i++ ) {
    	printf("CCH length=%02ld, chain number=%ld\n", i, cch_length_statistics[i]);
    }
//    free_domheap_pages(page, VCPU_TLB_ORDER);
    printf("Done check_vtlb\n");
}

void dump_vtlb(thash_cb_t *vtlb)
{
    static u64  dump_vtlb=0;
    thash_data_t  *hash, *cch, *tr;
    u64     hash_num,i;

    if ( dump_vtlb == 0 ) return;
    dump_vtlb --;
    hash_num = vtlb->hash_sz / sizeof(thash_data_t);
    hash = vtlb->hash;

    printf("Dump vTC\n");
    for ( i = 0; i < hash_num; i++ ) {
        if ( !INVALID_ENTRY(vtlb, hash) ) {
            printf("VTLB at hash=%p\n", hash);
            for (cch=hash; cch; cch=cch->next) {
                printf("Entry %p va=%lx ps=%d rid=%d\n",
                    cch, cch->vadr, cch->ps, cch->rid);
            }
        }
        hash ++;
    }
    printf("Dump vDTR\n");
    for (i=0; i<NDTRS; i++) {
        tr = &DTR(vtlb,i);
        printf("Entry %p va=%lx ps=%d rid=%d\n",
                    tr, tr->vadr, tr->ps, tr->rid);
    }
    printf("Dump vITR\n");
    for (i=0; i<NITRS; i++) {
        tr = &ITR(vtlb,i);
        printf("Entry %p va=%lx ps=%d rid=%d\n",
                    tr, tr->vadr, tr->ps, tr->rid);
    }
    printf("End of vTLB dump\n");
}
*/
#endif
