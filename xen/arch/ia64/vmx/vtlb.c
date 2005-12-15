
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
#define  MAX_CCH_LENGTH     40


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
    }
    return &(p->data);
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
static int __is_translated(thash_data_t *tlb, u64 rid, u64 va, CACHE_LINE_TYPE cl)
{
    u64  size1,sa1,ea1;
    if ( tlb->rid != rid ||(!tlb->tc && tlb->cl != cl) )
        return 0;
    size1 = PSIZE(tlb->ps);
    sa1 = tlb->vadr & ~(size1-1);   // mask the low address bits
    ea1 = sa1 + size1;

    if ( va >= sa1 && (va < ea1 || ea1 == 0) )
        return 1;
    else
        return 0;
}

/*
 * Only for TLB format.
 */
static int
__is_tlb_overlap(thash_cb_t *hcb,thash_data_t *entry,int rid, char cl, u64 sva, u64 eva)
{
    uint64_t size1,size2,sa1,ea1,ea2;

    if ( entry->invalid || entry->rid != rid || (!entry->tc && entry->cl != cl ) ) {
        return 0;
    }
    size1=PSIZE(entry->ps);
    sa1 = entry->vadr & ~(size1-1); // mask the low address bits
    ea1 = sa1 + size1;
    if ( (sva >= ea1 && ea1 != 0) || (eva <= sa1 && eva != 0) ) 
        return 0;
    else
        return 1;

}

static void __rem_tr (thash_cb_t *hcb, thash_data_t *tr)
{
    if ( hcb->remove_notifier ) {
        (hcb->remove_notifier)(hcb,tr);
    }
    tr->invalid = 1;
}

static inline void __set_tr (thash_data_t *tr, thash_data_t *data, int idx)
{
    *tr = *data;
    tr->tr_idx = idx;
}


static void __init_tr(thash_cb_t *hcb)
{
    int i;
    thash_data_t *tr;

    for ( i=0, tr = &ITR(hcb,0); i<NITRS; i++ ) {
        tr[i].invalid = 1;
    }
    for ( i=0, tr = &DTR(hcb,0); i<NDTRS; i++ ) {
        tr[i].invalid = 1;
    }
}

/*
 * Replace TR entry.
 */
static void rep_tr(thash_cb_t *hcb,thash_data_t *insert, int idx)
{
    thash_data_t *tr;

    if ( insert->cl == ISIDE_TLB ) {
        tr = &ITR(hcb,idx);
    }
    else {
        tr = &DTR(hcb,idx);
    }
    if ( !INVALID_TLB(tr) ) {
        __rem_tr(hcb, tr);
    }
    __set_tr (tr, insert, idx);
}

/*
 * remove TR entry.
 */
static void rem_tr(thash_cb_t *hcb,CACHE_LINE_TYPE cl, int idx)
{
    thash_data_t *tr;

    if ( cl == ISIDE_TLB ) {
        tr = &ITR(hcb,idx);
    }
    else {
        tr = &DTR(hcb,idx);
    }
    if ( !INVALID_TLB(tr) ) {
        __rem_tr(hcb, tr);
    }
}

/*
 * Delete an thash entry in collision chain.
 *  prev: the previous entry.
 *  rem: the removed entry.
 */
static void __rem_chain(thash_cb_t *hcb/*, thash_data_t *prev*/, thash_data_t *rem)
{
    //prev->next = rem->next;
    if ( hcb->remove_notifier ) {
         (hcb->remove_notifier)(hcb,rem);
    }
    cch_free (hcb, rem);
}

/*
 * Delete an thash entry leading collision chain.
 */
static void __rem_hash_head(thash_cb_t *hcb, thash_data_t *hash)
{
    thash_data_t *next=hash->next;

    if ( hcb->remove_notifier ) {
        (hcb->remove_notifier)(hcb,hash);
    }
    if ( next != NULL ) {
        *hash = *next;
        cch_free (hcb, next);
    }
    else {
        INVALIDATE_HASH(hcb, hash);
    }
}

thash_data_t *__vtr_lookup(thash_cb_t *hcb,
            u64 rid, u64 va,
            CACHE_LINE_TYPE cl)
{
    thash_data_t    *tr;
    int   num,i;

    if ( cl == ISIDE_TLB ) {
        tr = &ITR(hcb,0);
        num = NITRS;
    }
    else {
        tr = &DTR(hcb,0);
        num = NDTRS;
    }
    for ( i=0; i<num; i++ ) {
        if ( !INVALID_ENTRY(hcb,&tr[i]) &&
            __is_translated(&tr[i], rid, va, cl) )
            return &tr[i];
    }
    return NULL;
}


/*
 * Find overlap VHPT entry within current collision chain
 * base on internal priv info.
 */
static inline thash_data_t* _vhpt_next_overlap_in_chain(thash_cb_t *hcb)
{
    thash_data_t    *cch;
    thash_internal_t *priv = &hcb->priv;


    for (cch=priv->cur_cch; cch; cch = cch->next) {
        if ( priv->tag == cch->etag  ) {
            return cch;
        }
    }
    return NULL;
}

/*
 * Find overlap TLB/VHPT entry within current collision chain
 * base on internal priv info.
 */
static thash_data_t *_vtlb_next_overlap_in_chain(thash_cb_t *hcb)
{
    thash_data_t    *cch;
    thash_internal_t *priv = &hcb->priv;

    /* Find overlap TLB entry */
    for (cch=priv->cur_cch; cch; cch = cch->next) {
        if ( ( cch->tc ? priv->s_sect.tc : priv->s_sect.tr )  &&
            __is_tlb_overlap(hcb, cch, priv->rid, priv->cl,
                priv->_curva, priv->_eva) ) {
            return cch;
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
int __tlb_to_vhpt(thash_cb_t *hcb,
            thash_data_t *tlb, u64 va,
            thash_data_t *vhpt)
{
    u64 pages,mfn;
    ia64_rr vrr;

    ASSERT ( hcb->ht == THASH_VHPT );
    vrr = (hcb->get_rr_fn)(hcb->vcpu,va);
    pages = PSIZE(vrr.ps) >> PAGE_SHIFT;
    mfn = (hcb->vs->get_mfn)(DOMID_SELF,tlb->ppn, pages);
    if ( mfn == INVALID_MFN ) return 0;

    // TODO with machine discontinuous address space issue.
    vhpt->etag = (hcb->vs->tag_func)( hcb->pta, tlb->vadr);
    //vhpt->ti = 0;
    vhpt->itir = tlb->itir & ~ITIR_RV_MASK;
    vhpt->page_flags = tlb->page_flags & ~PAGE_FLAGS_RV_MASK;
    vhpt->ppn = mfn;
    vhpt->next = 0;
    return 1;
}


/*
 * Insert an entry to hash table. 
 *    NOTES:
 *  1: TLB entry may be TR, TC or Foreign Map. For TR entry,
 *     itr[]/dtr[] need to be updated too.
 *  2: Inserting to collision chain may trigger recycling if 
 *     the buffer for collision chain is empty.
 *  3: The new entry is inserted at the next of hash table.
 *     (I.e. head of the collision chain)
 *  4: The buffer holding the entry is allocated internally
 *     from cch_buf or just in the hash table.
 *  5: Return the entry in hash table or collision chain.
 *  6: Input parameter, entry, should be in TLB format.
 *      I.e. Has va, rid, ps...
 *  7: This API is invoked by emulating ITC/ITR and tlb_miss.
 *
 */

void thash_tr_insert(thash_cb_t *hcb, thash_data_t *entry, u64 va, int idx)
{
    if ( hcb->ht != THASH_TLB || entry->tc ) {
        panic("wrong parameter\n");
    }
    entry->vadr = PAGEALIGN(entry->vadr,entry->ps);
    entry->ppn = PAGEALIGN(entry->ppn, entry->ps-12);
    rep_tr(hcb, entry, idx);
    return ;
}
thash_data_t *vtlb_alloc_chain(thash_cb_t *hcb,thash_data_t *entry)
{
    thash_data_t *cch;
    
    cch = cch_alloc(hcb);
    if(cch == NULL){
        thash_purge_all(hcb);
    }
    return cch;
}
 

thash_data_t *__alloc_chain(thash_cb_t *hcb,thash_data_t *entry)
{
    thash_data_t *cch;
    
    cch = cch_alloc(hcb);
    if(cch == NULL){
        // recycle
        if ( hcb->recycle_notifier ) {
                hcb->recycle_notifier(hcb,(u64)entry);
        }
        thash_purge_all(hcb);
//        cch = cch_alloc(hcb);
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
void vtlb_insert(thash_cb_t *hcb, thash_data_t *entry, u64 va)
{
    thash_data_t    *hash_table, *cch;
    int flag;
    ia64_rr vrr;
    u64 gppn;
    u64 ppns, ppne;

    hash_table = (hcb->hash_func)(hcb->pta, va);
    if( INVALID_ENTRY(hcb, hash_table) ) {
        *hash_table = *entry;
        hash_table->next = 0;
    }
    else {
        // TODO: Add collision chain length limitation.
        cch = vtlb_alloc_chain(hcb,entry);
        if(cch == NULL){
            *hash_table = *entry;
            hash_table->next = 0;
        }else{
            *cch = *hash_table;
            *hash_table = *entry;
            hash_table->next = cch;
        }
    }
    if(hcb->vcpu->domain->domain_id==0){
       thash_insert(hcb->ts->vhpt, entry, va);
        return;
    }

#if 1
    vrr=vmx_vcpu_rr(current, va);
    if (vrr.ps != entry->ps) {
        machine_tlb_insert(hcb->vcpu, entry);
	printk("not preferred ps with va: 0x%lx\n", va);
	return;
    }
#endif 

    flag = 1;
    gppn = (POFFSET(va,entry->ps)|PAGEALIGN((entry->ppn<<12),entry->ps))>>PAGE_SHIFT;
    ppns = PAGEALIGN((entry->ppn<<12),entry->ps);
    ppne = ppns + PSIZE(entry->ps);
    if(((ppns<=0xa0000)&&(ppne>0xa0000))||((ppne>0xc0000)&&(ppns<=0xc0000)))
        flag = 0;
    if((__gpfn_is_mem(hcb->vcpu->domain, gppn)&&flag))
       thash_insert(hcb->ts->vhpt, entry, va);
    return ;
}

static void vhpt_insert(thash_cb_t *hcb, thash_data_t *entry, u64 va)
{
    thash_data_t   vhpt_entry, *hash_table, *cch;
    ia64_rr vrr;
    if ( !__tlb_to_vhpt(hcb, entry, va, &vhpt_entry) ) {
        panic("Can't convert to machine VHPT entry\n");
    }
    hash_table = (hcb->hash_func)(hcb->pta, va);
    if( INVALID_ENTRY(hcb, hash_table) ) {
        *hash_table = vhpt_entry;
        hash_table->next = 0;
    }
    else {
        // TODO: Add collision chain length limitation.
        cch = __alloc_chain(hcb,entry);
        if(cch == NULL){
            *hash_table = vhpt_entry;
            hash_table->next = 0;
        }else{
            *cch = *hash_table;
            *hash_table = vhpt_entry;
            hash_table->next = cch;
            if(hash_table->tag==hash_table->next->tag)
                while(1);

        }

    }
    return /*hash_table*/;
}

void thash_insert(thash_cb_t *hcb, thash_data_t *entry, u64 va)
{
    thash_data_t    *hash_table;
    ia64_rr vrr;
    
    vrr = (hcb->get_rr_fn)(hcb->vcpu,entry->vadr);
    if ( entry->ps != vrr.ps && entry->tc ) {
        panic("Not support for multiple page size now\n");
    }
    entry->vadr = PAGEALIGN(entry->vadr,entry->ps);
    entry->ppn = PAGEALIGN(entry->ppn, entry->ps-12);
    (hcb->ins_hash)(hcb, entry, va);
    
}

static void rem_thash(thash_cb_t *hcb, thash_data_t *entry)
{
    thash_data_t    *hash_table, *p, *q;
    thash_internal_t *priv = &hcb->priv;
    int idx;

    hash_table = priv->hash_base;
    if ( hash_table == entry ) {
//        if ( PURGABLE_ENTRY(hcb, entry) ) {
            __rem_hash_head (hcb, entry);
//        }
        return ;
    }
    // remove from collision chain
    p = hash_table;
    for ( q=p->next; q; q = p->next ) {
        if ( q == entry ){
//            if ( PURGABLE_ENTRY(hcb,q ) ) {
                p->next = q->next;
                __rem_chain(hcb, entry);
//            }
            return ;
        }
        p = q;
    }
    panic("Entry not existed or bad sequence\n");
}

static void rem_vtlb(thash_cb_t *hcb, thash_data_t *entry)
{
    thash_data_t    *hash_table, *p, *q;
    thash_internal_t *priv = &hcb->priv;
    int idx;
    
    if ( !entry->tc ) {
        return rem_tr(hcb, entry->cl, entry->tr_idx);
    }
    rem_thash(hcb, entry);
}    

int   cch_depth=0;
/*
 * Purge the collision chain starting from cch.
 * NOTE:
 *     For those UN-Purgable entries(FM), this function will return
 * the head of left collision chain.
 */
static thash_data_t *thash_rem_cch(thash_cb_t *hcb, thash_data_t *cch)
{
    thash_data_t *next;

//    if ( ++cch_depth > MAX_CCH_LENGTH ) {
//        printf ("cch length > MAX_CCH_LENGTH, exceed the expected length\n");
//        while(1);
//   }
    if ( cch -> next ) {
        next = thash_rem_cch(hcb, cch->next);
    }
    else {
        next = NULL;
    }
    if ( PURGABLE_ENTRY(hcb, cch) ) {
        __rem_chain(hcb, cch);
        return next;
    }
    else {
        cch->next = next;
        return cch;
    }
}

/*
 * Purge one hash line (include the entry in hash table).
 * Can only be called by thash_purge_all.
 * Input:
 *  hash: The head of collision chain (hash table)
 *
 */
static void thash_rem_line(thash_cb_t *hcb, thash_data_t *hash)
{
    if ( INVALID_ENTRY(hcb, hash) ) return;
    
    if ( hash->next ) {
        cch_depth = 0;
        hash->next = thash_rem_cch(hcb, hash->next);
    }
    // Then hash table itself.
    if ( PURGABLE_ENTRY(hcb, hash) ) {
        __rem_hash_head(hcb, hash);
    }
}


/*
 * Find an overlap entry in hash table and its collision chain.
 * Refer to SDM2 4.1.1.4 for overlap definition.
 *    PARAS:
 *  1: in: TLB format entry, rid:ps must be same with vrr[].
 *         va & ps identify the address space for overlap lookup
 *  2: section can be combination of TR, TC and FM. (THASH_SECTION_XX)
 *  3: cl means I side or D side.
 *    RETURNS:
 *  NULL to indicate the end of findings.
 *    NOTES:
 *
 */
thash_data_t *thash_find_overlap(thash_cb_t *hcb, 
            thash_data_t *in, search_section_t s_sect)
{
    return (hcb->find_overlap)(hcb, in->vadr, 
            PSIZE(in->ps), in->rid, in->cl, s_sect);
}

static thash_data_t *vtlb_find_overlap(thash_cb_t *hcb, 
        u64 va, u64 size, int rid, char cl, search_section_t s_sect)
{
    thash_data_t    *hash_table;
    thash_internal_t *priv = &hcb->priv;
    u64     tag;
    ia64_rr vrr;

    priv->_curva = va & ~(size-1);
    priv->_eva = priv->_curva + size;
    priv->rid = rid;
    vrr = (hcb->get_rr_fn)(hcb->vcpu,va);
    priv->ps = vrr.ps;
    hash_table = (hcb->hash_func)(hcb->pta, priv->_curva);
    priv->s_sect = s_sect;
    priv->cl = cl;
    priv->_tr_idx = 0;
    priv->hash_base = hash_table;
    priv->cur_cch = hash_table;
    return (hcb->next_overlap)(hcb);
}

static thash_data_t *vhpt_find_overlap(thash_cb_t *hcb, 
        u64 va, u64 size, int rid, char cl, search_section_t s_sect)
{
    thash_data_t    *hash_table;
    thash_internal_t *priv = &hcb->priv;
    u64     tag;
    ia64_rr vrr;

    priv->_curva = va & ~(size-1);
    priv->_eva = priv->_curva + size;
    priv->rid = rid;
    vrr = (hcb->get_rr_fn)(hcb->vcpu,va);
    priv->ps = vrr.ps;
    hash_table = (hcb->hash_func)( hcb->pta, priv->_curva);
    tag = (hcb->vs->tag_func)( hcb->pta, priv->_curva);
    priv->tag = tag;
    priv->hash_base = hash_table;
    priv->cur_cch = hash_table;
    return (hcb->next_overlap)(hcb);
}


static thash_data_t *vtr_find_next_overlap(thash_cb_t *hcb)
{
    thash_data_t    *tr;
    thash_internal_t *priv = &hcb->priv;
    int   num;

    if ( priv->cl == ISIDE_TLB ) {
        num = NITRS;
        tr = &ITR(hcb,0);
    }
    else {
        num = NDTRS;
        tr = &DTR(hcb,0);
    }
    for (; priv->_tr_idx < num; priv->_tr_idx ++ ) {
        if ( __is_tlb_overlap(hcb, &tr[priv->_tr_idx],
                priv->rid, priv->cl,
                priv->_curva, priv->_eva) ) {
            return &tr[priv->_tr_idx++];
        }
    }
    return NULL;
}

/*
 * Similar with vtlb_next_overlap but find next entry.
 *    NOTES:
 *  Intermediate position information is stored in hcb->priv.
 */
static thash_data_t *vtlb_next_overlap(thash_cb_t *hcb)
{
    thash_data_t    *ovl;
    thash_internal_t *priv = &hcb->priv;
    u64 addr,rr_psize;
    ia64_rr vrr;

    if ( priv->s_sect.tr ) {
        ovl = vtr_find_next_overlap (hcb);
        if ( ovl ) return ovl;
        priv->s_sect.tr = 0;
    }
    if ( priv->s_sect.v == 0 ) return NULL;
    vrr = (hcb->get_rr_fn)(hcb->vcpu,priv->_curva);
    rr_psize = PSIZE(vrr.ps);

    while ( priv->_curva < priv->_eva ) {
        if ( !INVALID_ENTRY(hcb, priv->hash_base) ) {
            ovl = _vtlb_next_overlap_in_chain(hcb);
            if ( ovl ) {
                priv->cur_cch = ovl->next;
                return ovl;
            }
        }
        priv->_curva += rr_psize;
        priv->hash_base = (hcb->hash_func)( hcb->pta, priv->_curva);
        priv->cur_cch = priv->hash_base;
    }
    return NULL;
}

static thash_data_t *vhpt_next_overlap(thash_cb_t *hcb)
{
    thash_data_t    *ovl;
    thash_internal_t *priv = &hcb->priv;
    u64 addr,rr_psize;
    ia64_rr vrr;

    vrr = (hcb->get_rr_fn)(hcb->vcpu,priv->_curva);
    rr_psize = PSIZE(vrr.ps);

    while ( priv->_curva < priv->_eva ) {
        if ( !INVALID_ENTRY(hcb, priv->hash_base) ) {
            ovl = _vhpt_next_overlap_in_chain(hcb);
            if ( ovl ) {
                priv->cur_cch = ovl->next;
                return ovl;
            }
        }
        priv->_curva += rr_psize;
        priv->hash_base = (hcb->hash_func)( hcb->pta, priv->_curva);
        priv->tag = (hcb->vs->tag_func)( hcb->pta, priv->_curva);
        priv->cur_cch = priv->hash_base;
    }
    return NULL;
}


/*
 * Find and purge overlap entries in hash table and its collision chain.
 *    PARAS:
 *  1: in: TLB format entry, rid:ps must be same with vrr[].
 *         rid, va & ps identify the address space for purge
 *  2: section can be combination of TR, TC and FM. (thash_SECTION_XX)
 *  3: cl means I side or D side.
 *    NOTES:
 *
 */
void thash_purge_entries(thash_cb_t *hcb, 
            thash_data_t *in, search_section_t p_sect)
{
    return thash_purge_entries_ex(hcb, in->rid, in->vadr,
            in->ps, p_sect, in->cl);
}

void thash_purge_entries_ex(thash_cb_t *hcb,
            u64 rid, u64 va, u64 ps, 
            search_section_t p_sect, 
            CACHE_LINE_TYPE cl)
{
    thash_data_t    *ovl;

    ovl = (hcb->find_overlap)(hcb, va, PSIZE(ps), rid, cl, p_sect);
    while ( ovl != NULL ) {
        (hcb->rem_hash)(hcb, ovl);
        ovl = (hcb->next_overlap)(hcb);
    };
}

/*
 * Purge overlap TCs and then insert the new entry to emulate itc ops.
 *    Notes: Only TC entry can purge and insert.
 */
void thash_purge_and_insert(thash_cb_t *hcb, thash_data_t *in)
{
    thash_data_t    *ovl;
    search_section_t sections;

#ifdef   XEN_DEBUGGER
    vrr = (hcb->get_rr_fn)(hcb->vcpu,in->vadr);
	if ( in->ps != vrr.ps || hcb->ht != THASH_TLB || !in->tc ) {
		panic ("Oops, wrong call for purge_and_insert\n");
		return;
	}
#endif
    in->vadr = PAGEALIGN(in->vadr,in->ps);
    in->ppn = PAGEALIGN(in->ppn, in->ps-12);
    sections.tr = 0;
    sections.tc = 1;
    ovl = (hcb->find_overlap)(hcb, in->vadr, PSIZE(in->ps),
    				 in->rid, in->cl, sections);
    if(ovl)
        (hcb->rem_hash)(hcb, ovl);
#ifdef   XEN_DEBUGGER
    ovl = (hcb->next_overlap)(hcb);
    if ( ovl ) {
		panic ("Oops, 2+ overlaps for purge_and_insert\n");
		return;
    }
#endif
    (hcb->ins_hash)(hcb, in, in->vadr);
}
/*
 * Purge one hash line (include the entry in hash table).
 * Can only be called by thash_purge_all.
 * Input:
 *  hash: The head of collision chain (hash table)
 *
 */
static void thash_purge_line(thash_cb_t *hcb, thash_data_t *hash)
{
    if ( INVALID_ENTRY(hcb, hash) ) return;
    thash_data_t *prev, *next;
    next=hash->next;
    while ( next ) {
        prev=next;
        next=next->next;
        cch_free(hcb, prev);
    }
    // Then hash table itself.
    INVALIDATE_HASH(hcb, hash);
}
/*
 * Purge all TCs or VHPT entries including those in Hash table.
 *
 */

// TODO: add sections.
void thash_purge_all(thash_cb_t *hcb)
{
    thash_data_t    *hash_table;
    
#ifdef  VTLB_DEBUG
	extern u64  sanity_check;
    static u64 statistics_before_purge_all=0;
    if ( statistics_before_purge_all ) {
    	sanity_check = 1;
        check_vtlb_sanity(hcb);
    }
#endif

    hash_table = (thash_data_t*)((u64)hcb->hash + hcb->hash_sz);
    for (--hash_table;(u64)hash_table >= (u64)hcb->hash;hash_table--) {
        thash_purge_line(hcb, hash_table);
    }
    if(hcb->ht== THASH_TLB) {
        hcb = hcb->ts->vhpt;
        hash_table = (thash_data_t*)((u64)hcb->hash + hcb->hash_sz);
        for (--hash_table;(u64)hash_table >= (u64)hcb->hash;hash_table--) {
            thash_purge_line(hcb, hash_table);
        }
    }
    local_flush_tlb_all();
}


/*
 * Lookup the hash table and its collision chain to find an entry
 * covering this address rid:va or the entry.
 *
 * INPUT:
 *  in: TLB format for both VHPT & TLB.
 */
thash_data_t *vtlb_lookup(thash_cb_t *hcb, 
            thash_data_t *in)
{
    return vtlb_lookup_ex(hcb, in->rid, in->vadr, in->cl);
}

thash_data_t *vtlb_lookup_ex(thash_cb_t *hcb, 
            u64 rid, u64 va,
            CACHE_LINE_TYPE cl)
{
    thash_data_t    *hash_table, *cch;
    u64     tag;
    ia64_rr vrr;
   
    ASSERT ( hcb->ht == THASH_VTLB );
    
    cch = __vtr_lookup(hcb, rid, va, cl);;
    if ( cch ) return cch;

    vrr = (hcb->get_rr_fn)(hcb->vcpu,va);
    hash_table = (hcb->hash_func)( hcb->pta, va);

    if ( INVALID_ENTRY(hcb, hash_table ) )
        return NULL;

        
    for (cch=hash_table; cch; cch = cch->next) {
        if ( __is_translated(cch, rid, va, cl) )
            return cch;
    }
    return NULL;
}

/*
 * Lock/Unlock TC if found.
 *     NOTES: Only the page in prefered size can be handled.
 *   return:
 *          1: failure
 *          0: success
 */
int thash_lock_tc(thash_cb_t *hcb, u64 va, u64 size, int rid, char cl, int lock)
{
	thash_data_t	*ovl;
	search_section_t	sections;

    sections.tr = 1;
    sections.tc = 1;
	ovl = (hcb->find_overlap)(hcb, va, size, rid, cl, sections);
	if ( ovl ) {
		if ( !ovl->tc ) {
//			panic("Oops, TR for lock\n");
			return 0;
		}
		else if ( lock ) {
			if ( ovl->locked ) {
				DPRINTK("Oops, already locked entry\n");
			}
			ovl->locked = 1;
		}
		else if ( !lock ) {
			if ( !ovl->locked ) {
				DPRINTK("Oops, already unlocked entry\n");
			}
			ovl->locked = 0;
		}
		return 0;
	}
	return 1;
}

/*
 * Notifier when TLB is deleted from hash table and its collision chain.
 * NOTES:
 *  The typical situation is that TLB remove needs to inform
 * VHPT to remove too.
 * PARAS:
 *  1: hcb is TLB object.
 *  2: The format of entry is always in TLB.
 *
 */
void tlb_remove_notifier(thash_cb_t *hcb, thash_data_t *entry)
{
    thash_cb_t  *vhpt;
    search_section_t    s_sect;
    
    s_sect.v = 0;
    thash_purge_entries(hcb->ts->vhpt, entry, s_sect);
    machine_tlb_purge(entry->vadr, entry->ps);
}

/*
 * Initialize internal control data before service.
 */
void thash_init(thash_cb_t *hcb, u64 sz)
{
    thash_data_t    *hash_table;

    cch_mem_init (hcb);
    hcb->magic = THASH_CB_MAGIC;
    hcb->pta.val = hcb->hash;
    hcb->pta.vf = 1;
    hcb->pta.ve = 1;
    hcb->pta.size = sz;
    hcb->get_rr_fn = vmmu_get_rr;
    ASSERT ( hcb->hash_sz % sizeof(thash_data_t) == 0 );
    if ( hcb->ht == THASH_TLB ) {
        hcb->remove_notifier =  tlb_remove_notifier;
        hcb->find_overlap = vtlb_find_overlap;
        hcb->next_overlap = vtlb_next_overlap;
        hcb->rem_hash = rem_vtlb;
        hcb->ins_hash = vtlb_insert;
        __init_tr(hcb);
    }
    else {
        hcb->remove_notifier =  NULL;
        hcb->find_overlap = vhpt_find_overlap;
        hcb->next_overlap = vhpt_next_overlap;
        hcb->rem_hash = rem_thash;
        hcb->ins_hash = vhpt_insert;
    }
    hash_table = (thash_data_t*)((u64)hcb->hash + hcb->hash_sz);
    
    for (--hash_table;(u64)hash_table >= (u64)hcb->hash;hash_table--) {
        INVALIDATE_HASH(hcb,hash_table);
    }
}
#define VTLB_DEBUG
#ifdef  VTLB_DEBUG
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
//    struct pfn_info *page;
    u64  hash_num, i, psr;
    static u64 check_ok_num, check_fail_num,check_invalid;
//  void *vb1, *vb2;
    thash_data_t  *hash, *cch;
    thash_data_t    *ovl;
    search_section_t s_sect;
    thash_cb_t *vhpt = vtlb->ts->vhpt;
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
    printf("vtlb=%lp, hash=%lp size=0x%lx; vhpt=%lp, hash=%lp size=0x%lx\n", 
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
    printf("Done vtlb entry check, hash=%lp\n", hash);
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
                    printf ("!!!Hash=%lp cch=%lp not within vtlb\n", hash, cch);
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
            printf("VTLB at hash=%lp\n", hash);
            for (cch=hash; cch; cch=cch->next) {
                printf("Entry %lp va=%lx ps=%lx rid=%lx\n",
                    cch, cch->vadr, cch->ps, cch->rid);
            }
        }
        hash ++;
    }
    printf("Dump vDTR\n");
    for (i=0; i<NDTRS; i++) {
        tr = &DTR(vtlb,i);
        printf("Entry %lp va=%lx ps=%lx rid=%lx\n",
                    tr, tr->vadr, tr->ps, tr->rid);
    }
    printf("Dump vITR\n");
    for (i=0; i<NITRS; i++) {
        tr = &ITR(vtlb,i);
        printf("Entry %lp va=%lx ps=%lx rid=%lx\n",
                    tr, tr->vadr, tr->ps, tr->rid);
    }
    printf("End of vTLB dump\n");
}
#endif
