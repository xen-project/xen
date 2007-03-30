
/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmmu.h: virtual memory management unit related APIs and data structure.
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
 */

#ifndef XEN_TLBthash_H
#define XEN_TLBthash_H

#define     MAX_CCN_DEPTH       (15)       // collision chain depth
#define     VCPU_VTLB_SHIFT     (20)    // 1M for VTLB
#define     VCPU_VTLB_SIZE      (1UL<<VCPU_VTLB_SHIFT)
#define     VCPU_VTLB_ORDER     (VCPU_VTLB_SHIFT - PAGE_SHIFT)
#define     VCPU_VHPT_SHIFT     (24)    // 16M for VTLB
#define     VCPU_VHPT_SIZE      (1UL<<VCPU_VHPT_SHIFT)
#define     VCPU_VHPT_ORDER     (VCPU_VHPT_SHIFT - PAGE_SHIFT)
#define     VTLB(v,_x)          (v->arch.vtlb._x)
#define     VHPT(v,_x)          (v->arch.vhpt._x)
#ifndef __ASSEMBLY__

#include <xen/config.h>
#include <xen/types.h>
#include <public/xen.h>
#include <asm/tlb.h>
#include <asm/regionreg.h>
#include <asm/vmx_mm_def.h>
#include <asm/bundle.h>
//#define         THASH_TLB_TR            0
//#define         THASH_TLB_TC            1


// bit definition of TR, TC search cmobination
//#define         THASH_SECTION_TR        (1<<0)
//#define         THASH_SECTION_TC        (1<<1)

/*
 * Next bit definition must be same with THASH_TLB_XX
#define         PTA_BASE_SHIFT          (15)
 */




#define HIGH_32BITS(x)  bits(x,32,63)
#define LOW_32BITS(x)   bits(x,0,31)

typedef union search_section {
    struct {
        u32 tr : 1;
        u32 tc : 1;
        u32 rsv: 30;
    };
    u32     v;
} search_section_t;


enum {
    ISIDE_TLB=0,
    DSIDE_TLB=1
};
#define VTLB_PTE_P_BIT      0
#define VTLB_PTE_IO_BIT     60
#define VTLB_PTE_IO         (1UL<<VTLB_PTE_IO_BIT)
#define VTLB_PTE_P         (1UL<<VTLB_PTE_P_BIT)
typedef struct thash_data {
    union {
        struct {
            u64 p    :  1; // 0
            u64 rv1  :  1; // 1
            u64 ma   :  3; // 2-4
            u64 a    :  1; // 5
            u64 d    :  1; // 6
            u64 pl   :  2; // 7-8
            u64 ar   :  3; // 9-11
            u64 ppn  : 38; // 12-49
            u64 rv2  :  2; // 50-51
            u64 ed   :  1; // 52
            u64 ig1  :  3; // 53-63
        };
        struct {
            u64 __rv1 : 53;     // 0-52
            u64 contiguous : 1; //53
            u64 tc : 1;         // 54 TR or TC
            u64 cl : 1;         // 55 I side or D side cache line
            u64 len  :  4;      // 56-59
            u64 io  : 1;	// 60 entry is for io or not
            u64 nomap : 1;      // 61 entry cann't be inserted into machine TLB.
            u64 checked : 1;    // 62 for VTLB/VHPT sanity check
            u64 invalid : 1;    // 63 invalid entry
        };
        u64 page_flags;
    };                  // same for VHPT and TLB

    union {
        struct {
            u64 rv3  :  2; // 0-1
            u64 ps   :  6; // 2-7
            u64 key  : 24; // 8-31
            u64 rv4  : 32; // 32-63
        };
        u64 itir;
    };
    union {
        struct {        // For TLB
            u64 ig2  :  12; // 0-11
            u64 vpn  :  49; // 12-60
            u64 vrn  :   3; // 61-63
        };
        u64 vadr;
        u64 ifa;
        struct {        // For VHPT
            u64 tag  :  63; // 0-62
            u64 ti   :  1;  // 63, invalid entry for VHPT
        };
        u64  etag;      // extended tag for VHPT
    };
    union {
        struct thash_data *next;
        u64  rid;  // only used in guest TR
//        u64  tr_idx;
    };
} thash_data_t;

#define INVALIDATE_VHPT_HEADER(hdata)   \
{   ((hdata)->page_flags)=0;            \
    ((hdata)->itir)=PAGE_SHIFT<<2;      \
    ((hdata)->etag)=1UL<<63;            \
    ((hdata)->next)=0;}

#define INVALIDATE_TLB_HEADER(hash)   INVALIDATE_VHPT_HEADER(hash)

#define INVALIDATE_HASH_HEADER(hcb,hash)    INVALIDATE_VHPT_HEADER(hash)

#define INVALID_VHPT(hdata)     ((hdata)->ti)
#define INVALID_TLB(hdata)      ((hdata)->ti)
#define INVALID_TR(hdata)      (!(hdata)->p)
#define INVALID_ENTRY(hcb, hdata)       INVALID_VHPT(hdata)


/*
 * Architecture ppn is in 4KB unit while XEN
 * page may be different(1<<PAGE_SHIFT).
 */
static inline u64 arch_to_xen_ppn(u64 appn)
{
    return (appn >>(PAGE_SHIFT-ARCH_PAGE_SHIFT));
}

static inline u64 xen_to_arch_ppn(u64 xppn)
{
    return (xppn <<(PAGE_SHIFT- ARCH_PAGE_SHIFT));
}

typedef enum {
    THASH_TLB=0,
    THASH_VHPT
} THASH_TYPE;

struct thash_cb;
/*
 * Use to calculate the HASH index of thash_data_t.
 */
typedef u64 *(THASH_FN)(PTA pta, u64 va);
typedef u64 *(TTAG_FN)(PTA pta, u64 va);
typedef u64 *(GET_MFN_FN)(domid_t d, u64 gpfn, u64 pages);
typedef void *(REM_NOTIFIER_FN)(struct thash_cb *hcb, thash_data_t *entry);
typedef void (RECYCLE_FN)(struct thash_cb *hc, u64 para);
typedef ia64_rr (GET_RR_FN)(struct vcpu *vcpu, u64 reg);
typedef thash_data_t *(FIND_OVERLAP_FN)(struct thash_cb *hcb, 
        u64 va, u64 ps, int rid, char cl, search_section_t s_sect);
typedef thash_data_t *(FIND_NEXT_OVL_FN)(struct thash_cb *hcb);
typedef void (REM_THASH_FN)(struct thash_cb *hcb, thash_data_t *entry);
typedef void (INS_THASH_FN)(struct thash_cb *hcb, thash_data_t *entry, u64 va);


typedef struct thash_cb {
    /* THASH base information */
    thash_data_t    *hash; // hash table pointer, aligned at thash_sz.
    u64     hash_sz;        // size of above data.
    void    *cch_buf;       // base address of collision chain.
    u64     cch_sz;         // size of above data.
    thash_data_t *cch_freelist;
    thash_data_t *cch_rec_head;  // cch recycle header
    PTA     pta;
} thash_cb_t;

/*
 * Initialize internal control data before service.
 */
extern void thash_init(thash_cb_t *hcb, u64 sz);

/*
 * Insert an entry to hash table. 
 *    NOTES:
 *      1: TLB entry may be TR, TC or Foreign Map. For TR entry,
 *         itr[]/dtr[] need to be updated too.
 *      2: Inserting to collision chain may trigger recycling if
 *         the buffer for collision chain is empty.
 *      3: The new entry is inserted at the hash table.
 *         (I.e. head of the collision chain)
 *      4: Return the entry in hash table or collision chain.
 *
 */
//extern void thash_insert(thash_cb_t *hcb, thash_data_t *entry, u64 va);
//extern void thash_tr_insert(thash_cb_t *hcb, thash_data_t *entry, u64 va, int idx);
extern int vtr_find_overlap(struct vcpu *vcpu, u64 va, u64 ps, int is_data);
extern u64 get_mfn(struct domain *d, u64 gpfn);
/*
 * Force to delete a found entry no matter TR or foreign map for TLB.
 *    NOTES:
 *      1: TLB entry may be TR, TC or Foreign Map. For TR entry,
 *         itr[]/dtr[] need to be updated too.
 *      2: This API must be called after thash_find_overlap() or
 *         thash_find_next_overlap().
 *      3: Return TRUE or FALSE
 *
 */
extern void thash_remove(thash_cb_t *hcb, thash_data_t *entry);
extern void thash_tr_remove(thash_cb_t *hcb, thash_data_t *entry/*, int idx*/);

/*
 * Find an overlap entry in hash table and its collision chain.
 * Refer to SDM2 4.1.1.4 for overlap definition.
 *    PARAS:
 *      1: in: TLB format entry, rid:ps must be same with vrr[].
 *             va & ps identify the address space for overlap lookup
 *      2: section can be combination of TR, TC and FM. (THASH_SECTION_XX)
 *      3: cl means I side or D side.
 *    RETURNS:
 *      NULL to indicate the end of findings.
 *    NOTES:
 *
 */
extern thash_data_t *thash_find_overlap(thash_cb_t *hcb, 
                        thash_data_t *in, search_section_t s_sect);
extern thash_data_t *thash_find_overlap_ex(thash_cb_t *hcb, 
                u64 va, u64 ps, int rid, char cl, search_section_t s_sect);


/*
 * Similar with thash_find_overlap but find next entry.
 *    NOTES:
 *      Intermediate position information is stored in hcb->priv.
 */
extern thash_data_t *thash_find_next_overlap(thash_cb_t *hcb);

/*
 * Find and purge overlap entries in hash table and its collision chain.
 *    PARAS:
 *      1: in: TLB format entry, rid:ps must be same with vrr[].
 *             rid, va & ps identify the address space for purge
 *      2: section can be combination of TR, TC and FM. (thash_SECTION_XX)
 *      3: cl means I side or D side.
 *    NOTES:
 *
 */
extern void thash_purge_entries(struct vcpu *v, u64 va, u64 ps);
extern void thash_purge_entries_remote(struct vcpu *v, u64 va, u64 ps);
extern void thash_purge_and_insert(struct vcpu *v, u64 pte, u64 itir, u64 ifa, int type);

/*
 * Purge all TCs or VHPT entries including those in Hash table.
 *
 */
extern void thash_purge_all(struct vcpu *v);

/*
 * Lookup the hash table and its collision chain to find an entry
 * covering this address rid:va.
 *
 */
extern thash_data_t *vtlb_lookup(struct vcpu *v,u64 va,int is_data);
extern int thash_lock_tc(thash_cb_t *hcb, u64 va, u64 size, int rid, char cl, int lock);


#define   ITIR_RV_MASK      (((1UL<<32)-1)<<32 | 0x3)
#define   PAGE_FLAGS_RV_MASK    (0x2 | (0x3UL<<50)|(((1UL<<11)-1)<<53))
#define   PAGE_FLAGS_AR_PL_MASK ((0x7UL<<9)|(0x3UL<<7))
extern u64 machine_ttag(PTA pta, u64 va);
extern u64 machine_thash(PTA pta, u64 va);
extern void purge_machine_tc_by_domid(domid_t domid);
extern void machine_tlb_insert(struct vcpu *v, thash_data_t *tlb);
extern ia64_rr vmmu_get_rr(struct vcpu *vcpu, u64 va);
extern int init_domain_tlb(struct vcpu *v);
extern void free_domain_tlb(struct vcpu *v);
extern thash_data_t * vsa_thash(PTA vpta, u64 va, u64 vrr, u64 *tag);
extern thash_data_t * vhpt_lookup(u64 va);
extern void machine_tlb_purge(u64 va, u64 ps);
extern unsigned long fetch_code(struct vcpu *vcpu, u64 gip, IA64_BUNDLE *pbundle);
extern void emulate_io_inst(struct vcpu *vcpu, u64 padr, u64 ma);
extern int vhpt_enabled(struct vcpu *vcpu, uint64_t vadr, vhpt_ref_t ref);
extern void vtlb_insert(struct vcpu *vcpu, u64 pte, u64 itir, u64 va);
extern u64 translate_phy_pte(struct vcpu *v, u64 *pte, u64 itir, u64 va);
extern void thash_vhpt_insert(struct vcpu *v, u64 pte, u64 itir, u64 ifa,
                              int type);
extern u64 guest_vhpt_lookup(u64 iha, u64 *pte);
extern int vhpt_access_rights_fixup(struct vcpu *v, u64 ifa, int is_data);

static inline void vmx_vcpu_set_tr (thash_data_t *trp, u64 pte, u64 itir, u64 va, u64 rid)
{
    trp->page_flags = pte;
    trp->itir = itir;
    trp->vadr = va;
    trp->rid = rid;
}

#endif  /* __ASSEMBLY__ */

#endif  /* XEN_TLBthash_H */
