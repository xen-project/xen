/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmmu.c: virtual memory management unit components.
 * Copyright (c) 2005, Intel Corporation.
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
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 *  Yaozu Dong (Eddie Dong) (Eddie.dong@intel.com)
 */
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/tlb.h>
#include <asm/gcc_intrin.h>
#include <asm/vcpu.h>
#include <linux/interrupt.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_mm_def.h>
#include <asm/vmx.h>
#include <asm/hw_irq.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/kregs.h>
#include <xen/irq.h>

/*
 * Architecture ppn is in 4KB unit while XEN
 * page may be different(1<<PAGE_SHIFT).
 */
static inline u64 arch_ppn_to_xen_ppn(u64 appn)
{
    return (appn << ARCH_PAGE_SHIFT) >> PAGE_SHIFT;
}

static inline u64 xen_ppn_to_arch_ppn(u64 xppn)
{
    return (xppn << PAGE_SHIFT) >> ARCH_PAGE_SHIFT;
}


/*
 * Get the machine page frame number in 16KB unit
 * Input:
 *  d: 
 */
u64 get_mfn(domid_t domid, u64 gpfn, u64 pages)
{
    struct domain *d;
    u64    xen_gppn, xen_mppn, mpfn;
    
    if ( domid == DOMID_SELF ) {
        d = current->domain;
    }
    else {
        d = find_domain_by_id(domid);
    }
    xen_gppn = arch_ppn_to_xen_ppn(gpfn);
    xen_mppn = gmfn_to_mfn(d, xen_gppn);
/*
    for (i=0; i<pages; i++) {
        if ( gmfn_to_mfn(d, gpfn+i) == INVALID_MFN ) {
            return INVALID_MFN;
        }
    }
*/
    mpfn= xen_ppn_to_arch_ppn(xen_mppn);
    mpfn = mpfn | (((1UL <<(PAGE_SHIFT-12))-1)&gpfn);
    return mpfn;
    
}

/*
 * The VRN bits of va stand for which rr to get.
 */
ia64_rr vmmu_get_rr(VCPU *vcpu, u64 va)
{
    ia64_rr   vrr;
    vmx_vcpu_get_rr(vcpu, va, &vrr.rrval);
    return vrr;
}


void recycle_message(thash_cb_t *hcb, u64 para)
{
    if(hcb->ht == THASH_VHPT)
    {
        printk("ERROR : vhpt recycle happenning!!!\n");
    }
    printk("hcb=%p recycled with %lx\n",hcb,para);
}


/*
 * Purge all guest TCs in logical processor.
 * Instead of purging all LP TCs, we should only purge   
 * TCs that belong to this guest.
 */
void
purge_machine_tc_by_domid(domid_t domid)
{
#ifndef PURGE_GUEST_TC_ONLY
    // purge all TCs
    struct ia64_pal_retval  result;
    u64 addr;
    u32 count1,count2;
    u32 stride1,stride2;
    u32 i,j;
    u64 psr;
    

    result = ia64_pal_call_static(PAL_PTCE_INFO,0,0,0, 0);
    if ( result.status != 0 ) {
        panic ("PAL_PTCE_INFO failed\n");
    }
    addr = result.v0;
    count1 = HIGH_32BITS(result.v1);
    count2 = LOW_32BITS (result.v1);
    stride1 = HIGH_32BITS(result.v2);
    stride2 = LOW_32BITS (result.v2);
    
    local_irq_save(psr);
    for (i=0; i<count1; i++) {
        for (j=0; j<count2; j++) {
            ia64_ptce(addr);
            addr += stride2;
        }
        addr += stride1;
    }
    local_irq_restore(psr);
#else
    // purge all TCs belong to this guest.
#endif
}

static thash_cb_t *init_domain_vhpt(struct vcpu *d)
{
    struct page_info *page;
    void   *vbase,*vcur;
    vhpt_special *vs;
    thash_cb_t  *vhpt;
    PTA pta_value;
    
    page = alloc_domheap_pages (NULL, VCPU_TLB_ORDER, 0);
    if ( page == NULL ) {
        panic("No enough contiguous memory for init_domain_mm\n");
    }
    vbase = page_to_virt(page);
    printk("Allocate domain vhpt at 0x%lx\n", (u64)vbase);
    memset(vbase, 0, VCPU_TLB_SIZE);
    vcur = (void*)((u64)vbase + VCPU_TLB_SIZE);
    vcur -= sizeof (thash_cb_t);
    vhpt = vcur;
    vhpt->ht = THASH_VHPT;
    vhpt->vcpu = d;
    vhpt->hash_func = machine_thash;
    vcur -= sizeof (vhpt_special);
    vs = vcur;

    /* Setup guest pta */
    pta_value.val = 0;
    pta_value.ve = 1;
    pta_value.vf = 1;
    pta_value.size = VCPU_TLB_SHIFT - 1;    /* 2M */
    pta_value.base = ((u64)vbase) >> PTA_BASE_SHIFT;
    d->arch.arch_vmx.mpta = pta_value.val;
   
    vhpt->vs = vs;
    vhpt->vs->get_mfn = get_mfn;
    vhpt->vs->tag_func = machine_ttag;
    vhpt->hash = vbase;
    vhpt->hash_sz = VCPU_TLB_SIZE/2;
    vhpt->cch_buf = (void *)(vbase + vhpt->hash_sz);
    vhpt->cch_sz = (u64)vcur - (u64)vhpt->cch_buf;
    vhpt->recycle_notifier = recycle_message;
    thash_init(vhpt,VCPU_TLB_SHIFT-1);
    return vhpt;
}


thash_cb_t *init_domain_tlb(struct vcpu *d)
{
    struct page_info *page;
    void    *vbase,*vcur;
    tlb_special_t  *ts;
    thash_cb_t  *tlb;
    
    page = alloc_domheap_pages (NULL, VCPU_TLB_ORDER, 0);
    if ( page == NULL ) {
        panic("No enough contiguous memory for init_domain_mm\n");
    }
    vbase = page_to_virt(page);
    printk("Allocate domain tlb at 0x%lx\n", (u64)vbase);
    memset(vbase, 0, VCPU_TLB_SIZE);
    vcur = (void*)((u64)vbase + VCPU_TLB_SIZE);
    vcur -= sizeof (thash_cb_t);
    tlb = vcur;
    tlb->ht = THASH_TLB;
    tlb->vcpu = d;
    vcur -= sizeof (tlb_special_t);
    ts = vcur;
    tlb->ts = ts;
    tlb->ts->vhpt = init_domain_vhpt(d);
    tlb->hash_func = machine_thash;
    tlb->hash = vbase;
    tlb->hash_sz = VCPU_TLB_SIZE/2;
    tlb->cch_buf = (void *)((u64)vbase + tlb->hash_sz);
    tlb->cch_sz = (u64)vcur - (u64)tlb->cch_buf;
    tlb->recycle_notifier = recycle_message;
    thash_init(tlb,VCPU_TLB_SHIFT-1);
    return tlb;
}

/* Allocate physical to machine mapping table for domN
 * FIXME: Later this interface may be removed, if that table is provided
 * by control panel. Dom0 has gpfn identical to mfn, which doesn't need
 * this interface at all.
 */
#if 0
void
alloc_pmt(struct domain *d)
{
    struct page_info *page;

    /* Only called once */
    ASSERT(d->arch.pmt);

    page = alloc_domheap_pages(NULL, get_order(d->max_pages), 0);
    ASSERT(page);

    d->arch.pmt = page_to_virt(page);
    memset(d->arch.pmt, 0x55, d->max_pages * 8);
}
#endif
/*
 * Insert guest TLB to machine TLB.
 *  data:   In TLB format
 */
void machine_tlb_insert(struct vcpu *d, thash_data_t *tlb)
{
    u64     psr;
    thash_data_t    mtlb;
    unsigned int    cl = tlb->cl;
    unsigned long mtlb_ppn; 
    mtlb.ifa = tlb->vadr;
    mtlb.itir = tlb->itir & ~ITIR_RV_MASK;
    //vmx_vcpu_get_rr(d, mtlb.ifa, &vrr.value);
    mtlb.page_flags = tlb->page_flags & ~PAGE_FLAGS_RV_MASK;
    mtlb.ppn = (unsigned long)get_mfn(DOMID_SELF,tlb->ppn, 1);
    mtlb_ppn=mtlb.ppn;
    if (mtlb_ppn == INVALID_MFN)
    panic("Machine tlb insert with invalid mfn number.\n");

    psr = ia64_clear_ic();
    if ( cl == ISIDE_TLB ) {
        ia64_itc(1, mtlb.ifa, mtlb.page_flags, mtlb.ps);
    }
    else {
        ia64_itc(2, mtlb.ifa, mtlb.page_flags, mtlb.ps);
    }
    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}

/*
 *  Purge machine tlb.
 *  INPUT
 *      rr:     guest rr.
 *      va:     only bits 0:60 is valid
 *      size:   bits format (1<<size) for the address range to purge.
 *
 */
void machine_tlb_purge(u64 va, u64 ps)
{
//    u64       psr;
//    psr = ia64_clear_ic();
    ia64_ptcl(va, ps << 2);
//    ia64_set_psr(psr);
//    ia64_srlz_i();
//    return;
}

u64 machine_thash(PTA pta, u64 va)
{
    u64     saved_pta;
    u64     hash_addr;
    unsigned long psr;

    saved_pta = ia64_getreg(_IA64_REG_CR_PTA);
    psr = ia64_clear_ic();
    ia64_setreg(_IA64_REG_CR_PTA, pta.val);
    hash_addr = ia64_thash(va);
    ia64_setreg(_IA64_REG_CR_PTA, saved_pta);
    ia64_set_psr(psr);
    ia64_srlz_i();
    return hash_addr;
}

u64 machine_ttag(PTA pta, u64 va)
{
//    u64     saved_pta;
//    u64     hash_addr, tag;
//    u64     psr;
//    struct vcpu *v = current;

//    saved_pta = ia64_getreg(_IA64_REG_CR_PTA);
//    psr = ia64_clear_ic();
//    ia64_setreg(_IA64_REG_CR_PTA, pta.val);
//    tag = ia64_ttag(va);
    return ia64_ttag(va);
//    ia64_setreg(_IA64_REG_CR_PTA, saved_pta);
//    ia64_set_psr(psr);
//    ia64_srlz_i();
//    return tag;
}



int vhpt_enabled(VCPU *vcpu, uint64_t vadr, vhpt_ref_t ref)
{
    ia64_rr  vrr;
    PTA   vpta;
    IA64_PSR  vpsr; 

    vpsr.val = vmx_vcpu_get_psr(vcpu);
    vrr = vmx_vcpu_rr(vcpu, vadr);
    vmx_vcpu_get_pta(vcpu,&vpta.val);

    if ( vrr.ve & vpta.ve ) {
        switch ( ref ) {
        case DATA_REF:
        case NA_REF:
            return vpsr.dt;
        case INST_REF:
            return vpsr.dt && vpsr.it && vpsr.ic;
        case RSE_REF:
            return vpsr.dt && vpsr.rt;

        }
    }
    return 0;
}


int unimplemented_gva(VCPU *vcpu,u64 vadr)
{
    int bit=vcpu->domain->arch.imp_va_msb;
    u64 ladr =(vadr<<3)>>(3+bit);
    if(!ladr||ladr==(1U<<(61-bit))-1){
        return 0;
    }else{
        return 1;
    }
}


/*
 * Prefetch guest bundle code.
 * INPUT:
 *  code: buffer pointer to hold the read data.
 *  num:  number of dword (8byts) to read.
 */
int
fetch_code(VCPU *vcpu, u64 gip, u64 *code)
{
    u64     gpip;   // guest physical IP
    u64     mpa;
    thash_data_t    *tlb;
    ia64_rr vrr;
    u64     mfn;

    if ( !(VCPU(vcpu, vpsr) & IA64_PSR_IT) ) {   // I-side physical mode
        gpip = gip;
    }
    else {
        vmx_vcpu_get_rr(vcpu, gip, &vrr.rrval);
        tlb = vtlb_lookup_ex (vmx_vcpu_get_vtlb(vcpu),
                vrr.rid, gip, ISIDE_TLB );
        if( tlb == NULL )
             tlb = vtlb_lookup_ex (vmx_vcpu_get_vtlb(vcpu),
                vrr.rid, gip, DSIDE_TLB );
        if ( tlb == NULL ) panic("No entry found in ITLB and DTLB\n");
        gpip = (tlb->ppn << 12) | ( gip & (PSIZE(tlb->ps)-1) );
    }
    mfn = gmfn_to_mfn(vcpu->domain, gpip >>PAGE_SHIFT);
    if ( mfn == INVALID_MFN ) return 0;
 
    mpa = (gpip & (PAGE_SIZE-1)) | (mfn<<PAGE_SHIFT);
    *code = *(u64*)__va(mpa);
    return 1;
}

IA64FAULT vmx_vcpu_itc_i(VCPU *vcpu, UINT64 pte, UINT64 itir, UINT64 ifa)
{

    thash_data_t data, *ovl;
    thash_cb_t  *hcb;
    search_section_t sections;
    ia64_rr vrr;

    hcb = vmx_vcpu_get_vtlb(vcpu);
    data.page_flags=pte & ~PAGE_FLAGS_RV_MASK;
    data.itir=itir;
    data.vadr=PAGEALIGN(ifa,data.ps);
    data.tc = 1;
    data.cl=ISIDE_TLB;
    vmx_vcpu_get_rr(vcpu, ifa, (UINT64 *)&vrr);
    data.rid = vrr.rid;
    
    sections.tr = 1;
    sections.tc = 0;

    ovl = thash_find_overlap(hcb, &data, sections);
    while (ovl) {
        // generate MCA.
        panic("Tlb conflict!!");
        return IA64_FAULT;
    }
    thash_purge_and_insert(hcb, &data);
    return IA64_NO_FAULT;
}




IA64FAULT vmx_vcpu_itc_d(VCPU *vcpu, UINT64 pte, UINT64 itir, UINT64 ifa)
{

    thash_data_t data, *ovl;
    thash_cb_t  *hcb;
    search_section_t sections;
    ia64_rr vrr;

    hcb = vmx_vcpu_get_vtlb(vcpu);
    data.page_flags=pte & ~PAGE_FLAGS_RV_MASK;
    data.itir=itir;
    data.vadr=PAGEALIGN(ifa,data.ps);
    data.tc = 1;
    data.cl=DSIDE_TLB;
    vmx_vcpu_get_rr(vcpu, ifa, (UINT64 *)&vrr);
    data.rid = vrr.rid;
    sections.tr = 1;
    sections.tc = 0;

    ovl = thash_find_overlap(hcb, &data, sections);
    if (ovl) {
          // generate MCA.
        panic("Tlb conflict!!");
        return IA64_FAULT;
    }
    thash_purge_and_insert(hcb, &data);
    return IA64_NO_FAULT;
}

/*
 * Return TRUE/FALSE for success of lock operation
 */
int vmx_lock_guest_dtc (VCPU *vcpu, UINT64 va, int lock)
{

    thash_cb_t  *hcb;
    ia64_rr vrr;
    u64	  preferred_size;

    vmx_vcpu_get_rr(vcpu, va, (UINT64 *)&vrr);
    hcb = vmx_vcpu_get_vtlb(vcpu);
    va = PAGEALIGN(va,vrr.ps);
    preferred_size = PSIZE(vrr.ps);
    return thash_lock_tc(hcb, va, preferred_size, vrr.rid, DSIDE_TLB, lock);
}

IA64FAULT vmx_vcpu_itr_i(VCPU *vcpu, UINT64 pte, UINT64 itir, UINT64 ifa, UINT64 idx)
{

    thash_data_t data, *ovl;
    thash_cb_t  *hcb;
    search_section_t sections;
    ia64_rr vrr;

    hcb = vmx_vcpu_get_vtlb(vcpu);
    data.page_flags=pte & ~PAGE_FLAGS_RV_MASK;
    data.itir=itir;
    data.vadr=PAGEALIGN(ifa,data.ps);
    data.tc = 0;
    data.cl=ISIDE_TLB;
    vmx_vcpu_get_rr(vcpu, ifa, (UINT64 *)&vrr);
    data.rid = vrr.rid;
    sections.tr = 1;
    sections.tc = 0;

    ovl = thash_find_overlap(hcb, &data, sections);
    if (ovl) {
        // generate MCA.
        panic("Tlb conflict!!");
        return IA64_FAULT;
    }
    sections.tr = 0;
    sections.tc = 1;
    thash_purge_entries(hcb, &data, sections);
    thash_tr_insert(hcb, &data, ifa, idx);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_itr_d(VCPU *vcpu, UINT64 pte, UINT64 itir, UINT64 ifa, UINT64 idx)
{

    thash_data_t data, *ovl;
    thash_cb_t  *hcb;
    search_section_t sections;
    ia64_rr    vrr;


    hcb = vmx_vcpu_get_vtlb(vcpu);
    data.page_flags=pte & ~PAGE_FLAGS_RV_MASK;
    data.itir=itir;
    data.vadr=PAGEALIGN(ifa,data.ps);
    data.tc = 0;
    data.cl=DSIDE_TLB;
    vmx_vcpu_get_rr(vcpu, ifa, (UINT64 *)&vrr);
    data.rid = vrr.rid;
    sections.tr = 1;
    sections.tc = 0;

    ovl = thash_find_overlap(hcb, &data, sections);
    while (ovl) {
        // generate MCA.
        panic("Tlb conflict!!");
        return IA64_FAULT;
    }
    sections.tr = 0;
    sections.tc = 1;
    thash_purge_entries(hcb, &data, sections);
    thash_tr_insert(hcb, &data, ifa, idx);
    return IA64_NO_FAULT;
}



IA64FAULT vmx_vcpu_ptr_d(VCPU *vcpu,UINT64 vadr,UINT64 ps)
{
    thash_cb_t  *hcb;
    ia64_rr rr;
    search_section_t sections;

    hcb = vmx_vcpu_get_vtlb(vcpu);
    rr=vmx_vcpu_rr(vcpu,vadr);
    sections.tr = 1;
    sections.tc = 1;
    thash_purge_entries_ex(hcb,rr.rid,vadr,ps,sections,DSIDE_TLB);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_ptr_i(VCPU *vcpu,UINT64 vadr,UINT64 ps)
{
    thash_cb_t  *hcb;
    ia64_rr rr;
    search_section_t sections;
    hcb = vmx_vcpu_get_vtlb(vcpu);
    rr=vmx_vcpu_rr(vcpu,vadr);
    sections.tr = 1;
    sections.tc = 1;
    thash_purge_entries_ex(hcb,rr.rid,vadr,ps,sections,ISIDE_TLB);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_ptc_l(VCPU *vcpu, UINT64 vadr, UINT64 ps)
{
    thash_cb_t  *hcb;
    ia64_rr vrr;
    search_section_t sections;
    hcb = vmx_vcpu_get_vtlb(vcpu);
    vrr=vmx_vcpu_rr(vcpu,vadr);
    sections.tr = 0;
    sections.tc = 1;
    vadr = PAGEALIGN(vadr, ps);

    thash_purge_entries_ex(hcb,vrr.rid,vadr,ps,sections,DSIDE_TLB);
    thash_purge_entries_ex(hcb,vrr.rid,vadr,ps,sections,ISIDE_TLB);
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_ptc_e(VCPU *vcpu, UINT64 vadr)
{
    thash_cb_t  *hcb;
    hcb = vmx_vcpu_get_vtlb(vcpu);
    thash_purge_all(hcb);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_ptc_g(VCPU *vcpu, UINT64 vadr, UINT64 ps)
{
    vmx_vcpu_ptc_l(vcpu, vadr, ps);
    return IA64_ILLOP_FAULT;
}

IA64FAULT vmx_vcpu_ptc_ga(VCPU *vcpu,UINT64 vadr,UINT64 ps)
{
    vmx_vcpu_ptc_l(vcpu, vadr, ps);
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_thash(VCPU *vcpu, UINT64 vadr, UINT64 *pval)
{
    PTA vpta;
    ia64_rr vrr;
    u64 vhpt_offset;
    vmx_vcpu_get_pta(vcpu, &vpta.val);
    vrr=vmx_vcpu_rr(vcpu, vadr);
    if(vpta.vf){
        panic("THASH,Don't support long format VHPT");
        *pval = ia64_call_vsa(PAL_VPS_THASH,vadr,vrr.rrval,vpta.val,0,0,0,0);
    }else{
        vhpt_offset=((vadr>>vrr.ps)<<3)&((1UL<<(vpta.size))-1);
        *pval = (vadr&VRN_MASK)|
            (vpta.val<<3>>(vpta.size+3)<<(vpta.size))|
            vhpt_offset;
    }
    return  IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_ttag(VCPU *vcpu, UINT64 vadr, UINT64 *pval)
{
    ia64_rr vrr;
    PTA vpta;
    vmx_vcpu_get_pta(vcpu, &vpta.val);
    vrr=vmx_vcpu_rr(vcpu, vadr);
    if(vpta.vf){
        panic("THASH,Don't support long format VHPT");
        *pval = ia64_call_vsa(PAL_VPS_TTAG,vadr,vrr.rrval,0,0,0,0,0);
    }else{
        *pval = 1;
    }
    return  IA64_NO_FAULT;
}



IA64FAULT vmx_vcpu_tpa(VCPU *vcpu, UINT64 vadr, UINT64 *padr)
{
    thash_data_t *data;
    thash_cb_t  *hcb;
    ia64_rr vrr;
    ISR visr,pt_isr;
    REGS *regs;
    u64 vhpt_adr;
    IA64_PSR vpsr;
    hcb = vmx_vcpu_get_vtlb(vcpu);
    vrr=vmx_vcpu_rr(vcpu,vadr);
    regs=vcpu_regs(vcpu);
    pt_isr.val=VMX(vcpu,cr_isr);
    visr.val=0;
    visr.ei=pt_isr.ei;
    visr.ir=pt_isr.ir;
    vpsr.val = vmx_vcpu_get_psr(vcpu);
    if(vpsr.ic==0){
         visr.ni=1;
    }
    visr.na=1;
    data = vtlb_lookup_ex(hcb, vrr.rid, vadr, DSIDE_TLB);
    if(data){
        if(data->p==0){
            visr.na=1;
            vcpu_set_isr(vcpu,visr.val);
            page_not_present(vcpu, vadr);
            return IA64_FAULT;
        }else if(data->ma == VA_MATTR_NATPAGE){
            visr.na = 1;
            vcpu_set_isr(vcpu, visr.val);
            dnat_page_consumption(vcpu, vadr);
            return IA64_FAULT;
        }else{
            *padr = (data->ppn<<12) | (vadr&(PSIZE(data->ps)-1));
            return IA64_NO_FAULT;
        }
    }else{
        if(!vhpt_enabled(vcpu, vadr, NA_REF)){
            if(vpsr.ic){
                vcpu_set_isr(vcpu, visr.val);
                alt_dtlb(vcpu, vadr);
                return IA64_FAULT;
            }
            else{
                nested_dtlb(vcpu);
                return IA64_FAULT;
            }
        }
        else{
            vmx_vcpu_thash(vcpu, vadr, &vhpt_adr);
            vrr=vmx_vcpu_rr(vcpu,vhpt_adr);
            data = vtlb_lookup_ex(hcb, vrr.rid, vhpt_adr, DSIDE_TLB);
            if(data){
                if(vpsr.ic){
                    vcpu_set_isr(vcpu, visr.val);
                    dtlb_fault(vcpu, vadr);
                    return IA64_FAULT;
                }
                else{
                    nested_dtlb(vcpu);
                    return IA64_FAULT;
                }
            }
            else{
                if(vpsr.ic){
                    vcpu_set_isr(vcpu, visr.val);
                    dvhpt_fault(vcpu, vadr);
                    return IA64_FAULT;
                }
                else{
                    nested_dtlb(vcpu);
                    return IA64_FAULT;
                }
            }
        }
    }
}

IA64FAULT vmx_vcpu_tak(VCPU *vcpu, UINT64 vadr, UINT64 *key)
{
    thash_data_t *data;
    thash_cb_t  *hcb;
    ia64_rr rr;
    PTA vpta;
    vmx_vcpu_get_pta(vcpu, &vpta.val);
    if(vpta.vf==0 || unimplemented_gva(vcpu, vadr)){
        *key=1;
        return IA64_NO_FAULT;
    }
    hcb = vmx_vcpu_get_vtlb(vcpu);
    rr=vmx_vcpu_rr(vcpu,vadr);
    data = vtlb_lookup_ex(hcb, rr.rid, vadr, DSIDE_TLB);
    if(!data||!data->p){
        *key=1;
    }else{
        *key=data->key;
    }
    return IA64_NO_FAULT;
}

/*
 * [FIXME] Is there any effective way to move this routine
 * into vmx_uaccess.h? struct exec_domain is incomplete type
 * in that way...
 *
 * This is the interface to lookup virtual TLB, and then
 * return corresponding machine address in 2nd parameter.
 * The 3rd parameter contains how many bytes mapped by
 * matched vTLB entry, thus to allow caller copy more once.
 *
 * If failed to lookup, -EFAULT is returned. Or else reutrn
 * 0. All upper domain access utilities rely on this routine
 * to determine the real machine address. 
 *
 * Yes, put_user and get_user seems to somhow slow upon it.
 * However it's the necessary steps for any vmx domain virtual
 * address, since that's difference address space as HV's one.
 * Later some short-circuit may be created for special case
 */
long
__domain_va_to_ma(unsigned long va, unsigned long* ma, unsigned long *len)
{
    unsigned long 	mpfn, gpfn, m, n = *len;
    thash_cb_t		*vtlb;
    unsigned long	end;	/* end of the area mapped by current entry */
    thash_data_t	*entry;
    struct vcpu *v = current;
    ia64_rr	vrr;

    vtlb = vmx_vcpu_get_vtlb(v); 
    vrr = vmx_vcpu_rr(v, va);
    entry = vtlb_lookup_ex(vtlb, vrr.rid, va, DSIDE_TLB);
    if (entry == NULL)
	return -EFAULT;

    gpfn =(entry->ppn>>(PAGE_SHIFT-12));
    gpfn =PAGEALIGN(gpfn,(entry->ps-PAGE_SHIFT));
    gpfn = gpfn | POFFSET(va>>PAGE_SHIFT,(entry->ps-PAGE_SHIFT)); 

    mpfn = gmfn_to_mfn(v->domain, gpfn);
    m = (mpfn<<PAGE_SHIFT) | (va & (PAGE_SIZE - 1));
    /* machine address may be not continuous */
    end = PAGEALIGN(m, PAGE_SHIFT) + PAGE_SIZE;
    /*end = PAGEALIGN(m, entry->ps) + PSIZE(entry->ps);*/
    /* Current entry can't map all requested area */
    if ((m + n) > end)
	n = end - m;

    *ma = m;
    *len = n;
    return 0;
}
