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
#include <asm/vcpu.h>
#include <xen/irq.h>
#include <xen/errno.h>

/*
 * Get the machine page frame number in 16KB unit
 * Input:
 *  d: 
 */
u64 get_mfn(struct domain *d, u64 gpfn)
{
//    struct domain *d;
    u64    xen_gppn, xen_mppn, mpfn;
/*
    if ( domid == DOMID_SELF ) {
        d = current->domain;
    }
    else {
        d = get_domain_by_id(domid);
    }
 */
    xen_gppn = arch_to_xen_ppn(gpfn);
    xen_mppn = gmfn_to_mfn(d, xen_gppn);
/*
    for (i=0; i<pages; i++) {
        if ( gmfn_to_mfn(d, gpfn+i) == INVALID_MFN ) {
            return INVALID_MFN;
        }
    }
*/
    mpfn= xen_to_arch_ppn(xen_mppn);
    mpfn = mpfn | (((1UL <<(PAGE_SHIFT-ARCH_PAGE_SHIFT))-1)&gpfn);
    return mpfn;
    
}

/*
 * The VRN bits of va stand for which rr to get.
 */
//ia64_rr vmmu_get_rr(struct vcpu *vcpu, u64 va)
//{
//    ia64_rr   vrr;
//    vcpu_get_rr(vcpu, va, &vrr.rrval);
//    return vrr;
//}

/*
void recycle_message(thash_cb_t *hcb, u64 para)
{
    if(hcb->ht == THASH_VHPT)
    {
        printk("ERROR : vhpt recycle happenning!!!\n");
    }
    printk("hcb=%p recycled with %lx\n",hcb,para);
}
 */

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

static void init_domain_vhpt(struct vcpu *v)
{
    struct page_info *page;
    void * vbase;
    page = alloc_domheap_pages (NULL, VCPU_VHPT_ORDER, 0);
    if ( page == NULL ) {
        panic_domain(vcpu_regs(v),"No enough contiguous memory for init_domain_vhpt\n");
    }
    vbase = page_to_virt(page);
    memset(vbase, 0, VCPU_VHPT_SIZE);
    printk("Allocate domain vhpt at 0x%p\n", vbase);
    
    VHPT(v,hash) = vbase;
    VHPT(v,hash_sz) = VCPU_VHPT_SIZE/2;
    VHPT(v,cch_buf) = (void *)((u64)vbase + VHPT(v,hash_sz));
    VHPT(v,cch_sz) = VCPU_VHPT_SIZE - VHPT(v,hash_sz);
    thash_init(&(v->arch.vhpt),VCPU_VHPT_SHIFT-1);
    v->arch.arch_vmx.mpta = v->arch.vhpt.pta.val;
}



void init_domain_tlb(struct vcpu *v)
{
    struct page_info *page;
    void * vbase;
    init_domain_vhpt(v);
    page = alloc_domheap_pages (NULL, VCPU_VTLB_ORDER, 0);
    if ( page == NULL ) {
        panic_domain(vcpu_regs(v),"No enough contiguous memory for init_domain_tlb\n");
    }
    vbase = page_to_virt(page);
    memset(vbase, 0, VCPU_VTLB_SIZE);
    printk("Allocate domain vtlb at 0x%p\n", vbase);
    
    VTLB(v,hash) = vbase;
    VTLB(v,hash_sz) = VCPU_VTLB_SIZE/2;
    VTLB(v,cch_buf) = (void *)((u64)vbase + VTLB(v,hash_sz));
    VTLB(v,cch_sz) = VCPU_VTLB_SIZE - VTLB(v,hash_sz);
    thash_init(&(v->arch.vtlb),VCPU_VTLB_SHIFT-1);
}

void free_domain_tlb(struct vcpu *v)
{
    struct page_info *page;

    if ( v->arch.vtlb.hash) {
        page = virt_to_page(v->arch.vtlb.hash);
        free_domheap_pages(page, VCPU_VTLB_ORDER);
    }
    if ( v->arch.vhpt.hash) {
        page = virt_to_page(v->arch.vhpt.hash);
        free_domheap_pages(page, VCPU_VHPT_ORDER);
    }
}

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
    mtlb.page_flags = tlb->page_flags & ~PAGE_FLAGS_RV_MASK;
    mtlb.ppn = get_mfn(d->domain,tlb->ppn);
    mtlb_ppn=mtlb.ppn;

#if 0
    if (mtlb_ppn == INVALID_MFN)
        panic_domain(vcpu_regs(d),"Machine tlb insert with invalid mfn number.\n");
#endif

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
/*
u64 machine_thash(u64 va)
{
    return ia64_thash(va);
}

u64 machine_ttag(u64 va)
{
    return ia64_ttag(va);
}
*/
thash_data_t * vsa_thash(PTA vpta, u64 va, u64 vrr, u64 *tag)
{
    u64 index,pfn,rid,pfn_bits;
    pfn_bits = vpta.size-5-8;
    pfn = REGION_OFFSET(va)>>_REGION_PAGE_SIZE(vrr);
    rid = _REGION_ID(vrr);
    index = ((rid&0xff)<<pfn_bits)|(pfn&((1UL<<pfn_bits)-1));
    *tag = ((rid>>8)&0xffff) | ((pfn >>pfn_bits)<<16);
    return (thash_data_t *)((vpta.base<<PTA_BASE_SHIFT)+(index<<5));
//    return ia64_call_vsa(PAL_VPS_THASH,va,vrr,vpta,0,0,0,0);
}

//u64 vsa_ttag(u64 va, u64 vrr)
//{
//    return ia64_call_vsa(PAL_VPS_TTAG,va,vrr,0,0,0,0,0);
//}

int vhpt_enabled(VCPU *vcpu, uint64_t vadr, vhpt_ref_t ref)
{
    ia64_rr  vrr;
    PTA   vpta;
    IA64_PSR  vpsr; 

    vpsr.val = VCPU(vcpu, vpsr);
    vcpu_get_rr(vcpu, vadr, &vrr.rrval);
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
#if 0
    int bit=vcpu->domain->arch.imp_va_msb;
    u64 ladr =(vadr<<3)>>(3+bit);
    if(!ladr||ladr==(1U<<(61-bit))-1){
        return 0;
    }else{
        return 1;
    }
#else
    return 0;
#endif
}


/*
 * Fetch guest bundle code.
 * INPUT:
 *  gip: guest ip
 *  pbundle: used to return fetched bundle.
 */
unsigned long
fetch_code(VCPU *vcpu, u64 gip, IA64_BUNDLE *pbundle)
{
    u64     gpip=0;   // guest physical IP
    u64     *vpa;
    thash_data_t    *tlb;
    u64     mfn, maddr;
    struct page_info* page;

 again:
    if ( !(VCPU(vcpu, vpsr) & IA64_PSR_IT) ) {   // I-side physical mode
        gpip = gip;
    }
    else {
        tlb = vtlb_lookup(vcpu, gip, ISIDE_TLB);
//        if( tlb == NULL )
//             tlb = vtlb_lookup(vcpu, gip, DSIDE_TLB );
        if (tlb)
            gpip = (tlb->ppn >>(tlb->ps-12)<<tlb->ps) | ( gip & (PSIZE(tlb->ps)-1) );
    }
    if( gpip){
        mfn = gmfn_to_mfn(vcpu->domain, gpip >>PAGE_SHIFT);
        if( mfn == INVALID_MFN )  panic_domain(vcpu_regs(vcpu),"fetch_code: invalid memory\n");
        maddr = (mfn << PAGE_SHIFT) | (gpip & (PAGE_SIZE - 1));
    }else{
        tlb = vhpt_lookup(gip);
        if (tlb == NULL) {
            ia64_ptcl(gip, ARCH_PAGE_SHIFT << 2);
            return IA64_RETRY;
        }
        maddr = (tlb->ppn >> (tlb->ps - 12) << tlb->ps) |
                (gip & (PSIZE(tlb->ps) - 1));
        mfn = maddr >> PAGE_SHIFT;
    }

    page = mfn_to_page(mfn);
    if (get_page(page, vcpu->domain) == 0) {
        if (page_get_owner(page) != vcpu->domain) {
            // This page might be a page granted by another domain.
            panic_domain(NULL, "domain tries to execute foreign domain "
                         "page which might be mapped by grant table.\n");
        }
        goto again;
    }
    vpa = (u64 *)__va(maddr);

    pbundle->i64[0] = *vpa++;
    pbundle->i64[1] = *vpa;
    put_page(page);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_itc_i(VCPU *vcpu, u64 pte, u64 itir, u64 ifa)
{
#ifdef VTLB_DEBUG
    int slot;
    u64 ps, va;
    ps = itir_ps(itir);
    va = PAGEALIGN(ifa, ps);
    slot = vtr_find_overlap(vcpu, va, ps, ISIDE_TLB);
    if (slot >=0) {
        // generate MCA.
        panic_domain(vcpu_regs(vcpu),"Tlb conflict!!");
        return IA64_FAULT;
    }
#endif //VTLB_DEBUG    
    pte &= ~PAGE_FLAGS_RV_MASK;
    thash_purge_and_insert(vcpu, pte, itir, ifa, ISIDE_TLB);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_itc_d(VCPU *vcpu, u64 pte, u64 itir, u64 ifa)
{
    u64 gpfn;
#ifdef VTLB_DEBUG    
    int slot;
    u64 ps, va;
    ps = itir_ps(itir);
    va = PAGEALIGN(ifa, ps);
    slot = vtr_find_overlap(vcpu, va, ps, DSIDE_TLB);
    if (slot >=0) {
        // generate MCA.
        panic_domain(vcpu_regs(vcpu),"Tlb conflict!!");
        return IA64_FAULT;
    }
#endif //VTLB_DEBUG
    pte &= ~PAGE_FLAGS_RV_MASK;
    gpfn = (pte & _PAGE_PPN_MASK)>> PAGE_SHIFT;
    if (VMX_DOMAIN(vcpu) && __gpfn_is_io(vcpu->domain, gpfn))
        pte |= VTLB_PTE_IO;
    thash_purge_and_insert(vcpu, pte, itir, ifa, DSIDE_TLB);
    return IA64_NO_FAULT;

}




IA64FAULT vmx_vcpu_itr_i(VCPU *vcpu, u64 slot, u64 pte, u64 itir, u64 ifa)
{
#ifdef VTLB_DEBUG
    int index;
#endif    
    u64 ps, va, rid;
    thash_data_t * p_itr;
    ps = itir_ps(itir);
    va = PAGEALIGN(ifa, ps);
#ifdef VTLB_DEBUG    
    index = vtr_find_overlap(vcpu, va, ps, ISIDE_TLB);
    if (index >=0) {
        // generate MCA.
        panic_domain(vcpu_regs(vcpu),"Tlb conflict!!");
        return IA64_FAULT;
    }
    thash_purge_entries(vcpu, va, ps);
#endif
    pte &= ~PAGE_FLAGS_RV_MASK;
    vcpu_get_rr(vcpu, va, &rid);
    rid = rid& RR_RID_MASK;
    p_itr = (thash_data_t *)&vcpu->arch.itrs[slot];
    vmx_vcpu_set_tr(p_itr, pte, itir, va, rid);
    vcpu_quick_region_set(PSCBX(vcpu,itr_regions),va);
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_itr_d(VCPU *vcpu, u64 slot, u64 pte, u64 itir, u64 ifa)
{
#ifdef VTLB_DEBUG
    int index;
#endif    
    u64 gpfn;
    u64 ps, va, rid;
    thash_data_t * p_dtr;
    ps = itir_ps(itir);
    va = PAGEALIGN(ifa, ps);
#ifdef VTLB_DEBUG    
    index = vtr_find_overlap(vcpu, va, ps, DSIDE_TLB);
    if (index>=0) {
        // generate MCA.
        panic_domain(vcpu_regs(vcpu),"Tlb conflict!!");
        return IA64_FAULT;
    }
#endif   
    pte &= ~PAGE_FLAGS_RV_MASK;

    /* This is a bad workaround
       In Linux, region 7 use 16M pagesize and is identity mapped.
       VHPT page size is 16K in XEN.  If purge VHPT while guest insert 16M,
       it will iteratively purge VHPT 1024 times, which makes XEN/IPF very
       slow.  XEN doesn't purge VHPT
    */   
    if (ps != _PAGE_SIZE_16M)
        thash_purge_entries(vcpu, va, ps);
    gpfn = (pte & _PAGE_PPN_MASK)>> PAGE_SHIFT;
    if (VMX_DOMAIN(vcpu) && __gpfn_is_io(vcpu->domain, gpfn))
        pte |= VTLB_PTE_IO;
    vcpu_get_rr(vcpu, va, &rid);
    rid = rid& RR_RID_MASK;
    p_dtr = (thash_data_t *)&vcpu->arch.dtrs[slot];
    vmx_vcpu_set_tr((thash_data_t *)&vcpu->arch.dtrs[slot], pte, itir, va, rid);
    vcpu_quick_region_set(PSCBX(vcpu,dtr_regions),va);
    return IA64_NO_FAULT;
}



IA64FAULT vmx_vcpu_ptr_d(VCPU *vcpu,u64 ifa, u64 ps)
{
    int index;
    u64 va;

    va = PAGEALIGN(ifa, ps);
    while ((index = vtr_find_overlap(vcpu, va, ps, DSIDE_TLB)) >= 0) {
        vcpu->arch.dtrs[index].pte.p=0;
    }
    thash_purge_entries(vcpu, va, ps);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_ptr_i(VCPU *vcpu, u64 ifa, u64 ps)
{
    int index;
    u64 va;

    va = PAGEALIGN(ifa, ps);
    while ((index = vtr_find_overlap(vcpu, va, ps, ISIDE_TLB)) >= 0) {
        vcpu->arch.itrs[index].pte.p=0;
    }
    thash_purge_entries(vcpu, va, ps);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_ptc_l(VCPU *vcpu, u64 va, u64 ps)
{
    va = PAGEALIGN(va, ps);
    thash_purge_entries(vcpu, va, ps);
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_ptc_e(VCPU *vcpu, u64 va)
{
    thash_purge_all(vcpu);
    return IA64_NO_FAULT;
}

IA64FAULT vmx_vcpu_ptc_g(VCPU *vcpu, u64 va, u64 ps)
{
    vmx_vcpu_ptc_ga(vcpu, va, ps);
    return IA64_ILLOP_FAULT;
}
/*
IA64FAULT vmx_vcpu_ptc_ga(VCPU *vcpu, u64 va, u64 ps)
{
    vmx_vcpu_ptc_l(vcpu, va, ps);
    return IA64_NO_FAULT;
}
 */
struct ptc_ga_args {
    unsigned long vadr;
    unsigned long rid;
    unsigned long ps;
    struct vcpu *vcpu;
};

static void ptc_ga_remote_func (void *varg)
{
    u64 oldrid, moldrid, mpta, oldpsbits, vadr;
    struct ptc_ga_args *args = (struct ptc_ga_args *)varg;
    VCPU *v = args->vcpu;
    vadr = args->vadr;

    oldrid = VMX(v, vrr[0]);
    VMX(v, vrr[0]) = args->rid;
    oldpsbits = VMX(v, psbits[0]);
    VMX(v, psbits[0]) = VMX(v, psbits[REGION_NUMBER(vadr)]);
    moldrid = ia64_get_rr(0x0);
    ia64_set_rr(0x0,vrrtomrr(v,args->rid));
    mpta = ia64_get_pta();
    ia64_set_pta(v->arch.arch_vmx.mpta&(~1));
    ia64_srlz_d();
    vmx_vcpu_ptc_l(v, REGION_OFFSET(vadr), args->ps);
    VMX(v, vrr[0]) = oldrid; 
    VMX(v, psbits[0]) = oldpsbits;
    ia64_set_rr(0x0,moldrid);
    ia64_set_pta(mpta);
    ia64_dv_serialize_data();
}


IA64FAULT vmx_vcpu_ptc_ga(VCPU *vcpu, u64 va, u64 ps)
{

    struct domain *d = vcpu->domain;
    struct vcpu *v;
    struct ptc_ga_args args;

    args.vadr = va;
    vcpu_get_rr(vcpu, va, &args.rid);
    args.ps = ps;
    for_each_vcpu (d, v) {
        if (!test_bit(_VCPUF_initialised, &v->vcpu_flags))
            continue;

        args.vcpu = v;
        if (v->processor != vcpu->processor) {
            int proc;
            /* Flush VHPT on remote processors.  */
            do {
                proc = v->processor;
                smp_call_function_single(v->processor, 
                    &ptc_ga_remote_func, &args, 0, 1);
                /* Try again if VCPU has migrated.  */
            } while (proc != v->processor);
        }
        else if(v == vcpu)
            vmx_vcpu_ptc_l(v, va, ps);
        else
            ptc_ga_remote_func(&args);
    }
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_thash(VCPU *vcpu, u64 vadr, u64 *pval)
{
    PTA vpta;
    ia64_rr vrr;
    u64 vhpt_offset;
    vmx_vcpu_get_pta(vcpu, &vpta.val);
    vcpu_get_rr(vcpu, vadr, &vrr.rrval);
    if(vpta.vf){
        *pval = ia64_call_vsa(PAL_VPS_THASH,vadr,vrr.rrval,vpta.val,0,0,0,0);
        *pval = vpta.val & ~0xffff;
    }else{
        vhpt_offset=((vadr>>vrr.ps)<<3)&((1UL<<(vpta.size))-1);
        *pval = (vadr&VRN_MASK)|
            (vpta.val<<3>>(vpta.size+3)<<(vpta.size))|
            vhpt_offset;
    }
    return  IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_ttag(VCPU *vcpu, u64 vadr, u64 *pval)
{
    ia64_rr vrr;
    PTA vpta;
    vmx_vcpu_get_pta(vcpu, &vpta.val);
    vcpu_get_rr(vcpu, vadr, &vrr.rrval);
    if(vpta.vf){
        *pval = ia64_call_vsa(PAL_VPS_TTAG,vadr,vrr.rrval,0,0,0,0,0);
    }else{
        *pval = 1;
    }
    return  IA64_NO_FAULT;
}



IA64FAULT vmx_vcpu_tpa(VCPU *vcpu, u64 vadr, u64 *padr)
{
    thash_data_t *data;
    ISR visr,pt_isr;
    REGS *regs;
    u64 vhpt_adr, madr;
    IA64_PSR vpsr;
    regs=vcpu_regs(vcpu);
    pt_isr.val=VMX(vcpu,cr_isr);
    visr.val=0;
    visr.ei=pt_isr.ei;
    visr.ir=pt_isr.ir;
    vpsr.val = VCPU(vcpu, vpsr);
    visr.na=1;
    data = vtlb_lookup(vcpu, vadr, DSIDE_TLB);
    if(data){
        if(data->p==0){
            vcpu_set_isr(vcpu,visr.val);
            data_page_not_present(vcpu, vadr);
            return IA64_FAULT;
        }else if(data->ma == VA_MATTR_NATPAGE){
            vcpu_set_isr(vcpu, visr.val);
            dnat_page_consumption(vcpu, vadr);
            return IA64_FAULT;
        }else{
            *padr = ((data->ppn >> (data->ps - 12)) << data->ps) |
                    (vadr & (PSIZE(data->ps) - 1));
            return IA64_NO_FAULT;
        }
    }
    data = vhpt_lookup(vadr);
    if(data){
        if(data->p==0){
            vcpu_set_isr(vcpu,visr.val);
            data_page_not_present(vcpu, vadr);
            return IA64_FAULT;
        }else if(data->ma == VA_MATTR_NATPAGE){
            vcpu_set_isr(vcpu, visr.val);
            dnat_page_consumption(vcpu, vadr);
            return IA64_FAULT;
        }else{
            madr = (data->ppn >> (data->ps - 12) << data->ps) |
                   (vadr & (PSIZE(data->ps) - 1));
            *padr = __mpa_to_gpa(madr);
            return IA64_NO_FAULT;
        }
    }
    else{
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
            data = vtlb_lookup(vcpu, vhpt_adr, DSIDE_TLB);
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

IA64FAULT vmx_vcpu_tak(VCPU *vcpu, u64 vadr, u64 *key)
{
    thash_data_t *data;
    PTA vpta;
    vmx_vcpu_get_pta(vcpu, &vpta.val);
    if(vpta.vf==0 || unimplemented_gva(vcpu, vadr)){
        *key=1;
        return IA64_NO_FAULT;
    }
    data = vtlb_lookup(vcpu, vadr, DSIDE_TLB);
    if(!data||!data->p){
        *key=1;
    }else{
        *key=data->key;
    }
    return IA64_NO_FAULT;
}
