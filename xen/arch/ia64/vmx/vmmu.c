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
#include <asm/vmx_vcpu.h>
#include <asm/vmx_pal_vsa.h>
#include <xen/sched-if.h>
#include <asm/vhpt.h>

static int default_vtlb_sz = DEFAULT_VTLB_SZ;
static int default_vhpt_sz = DEFAULT_VHPT_SZ;

static void __init parse_vtlb_size(char *s)
{
    int sz = parse_size_and_unit(s, NULL);

    if (sz > 0) {
        default_vtlb_sz = fls(sz - 1);
        /* minimum 16KB (for tag uniqueness) */
        if (default_vtlb_sz < 14)
            default_vtlb_sz = 14;
    }
}

static void __init parse_vhpt_size(char *s)
{
    int sz = parse_size_and_unit(s, NULL);
    if (sz > 0) {
        default_vhpt_sz = fls(sz - 1);
        default_vhpt_sz = canonicalize_vhpt_size(default_vhpt_sz);
    }
}

custom_param("vti_vtlb_size", parse_vtlb_size);
custom_param("vti_vhpt_size", parse_vhpt_size);


static int init_domain_vhpt(struct vcpu *v)
{
    int rc;
    u64 size = v->domain->arch.hvm_domain.params[HVM_PARAM_VHPT_SIZE];

    if (size == 0)
        size = default_vhpt_sz;
    else
        size = canonicalize_vhpt_size(size);

    rc = thash_alloc(&(v->arch.vhpt), size, "vhpt");
    v->arch.arch_vmx.mpta = v->arch.vhpt.pta.val;
    return rc;
}


static void free_domain_vhpt(struct vcpu *v)
{
    if (v->arch.vhpt.hash)
        thash_free(&(v->arch.vhpt));
}

int init_domain_tlb(struct vcpu *v)
{
    int rc;

    rc = init_domain_vhpt(v);
    if (rc)
        return rc;

    rc = thash_alloc(&(v->arch.vtlb), default_vtlb_sz, "vtlb");
    if (rc) {
        free_domain_vhpt(v);
        return rc;
    }
    
    return 0;
}


void free_domain_tlb(struct vcpu *v)
{
    if (v->arch.vtlb.hash)
        thash_free(&(v->arch.vtlb));

    free_domain_vhpt(v);
}


int vhpt_enabled(VCPU *vcpu, uint64_t vadr, vhpt_ref_t ref)
{
    ia64_rr  vrr;
    PTA   vpta;
    IA64_PSR  vpsr; 

    vpsr.val = VCPU(vcpu, vpsr);
    vcpu_get_rr(vcpu, vadr, &vrr.rrval);
    vpta.val = vmx_vcpu_get_pta(vcpu);

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
        gpip = pa_clear_uc(gip);	// clear UC bit
    }
    else {
        tlb = vtlb_lookup(vcpu, gip, ISIDE_TLB);
//        if( tlb == NULL )
//             tlb = vtlb_lookup(vcpu, gip, DSIDE_TLB );
        if (tlb)
            gpip = thash_translate(tlb, gip);
    }
    if( gpip){
        mfn = gmfn_to_mfn(vcpu->domain, gpip >>PAGE_SHIFT);
        if (mfn == INVALID_MFN)
            panic_domain(vcpu_regs(vcpu), "fetch_code: invalid memory\n");
        maddr = (mfn << PAGE_SHIFT) | (gpip & (PAGE_SIZE - 1));
    }else{
        tlb = vhpt_lookup(gip);
        if (tlb == NULL) {
            ia64_ptcl(gip, ARCH_PAGE_SHIFT << 2);
            return IA64_RETRY;
        }
        maddr = thash_translate(tlb, gip);
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

    if (slot >= NITRS) {
        panic_domain(NULL, "bad itr.i slot (%ld)", slot);
        return IA64_FAULT;
    }
        
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

    if (slot >= NDTRS) {
        panic_domain(NULL, "bad itr.d slot (%ld)", slot);
        return IA64_FAULT;
    }

    pte &= ~PAGE_FLAGS_RV_MASK;

    /* This is a bad workaround
       In Linux, region 7 use 16M pagesize and is identity mapped.
       VHPT page size is 16K in XEN.  If purge VHPT while guest insert 16M,
       it will iteratively purge VHPT 1024 times, which makes XEN/IPF very
       slow.  XEN doesn't purge VHPT
    */   
    if (ps != _PAGE_SIZE_16M)
        thash_purge_entries(vcpu, va, ps);
    gpfn = pte_pfn(__pte(pte));
    vcpu_get_rr(vcpu, va, &rid);
    rid &= RR_RID_MASK;
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
    return vmx_vcpu_ptc_ga(vcpu, va, ps);
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
    u64 oldrid, moldrid, mpta, oldpsbits, vadr, flags;
    struct ptc_ga_args *args = (struct ptc_ga_args *)varg;
    VCPU *v = args->vcpu;
    int cpu = v->processor;

    vadr = args->vadr;

    /* Try again if VCPU has migrated. */
    if (cpu != current->processor)
        return;
    local_irq_save(flags);
    if (!spin_trylock(per_cpu(schedule_data, cpu).schedule_lock))
        goto bail2;
    if (v->processor != cpu)
        goto bail1;
    oldrid = VMX(v, vrr[0]);
    VMX(v, vrr[0]) = args->rid;
    oldpsbits = VMX(v, psbits[0]);
    VMX(v, psbits[0]) = VMX(v, psbits[REGION_NUMBER(vadr)]);
    moldrid = ia64_get_rr(0x0);
    ia64_set_rr(0x0,vrrtomrr(v,args->rid));
    mpta = ia64_get_pta();
    ia64_set_pta(v->arch.arch_vmx.mpta&(~1));
    ia64_srlz_d();
    vadr = PAGEALIGN(vadr, args->ps);
    thash_purge_entries_remote(v, vadr, args->ps);
    VMX(v, vrr[0]) = oldrid; 
    VMX(v, psbits[0]) = oldpsbits;
    ia64_set_rr(0x0,moldrid);
    ia64_set_pta(mpta);
    ia64_dv_serialize_data();
    args->vcpu = NULL;
bail1:
    spin_unlock(per_cpu(schedule_data, cpu).schedule_lock);
bail2:
    local_irq_restore(flags);
}


IA64FAULT vmx_vcpu_ptc_ga(VCPU *vcpu, u64 va, u64 ps)
{

    struct domain *d = vcpu->domain;
    struct vcpu *v;
    struct ptc_ga_args args;
    int cpu;

    args.vadr = va;
    vcpu_get_rr(vcpu, va, &args.rid);
    args.ps = ps;
    for_each_vcpu (d, v) {
        if (!v->is_initialised)
            continue;

        if (v == vcpu) {
            vmx_vcpu_ptc_l(v, va, ps);
            continue;
        }

        args.vcpu = v;
        do {
            cpu = v->processor;
            if (cpu != current->processor) {
                spin_barrier(per_cpu(schedule_data, cpu).schedule_lock);
                /* Flush VHPT on remote processors. */
                smp_call_function_single(cpu, &ptc_ga_remote_func, &args, 1);
            } else {
                ptc_ga_remote_func(&args);
            }
        } while (args.vcpu != NULL);
    }
    return IA64_NO_FAULT;
}


u64 vmx_vcpu_thash(VCPU *vcpu, u64 vadr)
{
    PTA vpta;
    ia64_rr vrr;
    u64 pval;
    u64 vhpt_offset;
    u64 mask;

    vpta.val = vmx_vcpu_get_pta(vcpu);
    vcpu_get_rr(vcpu, vadr, &vrr.rrval);
    mask = (1UL << vpta.size) - 1;
    if (vpta.vf) {
        vadr = (vadr & 0x1fffffffffffffffUL) >> vrr.ps;
        vhpt_offset = vadr ^ vrr.rid;
        pval = (vpta.val & ~0x7fffUL) + ((vhpt_offset << 5) & mask);
    } else {
        vhpt_offset=((vadr >> vrr.ps) << 3) & mask;
        pval = (vadr & VRN_MASK) |
            (vpta.val << 3 >> (vpta.size + 3) << vpta.size) |
            vhpt_offset;
    }
    return  pval;
}


u64 vmx_vcpu_ttag(VCPU *vcpu, u64 vadr)
{
    ia64_rr vrr;
    PTA vpta;
    u64 pval;
    u64 rid;
    vpta.val = vmx_vcpu_get_pta(vcpu);
    vcpu_get_rr(vcpu, vadr, &vrr.rrval);
    if(vpta.vf){
        vadr = (vadr & 0x1fffffffffffffffUL) >> vrr.ps;
        rid = vrr.rid;
        pval = vadr ^ (rid << 39);
    }else{
        pval = 1;
    }
    return  pval;
}



IA64FAULT vmx_vcpu_tpa(VCPU *vcpu, u64 vadr, u64 *padr)
{
    thash_data_t *data;
    ISR visr,pt_isr;
    REGS *regs;
    u64 vhpt_adr, madr;
    IA64_PSR vpsr;

    regs = vcpu_regs(vcpu);
    pt_isr.val = VMX(vcpu, cr_isr);
    visr.val = 0;
    visr.ei = pt_isr.ei;
    visr.ir = pt_isr.ir;
    vpsr.val = VCPU(vcpu, vpsr);
    visr.na = 1;

    /* First look in VTLB.  */
    data = vtlb_lookup(vcpu, vadr, DSIDE_TLB);
    if (data) {
        if (data->p == 0) {
            vcpu_set_isr(vcpu,visr.val);
            data_page_not_present(vcpu, vadr);
            return IA64_FAULT;
        } else if (data->ma == VA_MATTR_NATPAGE) {
            vcpu_set_isr(vcpu, visr.val);
            dnat_page_consumption(vcpu, vadr);
            return IA64_FAULT;
        } else {
            *padr = thash_translate(data, vadr);
            return IA64_NO_FAULT;
        }
    }

    /* Look in mVHPT.  */
    data = vhpt_lookup(vadr);
    if (data) {
        if (data->p == 0) {
            vcpu_set_isr(vcpu,visr.val);
            data_page_not_present(vcpu, vadr);
            return IA64_FAULT;
        } else if (data->ma == VA_MATTR_NATPAGE) {
            vcpu_set_isr(vcpu, visr.val);
            dnat_page_consumption(vcpu, vadr);
            return IA64_FAULT;
        } else {
            madr = thash_translate(data, vadr);
            *padr = __mpa_to_gpa(madr);
            return IA64_NO_FAULT;
        }
    }

    /* If VHPT is not enabled, inject fault.  */
    if (!vhpt_enabled(vcpu, vadr, NA_REF)) {
        if (vpsr.ic) {
            vcpu_set_isr(vcpu, visr.val);
            alt_dtlb(vcpu, vadr);
            return IA64_FAULT;
        } else {
            nested_dtlb(vcpu);
            return IA64_FAULT;
        }
    }

    /* Get gVHPT entry.  */
    vhpt_adr = vmx_vcpu_thash(vcpu, vadr);
    data = vtlb_lookup(vcpu, vhpt_adr, DSIDE_TLB);
    if (data) {
        /* FIXME: we should read gadr from the entry!  */
        if (vpsr.ic) {
            vcpu_set_isr(vcpu, visr.val);
            dtlb_fault(vcpu, vadr);
            return IA64_FAULT;
        } else {
            nested_dtlb(vcpu);
            return IA64_FAULT;
        }
    } else {
        if (vpsr.ic) {
            vcpu_set_isr(vcpu, visr.val);
            dvhpt_fault(vcpu, vadr);
            return IA64_FAULT;
        } else {
            nested_dtlb(vcpu);
            return IA64_FAULT;
        }
    }
}

u64 vmx_vcpu_tak(VCPU *vcpu, u64 vadr)
{
    thash_data_t *data;
    u64 key;

    if (unimplemented_gva(vcpu, vadr)) {
        key = 1;
        return key;
    }

    data = vtlb_lookup(vcpu, vadr, DSIDE_TLB);
    if (data) {
        if (data->p)
            return data->key << 8;
        else
            return 1;
    }

    data = vhpt_lookup(vadr);
    if (data) {
        if (data->p)
            return data->key << 8;	/* FIXME: possible mangling/masking.  */
        else
            return 1;
    }

    if (!vhpt_enabled(vcpu, vadr, NA_REF))
        return 1;

    /* FIXME: look in the guest VHPT.  */
    return 1;
}
