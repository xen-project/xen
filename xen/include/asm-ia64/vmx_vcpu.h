/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_vcpu.h:
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

#ifndef _XEN_IA64_VMX_VCPU_H
#define _XEN_IA64_VMX_VCPU_H


#include <xen/sched.h>
#include <asm/ia64_int.h>
#include <asm/vmx_vpd.h>
#include <asm/ptrace.h>
#include <asm/regs.h>
#include <asm/regionreg.h>
#include <asm/types.h>
#include <asm/vcpu.h>

#define VRN_SHIFT    61
#define VRN0    0x0UL
#define VRN1    0x1UL
#define VRN2    0x2UL
#define VRN3    0x3UL
#define VRN4    0x4UL
#define VRN5    0x5UL
#define VRN6    0x6UL
#define VRN7    0x7UL

// this def for vcpu_regs won't work if kernel stack is present
#define	vcpu_regs(vcpu) (((struct pt_regs *) ((char *) (vcpu) + IA64_STK_OFFSET)) - 1)
#define	VMX_VPD(x,y)	((x)->arch.arch_vmx.vpd->y)

#define VMX(x,y)  ((x)->arch.arch_vmx.y)

#define VPD_CR(x,y) (((cr_t*)VMX_VPD(x,vcr))->y)

#define VMM_RR_SHIFT    20
#define VMM_RR_MASK     ((1UL<<VMM_RR_SHIFT)-1)
#define VRID_2_MRID(vcpu,rid)  ((rid) & VMM_RR_MASK) | \
                ((vcpu->domain->id) << VMM_RR_SHIFT)
extern u64 indirect_reg_igfld_MASK ( int type, int index, u64 value);
extern u64 cr_igfld_mask (int index, u64 value);
extern int check_indirect_reg_rsv_fields ( int type, int index, u64 value );
extern u64 set_isr_ei_ni (VCPU *vcpu);
extern u64 set_isr_for_na_inst(VCPU *vcpu, int op);


/* next all for CONFIG_VTI APIs definition */
extern void vmx_vcpu_set_psr(VCPU *vcpu, unsigned long value);
extern UINT64 vmx_vcpu_sync_mpsr(UINT64 mipsr, UINT64 value);
extern void vmx_vcpu_set_psr_sync_mpsr(VCPU * vcpu, UINT64 value);
extern IA64FAULT vmx_vcpu_cover(VCPU *vcpu);
extern thash_cb_t *vmx_vcpu_get_vtlb(VCPU *vcpu);
extern thash_cb_t *vmx_vcpu_get_vhpt(VCPU *vcpu);
ia64_rr vmx_vcpu_rr(VCPU *vcpu,UINT64 vadr);
extern IA64FAULT vmx_vcpu_set_rr(VCPU *vcpu, UINT64 reg, UINT64 val);
extern IA64FAULT vmx_vcpu_get_rr(VCPU *vcpu, UINT64 reg, UINT64 *pval);
extern IA64FAULT vmx_vcpu_get_pkr(VCPU *vcpu, UINT64 reg, UINT64 *pval);
IA64FAULT vmx_vcpu_set_pkr(VCPU *vcpu, UINT64 reg, UINT64 val);
extern IA64FAULT vmx_vcpu_itc_i(VCPU *vcpu, UINT64 pte, UINT64 itir, UINT64 ifa);
extern IA64FAULT vmx_vcpu_itc_d(VCPU *vcpu, UINT64 pte, UINT64 itir, UINT64 ifa);
extern IA64FAULT vmx_vcpu_itr_i(VCPU *vcpu, UINT64 pte, UINT64 itir, UINT64 ifa, UINT64 idx);
extern IA64FAULT vmx_vcpu_itr_d(VCPU *vcpu, UINT64 pte, UINT64 itir, UINT64 ifa, UINT64 idx);
extern IA64FAULT vmx_vcpu_ptr_d(VCPU *vcpu,UINT64 vadr,UINT64 ps);
extern IA64FAULT vmx_vcpu_ptr_i(VCPU *vcpu,UINT64 vadr,UINT64 ps);
extern IA64FAULT vmx_vcpu_ptc_l(VCPU *vcpu, UINT64 vadr, UINT64 ps);
extern IA64FAULT vmx_vcpu_ptc_e(VCPU *vcpu, UINT64 vadr);
extern IA64FAULT vmx_vcpu_ptc_g(VCPU *vcpu, UINT64 vadr, UINT64 ps);
extern IA64FAULT vmx_vcpu_ptc_ga(VCPU *vcpu,UINT64 vadr,UINT64 ps);
extern IA64FAULT vmx_vcpu_thash(VCPU *vcpu, UINT64 vadr, UINT64 *pval);
extern u64 vmx_vcpu_get_itir_on_fault(VCPU *vcpu, u64 ifa);
extern IA64FAULT vmx_vcpu_ttag(VCPU *vcpu, UINT64 vadr, UINT64 *pval);
extern IA64FAULT vmx_vcpu_tpa(VCPU *vcpu, UINT64 vadr, UINT64 *padr);
extern IA64FAULT vmx_vcpu_tak(VCPU *vcpu, UINT64 vadr, UINT64 *key);
extern IA64FAULT vmx_vcpu_rfi(VCPU *vcpu);
extern UINT64 vmx_vcpu_get_psr(VCPU *vcpu);
extern IA64FAULT vmx_vcpu_get_bgr(VCPU *vcpu, unsigned int reg, UINT64 *val);
extern IA64FAULT vmx_vcpu_set_bgr(VCPU *vcpu, unsigned int reg, u64 val,int nat);
extern IA64FAULT vmx_vcpu_get_gr(VCPU *vcpu, unsigned reg, UINT64 * val);
extern IA64FAULT vmx_vcpu_set_gr(VCPU *vcpu, unsigned reg, u64 value, int nat);
extern IA64FAULT vmx_vcpu_reset_psr_sm(VCPU *vcpu, UINT64 imm24);
extern IA64FAULT vmx_vcpu_set_psr_sm(VCPU *vcpu, UINT64 imm24);
extern IA64FAULT vmx_vcpu_set_psr_l(VCPU *vcpu, UINT64 val);
extern void vtm_init(VCPU *vcpu);
extern uint64_t vtm_get_itc(VCPU *vcpu);
extern void vtm_set_itc(VCPU *vcpu, uint64_t new_itc);
extern void vtm_set_itv(VCPU *vcpu);
extern void vtm_interruption_update(VCPU *vcpu, vtime_t* vtm);
extern void vtm_domain_out(VCPU *vcpu);
extern void vtm_domain_in(VCPU *vcpu);
extern void vlsapic_reset(VCPU *vcpu);
extern int vmx_check_pending_irq(VCPU *vcpu);
extern void guest_write_eoi(VCPU *vcpu);
extern uint64_t guest_read_vivr(VCPU *vcpu);
extern void vmx_inject_vhpi(VCPU *vcpu, u8 vec);
extern void vmx_vcpu_pend_interrupt(VCPU *vcpu, UINT64 vector);
extern struct virutal_platform_def *vmx_vcpu_get_plat(VCPU *vcpu);
extern void memread_p(VCPU *vcpu, void *src, void *dest, size_t s);
extern void memread_v(VCPU *vcpu, thash_data_t *vtlb, void *src, void *dest, size_t s);
extern void memwrite_v(VCPU *vcpu, thash_data_t *vtlb, void *src, void *dest, size_t s);
extern void memwrite_p(VCPU *vcpu, void *src, void *dest, size_t s);


/**************************************************************************
 VCPU control register access routines
**************************************************************************/

static inline
IA64FAULT vmx_vcpu_get_dcr(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,dcr);
    return (IA64_NO_FAULT);
}

static inline
IA64FAULT vmx_vcpu_get_itm(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,itm);
    return (IA64_NO_FAULT);
}

static inline
IA64FAULT vmx_vcpu_get_iva(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,iva);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_pta(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,pta);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_ipsr(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,ipsr);
    return (IA64_NO_FAULT);
}

static inline
IA64FAULT vmx_vcpu_get_isr(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,isr);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_iip(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,iip);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_ifa(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,ifa);
    return (IA64_NO_FAULT);
}

static inline
IA64FAULT vmx_vcpu_get_itir(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,itir);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_iipa(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,iipa);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_ifs(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,ifs);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_iim(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,iim);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_iha(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,iha);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_lid(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,lid);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_ivr(VCPU *vcpu, UINT64 *pval)
{
    *pval = guest_read_vivr(vcpu);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_tpr(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,tpr);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_eoi(VCPU *vcpu, UINT64 *pval)
{
    *pval = 0L;  // reads of eoi always return 0
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_irr0(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,irr[0]);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_irr1(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,irr[1]);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_irr2(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,irr[2]);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_irr3(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,irr[3]);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_itv(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,itv);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_pmv(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,pmv);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_cmcv(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,cmcv);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_lrr0(VCPU *vcpu, UINT64 *pval)
{
    *pval = VPD_CR(vcpu,lrr0);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_lrr1(VCPU *vcpu, UINT64 *pval)
{    *pval = VPD_CR(vcpu,lrr1);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT
vmx_vcpu_set_dcr(VCPU *vcpu, u64 val)
{
    u64 mdcr, mask;
    VPD_CR(vcpu,dcr)=val;
    /* All vDCR bits will go to mDCR, except for be/pp bit */
    mdcr = ia64_get_dcr();
    mask = IA64_DCR_BE | IA64_DCR_PP;
    mdcr = ( mdcr & mask ) | ( val & (~mask) );
    ia64_set_dcr( mdcr);

    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_itm(VCPU *vcpu, u64 val)
{
    vtime_t     *vtm;
    
    vtm=&(vcpu->arch.arch_vmx.vtm);
    VPD_CR(vcpu,itm)=val;
    vtm_interruption_update(vcpu, vtm);
    return IA64_NO_FAULT;
}
static inline
IA64FAULT
vmx_vcpu_set_iva(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,iva)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_pta(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,pta)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_ipsr(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,ipsr)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_isr(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,isr)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_iip(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,iip)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_ifa(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,ifa)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_itir(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,itir)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_iipa(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,iipa)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_ifs(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,ifs)=val;
    return IA64_NO_FAULT;
}
static inline
IA64FAULT
vmx_vcpu_set_iim(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,iim)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_iha(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,iha)=val;
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_lid(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,lid)=val;
    return IA64_NO_FAULT;
}
static inline
IA64FAULT
vmx_vcpu_set_tpr(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,tpr)=val;
    //TODO
    return IA64_NO_FAULT;
}
static inline
IA64FAULT
vmx_vcpu_set_eoi(VCPU *vcpu, u64 val)
{
    guest_write_eoi(vcpu);
    return IA64_NO_FAULT;
}

static inline
IA64FAULT
vmx_vcpu_set_itv(VCPU *vcpu, u64 val)
{

    VPD_CR(vcpu,itv)=val;
    vtm_set_itv(vcpu);
    return IA64_NO_FAULT;
}
static inline
IA64FAULT
vmx_vcpu_set_pmv(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,pmv)=val;
    return IA64_NO_FAULT;
}
static inline
IA64FAULT
vmx_vcpu_set_cmcv(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,cmcv)=val;
    return IA64_NO_FAULT;
}
static inline
IA64FAULT
vmx_vcpu_set_lrr0(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,lrr0)=val;
    return IA64_NO_FAULT;
}
static inline
IA64FAULT
vmx_vcpu_set_lrr1(VCPU *vcpu, u64 val)
{
    VPD_CR(vcpu,lrr1)=val;
    return IA64_NO_FAULT;
}




/**************************************************************************
 VCPU privileged application register access routines
**************************************************************************/
static inline
IA64FAULT vmx_vcpu_set_itc(VCPU *vcpu, UINT64 val)
{
    vtm_set_itc(vcpu, val);
    return  IA64_NO_FAULT;
}
static inline
IA64FAULT vmx_vcpu_get_itc(VCPU *vcpu,UINT64 *val)
{
    *val = vtm_get_itc(vcpu);
    return  IA64_NO_FAULT;
}
static inline
IA64FAULT vmx_vcpu_get_rr(VCPU *vcpu, UINT64 reg, UINT64 *pval)
{
    *pval = VMX(vcpu,vrr[reg>>61]);
    return (IA64_NO_FAULT);
}
/**************************************************************************
 VCPU debug breakpoint register access routines
**************************************************************************/

static inline
IA64FAULT vmx_vcpu_get_cpuid(VCPU *vcpu, UINT64 reg, UINT64 *pval)
{
    // TODO: unimplemented DBRs return a reserved register fault
    // TODO: Should set Logical CPU state, not just physical
    if(reg > 4){
        panic("there are only five cpuid registers");
    }
    *pval=VMX_VPD(vcpu,vcpuid[reg]);
    return (IA64_NO_FAULT);
}


static inline
IA64FAULT vmx_vcpu_set_dbr(VCPU *vcpu, UINT64 reg, UINT64 val)
{
    // TODO: unimplemented DBRs return a reserved register fault
    // TODO: Should set Logical CPU state, not just physical
    ia64_set_dbr(reg,val);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_set_ibr(VCPU *vcpu, UINT64 reg, UINT64 val)
{
    // TODO: unimplemented IBRs return a reserved register fault
    // TODO: Should set Logical CPU state, not just physical
    ia64_set_ibr(reg,val);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_dbr(VCPU *vcpu, UINT64 reg, UINT64 *pval)
{
    // TODO: unimplemented DBRs return a reserved register fault
    UINT64 val = ia64_get_dbr(reg);
    *pval = val;
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_ibr(VCPU *vcpu, UINT64 reg, UINT64 *pval)
{
    // TODO: unimplemented IBRs return a reserved register fault
    UINT64 val = ia64_get_ibr(reg);
    *pval = val;
    return (IA64_NO_FAULT);
}

/**************************************************************************
 VCPU performance monitor register access routines
**************************************************************************/
static inline
IA64FAULT vmx_vcpu_set_pmc(VCPU *vcpu, UINT64 reg, UINT64 val)
{
    // TODO: Should set Logical CPU state, not just physical
    // NOTE: Writes to unimplemented PMC registers are discarded
    ia64_set_pmc(reg,val);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_set_pmd(VCPU *vcpu, UINT64 reg, UINT64 val)
{
    // TODO: Should set Logical CPU state, not just physical
    // NOTE: Writes to unimplemented PMD registers are discarded
    ia64_set_pmd(reg,val);
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_pmc(VCPU *vcpu, UINT64 reg, UINT64 *pval)
{
    // NOTE: Reads from unimplemented PMC registers return zero
    UINT64 val = (UINT64)ia64_get_pmc(reg);
    *pval = val;
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_get_pmd(VCPU *vcpu, UINT64 reg, UINT64 *pval)
{
    // NOTE: Reads from unimplemented PMD registers return zero
    UINT64 val = (UINT64)ia64_get_pmd(reg);
    *pval = val;
    return (IA64_NO_FAULT);
}

/**************************************************************************
 VCPU banked general register access routines
**************************************************************************/
static inline
IA64FAULT vmx_vcpu_bsw0(VCPU *vcpu)
{

    VMX_VPD(vcpu,vpsr) &= ~IA64_PSR_BN;
    return (IA64_NO_FAULT);
}
static inline
IA64FAULT vmx_vcpu_bsw1(VCPU *vcpu)
{

    VMX_VPD(vcpu,vpsr) |= IA64_PSR_BN;
    return (IA64_NO_FAULT);
}

#define redistribute_rid(rid)	(((rid) & ~0xffff) | (((rid) << 8) & 0xff00) | (((rid) >> 8) & 0xff))
static inline unsigned long
vmx_vrrtomrr(VCPU *vcpu,unsigned long val)
{
    ia64_rr rr;
    u64	  rid;
    rr.rrval=val;
    rid=(((u64)vcpu->domain->id)<<DOMAIN_RID_SHIFT) + rr.rid;
    rr.rid = redistribute_rid(rid);
    rr.ve=1;
    return rr.rrval;
}
#endif
