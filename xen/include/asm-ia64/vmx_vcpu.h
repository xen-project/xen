/* -*-  Mode:C; c-basic-offset:8; tab-width:8; indent-tabs-mode:nil -*- */
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

#define VRN_SHIFT	61
#define VRN0		0x0UL
#define VRN1		0x1UL
#define VRN2		0x2UL
#define VRN3		0x3UL
#define VRN4		0x4UL
#define VRN5		0x5UL
#define VRN6		0x6UL
#define VRN7		0x7UL
// for vlsapic
#define VLSAPIC_INSVC(vcpu, i) ((vcpu)->arch.insvc[i])

#define VMX(x,y)  ((x)->arch.arch_vmx.y)

#define VMM_RR_SHIFT	20
#define VMM_RR_MASK	((1UL<<VMM_RR_SHIFT)-1)

extern u64 indirect_reg_igfld_MASK(int type, int index, u64 value);
extern u64 cr_igfld_mask(int index, u64 value);
extern int check_indirect_reg_rsv_fields(int type, int index, u64 value);
extern u64 set_isr_ei_ni(VCPU * vcpu);
extern u64 set_isr_for_na_inst(VCPU * vcpu, int op);

/* next all for VTI domain APIs definition */
extern void vmx_vcpu_set_psr(VCPU * vcpu, unsigned long value);
extern u64 vmx_vcpu_sync_mpsr(u64 mipsr, u64 value);
extern void vmx_vcpu_set_psr_sync_mpsr(VCPU * vcpu, u64 value);
extern IA64FAULT vmx_vcpu_cover(VCPU * vcpu);
extern IA64FAULT vmx_vcpu_set_rr(VCPU * vcpu, u64 reg, u64 val);
extern IA64FAULT vmx_vcpu_get_pkr(VCPU * vcpu, u64 reg, u64 * pval);
IA64FAULT vmx_vcpu_set_pkr(VCPU * vcpu, u64 reg, u64 val);
extern IA64FAULT vmx_vcpu_itc_i(VCPU * vcpu, u64 pte, u64 itir, u64 ifa);
extern IA64FAULT vmx_vcpu_itc_d(VCPU * vcpu, u64 pte, u64 itir, u64 ifa);
extern IA64FAULT vmx_vcpu_itr_i(VCPU * vcpu, u64 slot, u64 pte, u64 itir,
                                u64 ifa);
extern IA64FAULT vmx_vcpu_itr_d(VCPU * vcpu, u64 slot, u64 pte, u64 itir,
                                u64 ifa);
extern IA64FAULT vmx_vcpu_ptr_d(VCPU * vcpu, u64 vadr, u64 ps);
extern IA64FAULT vmx_vcpu_ptr_i(VCPU * vcpu, u64 vadr, u64 ps);
extern IA64FAULT vmx_vcpu_ptc_l(VCPU * vcpu, u64 vadr, u64 ps);
extern IA64FAULT vmx_vcpu_ptc_e(VCPU * vcpu, u64 vadr);
extern IA64FAULT vmx_vcpu_ptc_g(VCPU * vcpu, u64 vadr, u64 ps);
extern IA64FAULT vmx_vcpu_ptc_ga(VCPU * vcpu, u64 vadr, u64 ps);
extern IA64FAULT vmx_vcpu_thash(VCPU * vcpu, u64 vadr, u64 * pval);
extern u64 vmx_vcpu_get_itir_on_fault(VCPU * vcpu, u64 ifa);
extern IA64FAULT vmx_vcpu_ttag(VCPU * vcpu, u64 vadr, u64 * pval);
extern IA64FAULT vmx_vcpu_tpa(VCPU * vcpu, u64 vadr, u64 * padr);
extern IA64FAULT vmx_vcpu_tak(VCPU * vcpu, u64 vadr, u64 * key);
extern IA64FAULT vmx_vcpu_rfi(VCPU * vcpu);
extern u64 vmx_vcpu_get_psr(VCPU * vcpu);
extern IA64FAULT vmx_vcpu_get_bgr(VCPU * vcpu, unsigned int reg, u64 * val);
extern IA64FAULT vmx_vcpu_set_bgr(VCPU * vcpu, unsigned int reg, u64 val,
                                  int nat);
#if 0
extern IA64FAULT vmx_vcpu_get_gr(VCPU * vcpu, unsigned reg, u64 * val);
extern IA64FAULT vmx_vcpu_set_gr(VCPU * vcpu, unsigned reg, u64 value, int nat);
#endif
extern IA64FAULT vmx_vcpu_reset_psr_sm(VCPU * vcpu, u64 imm24);
extern IA64FAULT vmx_vcpu_set_psr_sm(VCPU * vcpu, u64 imm24);
extern IA64FAULT vmx_vcpu_set_psr_l(VCPU * vcpu, u64 val);
extern void vtm_init(VCPU * vcpu);
extern uint64_t vtm_get_itc(VCPU * vcpu);
extern void vtm_set_itc(VCPU * vcpu, uint64_t new_itc);
extern void vtm_set_itv(VCPU * vcpu, uint64_t val);
extern void vtm_set_itm(VCPU * vcpu, uint64_t val);
extern void vtm_interruption_update(VCPU * vcpu, vtime_t * vtm);
//extern void vtm_domain_out(VCPU *vcpu);
//extern void vtm_domain_in(VCPU *vcpu);
extern void vlsapic_reset(VCPU * vcpu);
extern int vmx_check_pending_irq(VCPU * vcpu);
extern void guest_write_eoi(VCPU * vcpu);
extern int is_unmasked_irq(VCPU * vcpu);
extern uint64_t guest_read_vivr(VCPU * vcpu);
extern void vmx_inject_vhpi(VCPU * vcpu, u8 vec);
extern int vmx_vcpu_pend_interrupt(VCPU * vcpu, uint8_t vector);
extern struct virtual_platform_def *vmx_vcpu_get_plat(VCPU * vcpu);
extern void memread_p(VCPU * vcpu, u64 * src, u64 * dest, size_t s);
extern void memread_v(VCPU * vcpu, thash_data_t * vtlb, u64 * src, u64 * dest,
                      size_t s);
extern void memwrite_v(VCPU * vcpu, thash_data_t * vtlb, u64 * src, u64 * dest,
                       size_t s);
extern void memwrite_p(VCPU * vcpu, u64 * src, u64 * dest, size_t s);
extern void vcpu_load_kernel_regs(VCPU * vcpu);
extern void vmx_switch_rr7(unsigned long, shared_info_t *, void *, void *,
                           void *);

extern void dtlb_fault(VCPU * vcpu, u64 vadr);
extern void nested_dtlb(VCPU * vcpu);
extern void alt_dtlb(VCPU * vcpu, u64 vadr);
extern void dvhpt_fault(VCPU * vcpu, u64 vadr);
extern void dnat_page_consumption(VCPU * vcpu, uint64_t vadr);
extern void data_page_not_present(VCPU * vcpu, u64 vadr);
extern void inst_page_not_present(VCPU * vcpu, u64 vadr);
extern void data_access_rights(VCPU * vcpu, u64 vadr);
extern void vmx_ia64_set_dcr(VCPU * v);

/**************************************************************************
 VCPU control register access routines
**************************************************************************/

static inline IA64FAULT vmx_vcpu_get_itm(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, itm);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_iva(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, iva);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_pta(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, pta);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_lid(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, lid);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_ivr(VCPU * vcpu, u64 * pval)
{
	*pval = guest_read_vivr(vcpu);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_tpr(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, tpr);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_eoi(VCPU * vcpu, u64 * pval)
{
	*pval = 0L;		// reads of eoi always return 0
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_irr0(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, irr[0]);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_irr1(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, irr[1]);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_irr2(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, irr[2]);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_irr3(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, irr[3]);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_itv(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, itv);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_pmv(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, pmv);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_cmcv(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, cmcv);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_lrr0(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, lrr0);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_lrr1(VCPU * vcpu, u64 * pval)
{
	*pval = VCPU(vcpu, lrr1);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_itm(VCPU * vcpu, u64 val)
{
	vtm_set_itm(vcpu, val);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_iva(VCPU * vcpu, u64 val)
{
	VCPU(vcpu, iva) = val;
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_pta(VCPU * vcpu, u64 val)
{
	VCPU(vcpu, pta) = val;
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_lid(VCPU * vcpu, u64 val)
{
	VCPU(vcpu, lid) = val;
	return IA64_NO_FAULT;
}
extern IA64FAULT vmx_vcpu_set_tpr(VCPU * vcpu, u64 val);

static inline IA64FAULT vmx_vcpu_set_eoi(VCPU * vcpu, u64 val)
{
	guest_write_eoi(vcpu);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_itv(VCPU * vcpu, u64 val)
{

	vtm_set_itv(vcpu, val);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_pmv(VCPU * vcpu, u64 val)
{
	VCPU(vcpu, pmv) = val;
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_cmcv(VCPU * vcpu, u64 val)
{
	VCPU(vcpu, cmcv) = val;
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_lrr0(VCPU * vcpu, u64 val)
{
	VCPU(vcpu, lrr0) = val;
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_lrr1(VCPU * vcpu, u64 val)
{
	VCPU(vcpu, lrr1) = val;
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU privileged application register access routines
**************************************************************************/
static inline IA64FAULT vmx_vcpu_set_itc(VCPU * vcpu, u64 val)
{
	vtm_set_itc(vcpu, val);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_itc(VCPU * vcpu, u64 * val)
{
	*val = vtm_get_itc(vcpu);
	return IA64_NO_FAULT;
}

/*
static inline
IA64FAULT vmx_vcpu_get_rr(VCPU *vcpu, u64 reg, u64 *pval)
{
    *pval = VMX(vcpu,vrr[reg>>61]);
    return IA64_NO_FAULT;
}
 */
/**************************************************************************
 VCPU debug breakpoint register access routines
**************************************************************************/

static inline IA64FAULT vmx_vcpu_get_cpuid(VCPU * vcpu, u64 reg, u64 * pval)
{
	// TODO: unimplemented DBRs return a reserved register fault
	// TODO: Should set Logical CPU state, not just physical
	if (reg > 4) {
		panic_domain(vcpu_regs(vcpu),
			     "there are only five cpuid registers");
	}
	*pval = VCPU(vcpu, vcpuid[reg]);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_dbr(VCPU * vcpu, u64 reg, u64 val)
{
	// TODO: unimplemented DBRs return a reserved register fault
	// TODO: Should set Logical CPU state, not just physical
	ia64_set_dbr(reg, val);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_ibr(VCPU * vcpu, u64 reg, u64 val)
{
	// TODO: unimplemented IBRs return a reserved register fault
	// TODO: Should set Logical CPU state, not just physical
	ia64_set_ibr(reg, val);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_dbr(VCPU * vcpu, u64 reg, u64 * pval)
{
	// TODO: unimplemented DBRs return a reserved register fault
	u64 val = ia64_get_dbr(reg);
	*pval = val;
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_ibr(VCPU * vcpu, u64 reg, u64 * pval)
{
	// TODO: unimplemented IBRs return a reserved register fault
	u64 val = ia64_get_ibr(reg);
	*pval = val;
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU performance monitor register access routines
**************************************************************************/
static inline IA64FAULT vmx_vcpu_set_pmc(VCPU * vcpu, u64 reg, u64 val)
{
	// TODO: Should set Logical CPU state, not just physical
	// NOTE: Writes to unimplemented PMC registers are discarded
	ia64_set_pmc(reg, val);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_set_pmd(VCPU * vcpu, u64 reg, u64 val)
{
	// TODO: Should set Logical CPU state, not just physical
	// NOTE: Writes to unimplemented PMD registers are discarded
	ia64_set_pmd(reg, val);
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_pmc(VCPU * vcpu, u64 reg, u64 * pval)
{
	// NOTE: Reads from unimplemented PMC registers return zero
	u64 val = (u64) ia64_get_pmc(reg);
	*pval = val;
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_get_pmd(VCPU * vcpu, u64 reg, u64 * pval)
{
	// NOTE: Reads from unimplemented PMD registers return zero
	u64 val = (u64) ia64_get_pmd(reg);
	*pval = val;
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU banked general register access routines
**************************************************************************/
#if 0
static inline IA64FAULT vmx_vcpu_bsw0(VCPU * vcpu)
{

	VCPU(vcpu, vpsr) &= ~IA64_PSR_BN;
	return IA64_NO_FAULT;
}

static inline IA64FAULT vmx_vcpu_bsw1(VCPU * vcpu)
{

	VCPU(vcpu, vpsr) |= IA64_PSR_BN;
	return IA64_NO_FAULT;
}
#endif
#if 0
/* Another hash performance algorithm */
#define redistribute_rid(rid)	(((rid) & ~0xffff) | (((rid) << 8) & 0xff00) | (((rid) >> 8) & 0xff))
#endif
static inline unsigned long vrrtomrr(VCPU * v, unsigned long val)
{
	ia64_rr rr;

	rr.rrval = val;
	rr.rid = rr.rid + v->arch.starting_rid;
	if (rr.ps > PAGE_SHIFT)
		rr.ps = PAGE_SHIFT;
	rr.ve = 1;
	return vmMangleRID(rr.rrval);
/* Disable this rid allocation algorithm for now */
#if 0
	rid = (((u64) vcpu->domain->domain_id) << DOMAIN_RID_SHIFT) + rr.rid;
	rr.rid = redistribute_rid(rid);
#endif

}
static inline thash_cb_t *vmx_vcpu_get_vtlb(VCPU * vcpu)
{
	return &vcpu->arch.vtlb;
}

static inline thash_cb_t *vcpu_get_vhpt(VCPU * vcpu)
{
	return &vcpu->arch.vhpt;
}

#endif
