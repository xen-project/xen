/*
 * Virtualized CPU functions
 *
 * Copyright (C) 2004-2005 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <linux/sched.h>
#include <public/xen.h>
#include <xen/mm.h>
#include <asm/ia64_int.h>
#include <asm/vcpu.h>
#include <asm/regionreg.h>
#include <asm/tlb.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/vmx_vcpu.h>
#include <asm/vhpt.h>
#include <asm/tlbflush.h>
#include <asm/privop.h>
#include <xen/event.h>
#include <asm/vmx_phy_mode.h>
#include <asm/bundle.h>
#include <asm/privop_stat.h>
#include <asm/uaccess.h>
#include <asm/p2m_entry.h>
#include <asm/tlb_track.h>

/* FIXME: where these declarations should be there ? */
extern void getreg(unsigned long regnum, unsigned long *val, int *nat,
                   struct pt_regs *regs);
extern void setreg(unsigned long regnum, unsigned long val, int nat,
                   struct pt_regs *regs);
extern void getfpreg(unsigned long regnum, struct ia64_fpreg *fpval,
                     struct pt_regs *regs);

extern void setfpreg(unsigned long regnum, struct ia64_fpreg *fpval,
                     struct pt_regs *regs);

typedef union {
	struct ia64_psr ia64_psr;
	unsigned long i64;
} PSR;

// this def for vcpu_regs won't work if kernel stack is present
//#define       vcpu_regs(vcpu) ((struct pt_regs *) vcpu->arch.regs

#define	IA64_PTA_SZ_BIT		2
#define	IA64_PTA_VF_BIT		8
#define	IA64_PTA_BASE_BIT	15
#define	IA64_PTA_LFMT		(1UL << IA64_PTA_VF_BIT)
#define	IA64_PTA_SZ(x)		(x##UL << IA64_PTA_SZ_BIT)

unsigned long vcpu_verbose = 0;

/**************************************************************************
 VCPU general register access routines
**************************************************************************/
#ifdef XEN
u64 vcpu_get_gr(VCPU * vcpu, unsigned long reg)
{
	REGS *regs = vcpu_regs(vcpu);
	u64 val;

	if (!reg)
		return 0;
	getreg(reg, &val, 0, regs);	// FIXME: handle NATs later
	return val;
}

IA64FAULT vcpu_get_gr_nat(VCPU * vcpu, unsigned long reg, u64 * val)
{
	REGS *regs = vcpu_regs(vcpu);
	int nat;

	getreg(reg, val, &nat, regs);	// FIXME: handle NATs later
	if (nat)
		return IA64_NAT_CONSUMPTION_VECTOR;
	return 0;
}

// returns:
//   IA64_ILLOP_FAULT if the register would cause an Illegal Operation fault
//   IA64_NO_FAULT otherwise
IA64FAULT vcpu_set_gr(VCPU * vcpu, unsigned long reg, u64 value, int nat)
{
	REGS *regs = vcpu_regs(vcpu);
	long sof = (regs->cr_ifs) & 0x7f;

	if (!reg)
		return IA64_ILLOP_FAULT;
	if (reg >= sof + 32)
		return IA64_ILLOP_FAULT;
	setreg(reg, value, nat, regs);	// FIXME: handle NATs later
	return IA64_NO_FAULT;
}

IA64FAULT
vcpu_get_fpreg(VCPU * vcpu, unsigned long reg, struct ia64_fpreg * val)
{
	REGS *regs = vcpu_regs(vcpu);
	getfpreg(reg, val, regs);	// FIXME: handle NATs later
	return IA64_NO_FAULT;
}

IA64FAULT
vcpu_set_fpreg(VCPU * vcpu, unsigned long reg, struct ia64_fpreg * val)
{
	REGS *regs = vcpu_regs(vcpu);
	if (reg > 1)
		setfpreg(reg, val, regs);	// FIXME: handle NATs later
	return IA64_NO_FAULT;
}

#else
// returns:
//   IA64_ILLOP_FAULT if the register would cause an Illegal Operation fault
//   IA64_NO_FAULT otherwise
IA64FAULT vcpu_set_gr(VCPU * vcpu, unsigned long reg, u64 value)
{
	REGS *regs = vcpu_regs(vcpu);
	long sof = (regs->cr_ifs) & 0x7f;

	if (!reg)
		return IA64_ILLOP_FAULT;
	if (reg >= sof + 32)
		return IA64_ILLOP_FAULT;
	setreg(reg, value, 0, regs);	// FIXME: handle NATs later
	return IA64_NO_FAULT;
}

#endif

void vcpu_init_regs(struct vcpu *v)
{
	struct pt_regs *regs;

	regs = vcpu_regs(v);
	if (VMX_DOMAIN(v)) {
		/* dt/rt/it:1;i/ic:1, si:1, vm/bn:1, ac:1 */
		/* Need to be expanded as macro */
		regs->cr_ipsr = 0x501008826008;
		/* lazy fp */
		FP_PSR(v) = IA64_PSR_DFH;
		regs->cr_ipsr |= IA64_PSR_DFH;
	} else {
		regs->cr_ipsr = ia64_getreg(_IA64_REG_PSR)
		    | IA64_PSR_BITS_TO_SET | IA64_PSR_BN;
		regs->cr_ipsr &= ~(IA64_PSR_BITS_TO_CLEAR
				   | IA64_PSR_RI | IA64_PSR_IS);
		// domain runs at PL2
		regs->cr_ipsr |= 2UL << IA64_PSR_CPL0_BIT;
		// lazy fp 
		PSCB(v, hpsr_dfh) = 1;
		PSCB(v, hpsr_mfh) = 0;
		regs->cr_ipsr |= IA64_PSR_DFH;
	}
	regs->cr_ifs = 1UL << 63;	/* or clear? */
	regs->ar_fpsr = FPSR_DEFAULT;

	if (VMX_DOMAIN(v)) {
		vmx_init_all_rr(v);
		/* Virtual processor context setup */
		VCPU(v, vpsr) = IA64_PSR_BN;
		VCPU(v, dcr) = 0;
	} else {
		init_all_rr(v);
		regs->ar_rsc |= (2 << 2);	/* force PL2/3 */
		VCPU(v, banknum) = 1;
		VCPU(v, metaphysical_mode) = 1;
		VCPU(v, interrupt_mask_addr) =
		    (unsigned char *)v->domain->arch.shared_info_va +
		    INT_ENABLE_OFFSET(v);
		VCPU(v, itv) = (1 << 16);	/* timer vector masked */
	}

	v->arch.domain_itm_last = -1L;
}

/**************************************************************************
 VCPU privileged application register access routines
**************************************************************************/

void vcpu_load_kernel_regs(VCPU * vcpu)
{
	ia64_set_kr(0, VCPU(vcpu, krs[0]));
	ia64_set_kr(1, VCPU(vcpu, krs[1]));
	ia64_set_kr(2, VCPU(vcpu, krs[2]));
	ia64_set_kr(3, VCPU(vcpu, krs[3]));
	ia64_set_kr(4, VCPU(vcpu, krs[4]));
	ia64_set_kr(5, VCPU(vcpu, krs[5]));
	ia64_set_kr(6, VCPU(vcpu, krs[6]));
	ia64_set_kr(7, VCPU(vcpu, krs[7]));
}

/* GCC 4.0.2 seems not to be able to suppress this call!.  */
#define ia64_setreg_unknown_kr() return IA64_ILLOP_FAULT

IA64FAULT vcpu_set_ar(VCPU * vcpu, u64 reg, u64 val)
{
	if (reg == 44)
		return vcpu_set_itc(vcpu, val);
	else if (reg == 27)
		return IA64_ILLOP_FAULT;
	else if (reg == 24)
		printk("warning: setting ar.eflg is a no-op; no IA-32 "
		       "support\n");
	else if (reg > 7)
		return IA64_ILLOP_FAULT;
	else {
		PSCB(vcpu, krs[reg]) = val;
		ia64_set_kr(reg, val);
	}
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_ar(VCPU * vcpu, u64 reg, u64 * val)
{
	if (reg == 24)
		printk("warning: getting ar.eflg is a no-op; no IA-32 "
		       "support\n");
	else if (reg > 7)
		return IA64_ILLOP_FAULT;
	else
		*val = PSCB(vcpu, krs[reg]);
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU processor status register access routines
**************************************************************************/

void vcpu_set_metaphysical_mode(VCPU * vcpu, BOOLEAN newmode)
{
	/* only do something if mode changes */
	if (!!newmode ^ !!PSCB(vcpu, metaphysical_mode)) {
		PSCB(vcpu, metaphysical_mode) = newmode;
		if (newmode)
			set_metaphysical_rr0();
		else if (PSCB(vcpu, rrs[0]) != -1)
			set_one_rr(0, PSCB(vcpu, rrs[0]));
	}
}

IA64FAULT vcpu_reset_psr_dt(VCPU * vcpu)
{
	vcpu_set_metaphysical_mode(vcpu, TRUE);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_reset_psr_sm(VCPU * vcpu, u64 imm24)
{
	struct ia64_psr psr, imm, *ipsr;
	REGS *regs = vcpu_regs(vcpu);

	//PRIVOP_COUNT_ADDR(regs,_RSM);
	// TODO: All of these bits need to be virtualized
	// TODO: Only allowed for current vcpu
	__asm__ __volatile("mov %0=psr;;":"=r"(psr)::"memory");
	ipsr = (struct ia64_psr *)&regs->cr_ipsr;
	imm = *(struct ia64_psr *)&imm24;
	// interrupt flag
	if (imm.i)
		vcpu->vcpu_info->evtchn_upcall_mask = 1;
	if (imm.ic)
		PSCB(vcpu, interrupt_collection_enabled) = 0;
	// interrupt collection flag
	//if (imm.ic) PSCB(vcpu,interrupt_delivery_enabled) = 0;
	// just handle psr.up and psr.pp for now
	if (imm24 & ~(IA64_PSR_BE | IA64_PSR_PP | IA64_PSR_UP | IA64_PSR_SP |
		      IA64_PSR_I | IA64_PSR_IC | IA64_PSR_DT |
		      IA64_PSR_DFL | IA64_PSR_DFH))
		return IA64_ILLOP_FAULT;
	if (imm.dfh) {
		ipsr->dfh = PSCB(vcpu, hpsr_dfh);
		PSCB(vcpu, vpsr_dfh) = 0;
	}
	if (imm.dfl)
		ipsr->dfl = 0;
	if (imm.pp) {
		ipsr->pp = 1;
		psr.pp = 1;	// priv perf ctrs always enabled
		PSCB(vcpu, vpsr_pp) = 0; // but fool the domain if it gets psr
	}
	if (imm.up) {
		ipsr->up = 0;
		psr.up = 0;
	}
	if (imm.sp) {
		ipsr->sp = 0;
		psr.sp = 0;
	}
	if (imm.be)
		ipsr->be = 0;
	if (imm.dt)
		vcpu_set_metaphysical_mode(vcpu, TRUE);
	__asm__ __volatile(";; mov psr.l=%0;; srlz.d"::"r"(psr):"memory");
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_psr_dt(VCPU * vcpu)
{
	vcpu_set_metaphysical_mode(vcpu, FALSE);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_psr_i(VCPU * vcpu)
{
	vcpu->vcpu_info->evtchn_upcall_mask = 0;
	PSCB(vcpu, interrupt_collection_enabled) = 1;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_psr_sm(VCPU * vcpu, u64 imm24)
{
	struct ia64_psr psr, imm, *ipsr;
	REGS *regs = vcpu_regs(vcpu);
	u64 mask, enabling_interrupts = 0;

	//PRIVOP_COUNT_ADDR(regs,_SSM);
	// TODO: All of these bits need to be virtualized
	__asm__ __volatile("mov %0=psr;;":"=r"(psr)::"memory");
	imm = *(struct ia64_psr *)&imm24;
	ipsr = (struct ia64_psr *)&regs->cr_ipsr;
	// just handle psr.sp,pp and psr.i,ic (and user mask) for now
	mask =
	    IA64_PSR_PP | IA64_PSR_SP | IA64_PSR_I | IA64_PSR_IC | IA64_PSR_UM |
	    IA64_PSR_DT | IA64_PSR_DFL | IA64_PSR_DFH | IA64_PSR_BE;
	if (imm24 & ~mask)
		return IA64_ILLOP_FAULT;
	if (imm.dfh) {
		PSCB(vcpu, vpsr_dfh) = 1;
		ipsr->dfh = 1;
	} 
	if (imm.dfl)
		ipsr->dfl = 1;
	if (imm.pp) {
		ipsr->pp = 1;
		psr.pp = 1;
		PSCB(vcpu, vpsr_pp) = 1;
	}
	if (imm.sp) {
		ipsr->sp = 1;
		psr.sp = 1;
	}
	if (imm.i) {
		if (vcpu->vcpu_info->evtchn_upcall_mask) {
//printk("vcpu_set_psr_sm: psr.ic 0->1\n");
			enabling_interrupts = 1;
		}
		vcpu->vcpu_info->evtchn_upcall_mask = 0;
	}
	if (imm.ic)
		PSCB(vcpu, interrupt_collection_enabled) = 1;
	// TODO: do this faster
	if (imm.mfl) {
		ipsr->mfl = 1;
		psr.mfl = 1;
	}
	if (imm.mfh) {
		ipsr->mfh = 1;
		psr.mfh = 1;
	}
	if (imm.ac) {
		ipsr->ac = 1;
		psr.ac = 1;
	}
	if (imm.up) {
		ipsr->up = 1;
		psr.up = 1;
	}
	if (imm.be)
		ipsr->be = 1;
	if (imm.dt)
		vcpu_set_metaphysical_mode(vcpu, FALSE);
	__asm__ __volatile(";; mov psr.l=%0;; srlz.d"::"r"(psr):"memory");
	if (enabling_interrupts &&
	    vcpu_check_pending_interrupts(vcpu) != SPURIOUS_VECTOR)
		PSCB(vcpu, pending_interruption) = 1;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_psr_l(VCPU * vcpu, u64 val)
{
	struct ia64_psr newpsr, *ipsr;
	REGS *regs = vcpu_regs(vcpu);
	u64 enabling_interrupts = 0;

	newpsr = *(struct ia64_psr *)&val;
	ipsr = (struct ia64_psr *)&regs->cr_ipsr;
	// just handle psr.up and psr.pp for now
	//if (val & ~(IA64_PSR_PP | IA64_PSR_UP | IA64_PSR_SP))
	//	return IA64_ILLOP_FAULT;
	// however trying to set other bits can't be an error as it is in ssm
	if (newpsr.dfh) {
		ipsr->dfh = 1;
		PSCB(vcpu, vpsr_dfh) = 1;
	} else {
		ipsr->dfh = PSCB(vcpu, hpsr_dfh);
		PSCB(vcpu, vpsr_dfh) = 0;
	}       
	if (newpsr.dfl)
		ipsr->dfl = 1;
	if (newpsr.pp) {
		ipsr->pp = 1;
		PSCB(vcpu, vpsr_pp) = 1;
	} else {
		ipsr->pp = 1;
		PSCB(vcpu, vpsr_pp) = 0;
	}
	if (newpsr.up)
		ipsr->up = 1;
	if (newpsr.sp)
		ipsr->sp = 1;
	if (newpsr.i) {
		if (vcpu->vcpu_info->evtchn_upcall_mask)
			enabling_interrupts = 1;
		vcpu->vcpu_info->evtchn_upcall_mask = 0;
	}
	if (newpsr.ic)
		PSCB(vcpu, interrupt_collection_enabled) = 1;
	if (newpsr.mfl)
		ipsr->mfl = 1;
	if (newpsr.mfh)
		ipsr->mfh = 1;
	if (newpsr.ac)
		ipsr->ac = 1;
	if (newpsr.up)
		ipsr->up = 1;
	if (newpsr.dt && newpsr.rt)
		vcpu_set_metaphysical_mode(vcpu, FALSE);
	else
		vcpu_set_metaphysical_mode(vcpu, TRUE);
	if (newpsr.be)
		ipsr->be = 1;
	if (enabling_interrupts &&
	    vcpu_check_pending_interrupts(vcpu) != SPURIOUS_VECTOR)
		PSCB(vcpu, pending_interruption) = 1;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_psr(VCPU * vcpu, u64 * pval)
{
	REGS *regs = vcpu_regs(vcpu);
	struct ia64_psr newpsr;

	newpsr = *(struct ia64_psr *)&regs->cr_ipsr;
	if (!vcpu->vcpu_info->evtchn_upcall_mask)
		newpsr.i = 1;
	else
		newpsr.i = 0;
	if (PSCB(vcpu, interrupt_collection_enabled))
		newpsr.ic = 1;
	else
		newpsr.ic = 0;
	if (PSCB(vcpu, metaphysical_mode))
		newpsr.dt = 0;
	else
		newpsr.dt = 1;
	if (PSCB(vcpu, vpsr_pp))
		newpsr.pp = 1;
	else
		newpsr.pp = 0;
	newpsr.dfh = PSCB(vcpu, vpsr_dfh);

	*pval = *(unsigned long *)&newpsr;
	*pval &= (MASK(0, 32) | MASK(35, 2));
	return IA64_NO_FAULT;
}

BOOLEAN vcpu_get_psr_ic(VCPU * vcpu)
{
	return !!PSCB(vcpu, interrupt_collection_enabled);
}

BOOLEAN vcpu_get_psr_i(VCPU * vcpu)
{
	return !vcpu->vcpu_info->evtchn_upcall_mask;
}

u64 vcpu_get_ipsr_int_state(VCPU * vcpu, u64 prevpsr)
{
	u64 dcr = PSCB(vcpu, dcr);
	PSR psr;

	//printk("*** vcpu_get_ipsr_int_state (0x%016lx)...\n",prevpsr);
	psr.i64 = prevpsr;
	psr.ia64_psr.pp = 0;
	if (dcr & IA64_DCR_PP)
		psr.ia64_psr.pp = 1;
	psr.ia64_psr.ic = PSCB(vcpu, interrupt_collection_enabled);
	psr.ia64_psr.i = !vcpu->vcpu_info->evtchn_upcall_mask;
	psr.ia64_psr.bn = PSCB(vcpu, banknum);
	psr.ia64_psr.dfh = PSCB(vcpu, vpsr_dfh);
	psr.ia64_psr.dt = 1;
	psr.ia64_psr.it = 1;
	psr.ia64_psr.rt = 1;
	if (psr.ia64_psr.cpl == 2)
		psr.ia64_psr.cpl = 0;	// !!!! fool domain
	// psr.pk = 1;
	//printk("returns 0x%016lx...\n",psr.i64);
	return psr.i64;
}

/**************************************************************************
 VCPU control register access routines
**************************************************************************/

IA64FAULT vcpu_get_dcr(VCPU * vcpu, u64 * pval)
{
	*pval = PSCB(vcpu, dcr);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_iva(VCPU * vcpu, u64 * pval)
{
	if (VMX_DOMAIN(vcpu))
		*pval = PSCB(vcpu, iva) & ~0x7fffL;
	else
		*pval = PSCBX(vcpu, iva) & ~0x7fffL;

	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_pta(VCPU * vcpu, u64 * pval)
{
	*pval = PSCB(vcpu, pta);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_ipsr(VCPU * vcpu, u64 * pval)
{
	//REGS *regs = vcpu_regs(vcpu);
	//*pval = regs->cr_ipsr;
	*pval = PSCB(vcpu, ipsr);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_isr(VCPU * vcpu, u64 * pval)
{
	*pval = PSCB(vcpu, isr);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_iip(VCPU * vcpu, u64 * pval)
{
	//REGS *regs = vcpu_regs(vcpu);
	//*pval = regs->cr_iip;
	*pval = PSCB(vcpu, iip);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_ifa(VCPU * vcpu, u64 * pval)
{
	PRIVOP_COUNT_ADDR(vcpu_regs(vcpu), privop_inst_get_ifa);
	*pval = PSCB(vcpu, ifa);
	return IA64_NO_FAULT;
}

unsigned long vcpu_get_rr_ps(VCPU * vcpu, u64 vadr)
{
	ia64_rr rr;

	rr.rrval = PSCB(vcpu, rrs)[vadr >> 61];
	return rr.ps;
}

unsigned long vcpu_get_rr_rid(VCPU * vcpu, u64 vadr)
{
	ia64_rr rr;

	rr.rrval = PSCB(vcpu, rrs)[vadr >> 61];
	return rr.rid;
}

unsigned long vcpu_get_itir_on_fault(VCPU * vcpu, u64 ifa)
{
	ia64_rr rr;

	rr.rrval = 0;
	rr.ps = vcpu_get_rr_ps(vcpu, ifa);
	rr.rid = vcpu_get_rr_rid(vcpu, ifa);
	return rr.rrval;
}

IA64FAULT vcpu_get_itir(VCPU * vcpu, u64 * pval)
{
	u64 val = PSCB(vcpu, itir);
	*pval = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_iipa(VCPU * vcpu, u64 * pval)
{
	u64 val = PSCB(vcpu, iipa);
	// SP entry code does not save iipa yet nor does it get
	//  properly delivered in the pscb
//	printk("*** vcpu_get_iipa: cr.iipa not fully implemented yet!!\n");
	*pval = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_ifs(VCPU * vcpu, u64 * pval)
{
	//PSCB(vcpu,ifs) = PSCB(vcpu)->regs.cr_ifs;
	//*pval = PSCB(vcpu,regs).cr_ifs;
	*pval = PSCB(vcpu, ifs);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_iim(VCPU * vcpu, u64 * pval)
{
	u64 val = PSCB(vcpu, iim);
	*pval = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_iha(VCPU * vcpu, u64 * pval)
{
	PRIVOP_COUNT_ADDR(vcpu_regs(vcpu), privop_inst_thash);
	*pval = PSCB(vcpu, iha);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_dcr(VCPU * vcpu, u64 val)
{
	PSCB(vcpu, dcr) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_iva(VCPU * vcpu, u64 val)
{
	if (VMX_DOMAIN(vcpu))
		PSCB(vcpu, iva) = val & ~0x7fffL;
	else
		PSCBX(vcpu, iva) = val & ~0x7fffL;

	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_pta(VCPU * vcpu, u64 val)
{
	if (val & IA64_PTA_LFMT) {
		printk("*** No support for VHPT long format yet!!\n");
		return IA64_ILLOP_FAULT;
	}
	if (val & (0x3f << 9))	/* reserved fields */
		return IA64_RSVDREG_FAULT;
	if (val & 2)		/* reserved fields */
		return IA64_RSVDREG_FAULT;
	PSCB(vcpu, pta) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_ipsr(VCPU * vcpu, u64 val)
{
	PSCB(vcpu, ipsr) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_isr(VCPU * vcpu, u64 val)
{
	PSCB(vcpu, isr) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_iip(VCPU * vcpu, u64 val)
{
	PSCB(vcpu, iip) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_increment_iip(VCPU * vcpu)
{
	REGS *regs = vcpu_regs(vcpu);
	struct ia64_psr *ipsr = (struct ia64_psr *)&regs->cr_ipsr;
	if (ipsr->ri == 2) {
		ipsr->ri = 0;
		regs->cr_iip += 16;
	} else
		ipsr->ri++;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_decrement_iip(VCPU * vcpu)
{
	REGS *regs = vcpu_regs(vcpu);
	struct ia64_psr *ipsr = (struct ia64_psr *)&regs->cr_ipsr;

	if (ipsr->ri == 0) {
		ipsr->ri = 2;
		regs->cr_iip -= 16;
	} else
		ipsr->ri--;

	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_ifa(VCPU * vcpu, u64 val)
{
	PSCB(vcpu, ifa) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_itir(VCPU * vcpu, u64 val)
{
	PSCB(vcpu, itir) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_iipa(VCPU * vcpu, u64 val)
{
	// SP entry code does not save iipa yet nor does it get
	//  properly delivered in the pscb
//	printk("*** vcpu_set_iipa: cr.iipa not fully implemented yet!!\n");
	PSCB(vcpu, iipa) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_ifs(VCPU * vcpu, u64 val)
{
	//REGS *regs = vcpu_regs(vcpu);
	PSCB(vcpu, ifs) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_iim(VCPU * vcpu, u64 val)
{
	PSCB(vcpu, iim) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_iha(VCPU * vcpu, u64 val)
{
	PSCB(vcpu, iha) = val;
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU interrupt control register access routines
**************************************************************************/

void vcpu_pend_unspecified_interrupt(VCPU * vcpu)
{
	PSCB(vcpu, pending_interruption) = 1;
}

void vcpu_pend_interrupt(VCPU * vcpu, u64 vector)
{
	if (vector & ~0xff) {
		printk("vcpu_pend_interrupt: bad vector\n");
		return;
	}

	if (vcpu->arch.event_callback_ip) {
		printk("Deprecated interface. Move to new event based "
		       "solution\n");
		return;
	}

	if (VMX_DOMAIN(vcpu)) {
		set_bit(vector, VCPU(vcpu, irr));
	} else {
		set_bit(vector, PSCBX(vcpu, irr));
		PSCB(vcpu, pending_interruption) = 1;
	}
}

#define	IA64_TPR_MMI	0x10000
#define	IA64_TPR_MIC	0x000f0

/* checks to see if a VCPU has any unmasked pending interrupts
 * if so, returns the highest, else returns SPURIOUS_VECTOR */
/* NOTE: Since this gets called from vcpu_get_ivr() and the
 * semantics of "mov rx=cr.ivr" ignore the setting of the psr.i bit,
 * this routine also ignores pscb.interrupt_delivery_enabled
 * and this must be checked independently; see vcpu_deliverable interrupts() */
u64 vcpu_check_pending_interrupts(VCPU * vcpu)
{
	u64 *p, *r, bits, bitnum, mask, i, vector;

	if (vcpu->arch.event_callback_ip)
		return SPURIOUS_VECTOR;

	/* Always check pending event, since guest may just ack the
	 * event injection without handle. Later guest may throw out
	 * the event itself.
	 */
 check_start:
	if (event_pending(vcpu) &&
	    !test_bit(vcpu->domain->shared_info->arch.evtchn_vector,
		      &PSCBX(vcpu, insvc[0])))
		vcpu_pend_interrupt(vcpu,
		                    vcpu->domain->shared_info->arch.
		                    evtchn_vector);

	p = &PSCBX(vcpu, irr[3]);
	r = &PSCBX(vcpu, insvc[3]);
	for (i = 3 ;; p--, r--, i--) {
		bits = *p;
		if (bits)
			break;	// got a potential interrupt
		if (*r) {
			// nothing in this word which is pending+inservice
			// but there is one inservice which masks lower
			return SPURIOUS_VECTOR;
		}
		if (i == 0) {
			// checked all bits... nothing pending+inservice
			return SPURIOUS_VECTOR;
		}
	}
	// have a pending,deliverable interrupt... see if it is masked
	bitnum = ia64_fls(bits);
//printk("XXXXXXX vcpu_check_pending_interrupts: got bitnum=%p...\n",bitnum);
	vector = bitnum + (i * 64);
	mask = 1L << bitnum;
	/* sanity check for guest timer interrupt */
	if (vector == (PSCB(vcpu, itv) & 0xff)) {
		uint64_t now = ia64_get_itc();
		if (now < PSCBX(vcpu, domain_itm)) {
//			printk("Ooops, pending guest timer before its due\n");
			PSCBX(vcpu, irr[i]) &= ~mask;
			goto check_start;
		}
	}
//printk("XXXXXXX vcpu_check_pending_interrupts: got vector=%p...\n",vector);
	if (*r >= mask) {
		// masked by equal inservice
//printk("but masked by equal inservice\n");
		return SPURIOUS_VECTOR;
	}
	if (PSCB(vcpu, tpr) & IA64_TPR_MMI) {
		// tpr.mmi is set
//printk("but masked by tpr.mmi\n");
		return SPURIOUS_VECTOR;
	}
	if (((PSCB(vcpu, tpr) & IA64_TPR_MIC) + 15) >= vector) {
		//tpr.mic masks class
//printk("but masked by tpr.mic\n");
		return SPURIOUS_VECTOR;
	}
//printk("returned to caller\n");
	return vector;
}

u64 vcpu_deliverable_interrupts(VCPU * vcpu)
{
	return (vcpu_get_psr_i(vcpu) &&
		vcpu_check_pending_interrupts(vcpu) != SPURIOUS_VECTOR);
}

u64 vcpu_deliverable_timer(VCPU * vcpu)
{
	return (vcpu_get_psr_i(vcpu) &&
		vcpu_check_pending_interrupts(vcpu) == PSCB(vcpu, itv));
}

IA64FAULT vcpu_get_lid(VCPU * vcpu, u64 * pval)
{
	/* Use EID=0, ID=vcpu_id.  */
	*pval = vcpu->vcpu_id << 24;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_ivr(VCPU * vcpu, u64 * pval)
{
	int i;
	u64 vector, mask;

#define HEARTBEAT_FREQ 16	// period in seconds
#ifdef HEARTBEAT_FREQ
#define N_DOMS 16		// period in seconds
#if 0
	static long count[N_DOMS] = { 0 };
#endif
	static long nonclockcount[N_DOMS] = { 0 };
	unsigned domid = vcpu->domain->domain_id;
#endif
#ifdef IRQ_DEBUG
	static char firstivr = 1;
	static char firsttime[256];
	if (firstivr) {
		int i;
		for (i = 0; i < 256; i++)
			firsttime[i] = 1;
		firstivr = 0;
	}
#endif

	vector = vcpu_check_pending_interrupts(vcpu);
	if (vector == SPURIOUS_VECTOR) {
		PSCB(vcpu, pending_interruption) = 0;
		*pval = vector;
		return IA64_NO_FAULT;
	}
#ifdef HEARTBEAT_FREQ
	if (domid >= N_DOMS)
		domid = N_DOMS - 1;
#if 0
	if (vector == (PSCB(vcpu, itv) & 0xff)) {
		if (!(++count[domid] & ((HEARTBEAT_FREQ * 1024) - 1))) {
			printk("Dom%d heartbeat... ticks=%lx,nonticks=%lx\n",
			       domid, count[domid], nonclockcount[domid]);
			//count[domid] = 0;
			//dump_runq();
		}
	}
#endif
	else
		nonclockcount[domid]++;
#endif
	// now have an unmasked, pending, deliverable vector!
	// getting ivr has "side effects"
#ifdef IRQ_DEBUG
	if (firsttime[vector]) {
		printk("*** First get_ivr on vector=%lu,itc=%lx\n",
		       vector, ia64_get_itc());
		firsttime[vector] = 0;
	}
#endif
	/* if delivering a timer interrupt, remember domain_itm, which
	 * needs to be done before clearing irr
	 */
	if (vector == (PSCB(vcpu, itv) & 0xff)) {
		PSCBX(vcpu, domain_itm_last) = PSCBX(vcpu, domain_itm);
	}

	i = vector >> 6;
	mask = 1L << (vector & 0x3f);
//printk("ZZZZZZ vcpu_get_ivr: setting insvc mask for vector %lu\n",vector);
	PSCBX(vcpu, insvc[i]) |= mask;
	PSCBX(vcpu, irr[i]) &= ~mask;
	//PSCB(vcpu,pending_interruption)--;
	*pval = vector;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_tpr(VCPU * vcpu, u64 * pval)
{
	*pval = PSCB(vcpu, tpr);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_eoi(VCPU * vcpu, u64 * pval)
{
	*pval = 0L;		// reads of eoi always return 0
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_irr0(VCPU * vcpu, u64 * pval)
{
	*pval = PSCBX(vcpu, irr[0]);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_irr1(VCPU * vcpu, u64 * pval)
{
	*pval = PSCBX(vcpu, irr[1]);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_irr2(VCPU * vcpu, u64 * pval)
{
	*pval = PSCBX(vcpu, irr[2]);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_irr3(VCPU * vcpu, u64 * pval)
{
	*pval = PSCBX(vcpu, irr[3]);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_itv(VCPU * vcpu, u64 * pval)
{
	*pval = PSCB(vcpu, itv);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_pmv(VCPU * vcpu, u64 * pval)
{
	*pval = PSCB(vcpu, pmv);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_cmcv(VCPU * vcpu, u64 * pval)
{
	*pval = PSCB(vcpu, cmcv);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_lrr0(VCPU * vcpu, u64 * pval)
{
	// fix this when setting values other than m-bit is supported
	gdprintk(XENLOG_DEBUG,
		 "vcpu_get_lrr0: Unmasked interrupts unsupported\n");
	*pval = (1L << 16);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_lrr1(VCPU * vcpu, u64 * pval)
{
	// fix this when setting values other than m-bit is supported
	gdprintk(XENLOG_DEBUG,
		 "vcpu_get_lrr1: Unmasked interrupts unsupported\n");
	*pval = (1L << 16);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_lid(VCPU * vcpu, u64 val)
{
	printk("vcpu_set_lid: Setting cr.lid is unsupported\n");
	return IA64_ILLOP_FAULT;
}

IA64FAULT vcpu_set_tpr(VCPU * vcpu, u64 val)
{
	if (val & 0xff00)
		return IA64_RSVDREG_FAULT;
	PSCB(vcpu, tpr) = val;
	/* This can unmask interrupts.  */
	if (vcpu_check_pending_interrupts(vcpu) != SPURIOUS_VECTOR)
		PSCB(vcpu, pending_interruption) = 1;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_eoi(VCPU * vcpu, u64 val)
{
	u64 *p, bits, vec, bitnum;
	int i;

	p = &PSCBX(vcpu, insvc[3]);
	for (i = 3; (i >= 0) && !(bits = *p); i--, p--)
		;
	if (i < 0) {
		printk("Trying to EOI interrupt when none are in-service.\n");
		return IA64_NO_FAULT;
	}
	bitnum = ia64_fls(bits);
	vec = bitnum + (i * 64);
	/* clear the correct bit */
	bits &= ~(1L << bitnum);
	*p = bits;
	/* clearing an eoi bit may unmask another pending interrupt... */
	if (!vcpu->vcpu_info->evtchn_upcall_mask) {	// but only if enabled...
		// worry about this later... Linux only calls eoi
		// with interrupts disabled
		printk("Trying to EOI interrupt with interrupts enabled\n");
	}
	if (vcpu_check_pending_interrupts(vcpu) != SPURIOUS_VECTOR)
		PSCB(vcpu, pending_interruption) = 1;
//printk("YYYYY vcpu_set_eoi: Successful\n");
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_lrr0(VCPU * vcpu, u64 val)
{
	if (!(val & (1L << 16))) {
		printk("vcpu_set_lrr0: Unmasked interrupts unsupported\n");
		return IA64_ILLOP_FAULT;
	}
	// no place to save this state but nothing to do anyway
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_lrr1(VCPU * vcpu, u64 val)
{
	if (!(val & (1L << 16))) {
		printk("vcpu_set_lrr0: Unmasked interrupts unsupported\n");
		return IA64_ILLOP_FAULT;
	}
	// no place to save this state but nothing to do anyway
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_itv(VCPU * vcpu, u64 val)
{
	/* Check reserved fields.  */
	if (val & 0xef00)
		return IA64_ILLOP_FAULT;
	PSCB(vcpu, itv) = val;
	if (val & 0x10000) {
		/* Disable itm.  */
		PSCBX(vcpu, domain_itm) = 0;
	} else
		vcpu_set_next_timer(vcpu);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_pmv(VCPU * vcpu, u64 val)
{
	if (val & 0xef00)	/* reserved fields */
		return IA64_RSVDREG_FAULT;
	PSCB(vcpu, pmv) = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_cmcv(VCPU * vcpu, u64 val)
{
	if (val & 0xef00)	/* reserved fields */
		return IA64_RSVDREG_FAULT;
	PSCB(vcpu, cmcv) = val;
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU temporary register access routines
**************************************************************************/
u64 vcpu_get_tmp(VCPU * vcpu, u64 index)
{
	if (index > 7)
		return 0;
	return PSCB(vcpu, tmp[index]);
}

void vcpu_set_tmp(VCPU * vcpu, u64 index, u64 val)
{
	if (index <= 7)
		PSCB(vcpu, tmp[index]) = val;
}

/**************************************************************************
Interval timer routines
**************************************************************************/

BOOLEAN vcpu_timer_disabled(VCPU * vcpu)
{
	u64 itv = PSCB(vcpu, itv);
	return (!itv || !!(itv & 0x10000));
}

BOOLEAN vcpu_timer_inservice(VCPU * vcpu)
{
	u64 itv = PSCB(vcpu, itv);
	return test_bit(itv, PSCBX(vcpu, insvc));
}

BOOLEAN vcpu_timer_expired(VCPU * vcpu)
{
	unsigned long domain_itm = PSCBX(vcpu, domain_itm);
	unsigned long now = ia64_get_itc();

	if (!domain_itm)
		return FALSE;
	if (now < domain_itm)
		return FALSE;
	if (vcpu_timer_disabled(vcpu))
		return FALSE;
	return TRUE;
}

void vcpu_safe_set_itm(unsigned long val)
{
	unsigned long epsilon = 100;
	unsigned long flags;
	u64 now = ia64_get_itc();

	local_irq_save(flags);
	while (1) {
//printk("*** vcpu_safe_set_itm: Setting itm to %lx, itc=%lx\n",val,now);
		ia64_set_itm(val);
		if (val > (now = ia64_get_itc()))
			break;
		val = now + epsilon;
		epsilon <<= 1;
	}
	local_irq_restore(flags);
}

void vcpu_set_next_timer(VCPU * vcpu)
{
	u64 d = PSCBX(vcpu, domain_itm);
	//u64 s = PSCBX(vcpu,xen_itm);
	u64 s = local_cpu_data->itm_next;
	u64 now = ia64_get_itc();

	/* gloss over the wraparound problem for now... we know it exists
	 * but it doesn't matter right now */

	if (is_idle_domain(vcpu->domain)) {
//		printk("****** vcpu_set_next_timer called during idle!!\n");
		vcpu_safe_set_itm(s);
		return;
	}
	//s = PSCBX(vcpu,xen_itm);
	if (d && (d > now) && (d < s)) {
		vcpu_safe_set_itm(d);
		//using_domain_as_itm++;
	} else {
		vcpu_safe_set_itm(s);
		//using_xen_as_itm++;
	}
}

IA64FAULT vcpu_set_itm(VCPU * vcpu, u64 val)
{
	//UINT now = ia64_get_itc();

	//if (val < now) val = now + 1000;
//printk("*** vcpu_set_itm: called with %lx\n",val);
	PSCBX(vcpu, domain_itm) = val;
	vcpu_set_next_timer(vcpu);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_itc(VCPU * vcpu, u64 val)
{
#define DISALLOW_SETTING_ITC_FOR_NOW
#ifdef DISALLOW_SETTING_ITC_FOR_NOW
	static int did_print;
	if (!did_print) {
		printk("vcpu_set_itc: Setting ar.itc is currently disabled "
		       "(this message is only displayed once)\n");
		did_print = 1;
	}
#else
	u64 oldnow = ia64_get_itc();
	u64 olditm = PSCBX(vcpu, domain_itm);
	unsigned long d = olditm - oldnow;
	unsigned long x = local_cpu_data->itm_next - oldnow;

	u64 newnow = val, min_delta;

	local_irq_disable();
	if (olditm) {
		printk("**** vcpu_set_itc(%lx): vitm changed to %lx\n", val,
		       newnow + d);
		PSCBX(vcpu, domain_itm) = newnow + d;
	}
	local_cpu_data->itm_next = newnow + x;
	d = PSCBX(vcpu, domain_itm);
	x = local_cpu_data->itm_next;

	ia64_set_itc(newnow);
	if (d && (d > newnow) && (d < x)) {
		vcpu_safe_set_itm(d);
		//using_domain_as_itm++;
	} else {
		vcpu_safe_set_itm(x);
		//using_xen_as_itm++;
	}
	local_irq_enable();
#endif
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_itm(VCPU * vcpu, u64 * pval)
{
	//FIXME: Implement this
	printk("vcpu_get_itm: Getting cr.itm is unsupported... continuing\n");
	return IA64_NO_FAULT;
	//return IA64_ILLOP_FAULT;
}

IA64FAULT vcpu_get_itc(VCPU * vcpu, u64 * pval)
{
	//TODO: Implement this
	printk("vcpu_get_itc: Getting ar.itc is unsupported\n");
	return IA64_ILLOP_FAULT;
}

void vcpu_pend_timer(VCPU * vcpu)
{
	u64 itv = PSCB(vcpu, itv) & 0xff;

	if (vcpu_timer_disabled(vcpu))
		return;
	//if (vcpu_timer_inservice(vcpu)) return;
	if (PSCBX(vcpu, domain_itm_last) == PSCBX(vcpu, domain_itm)) {
		// already delivered an interrupt for this so
		// don't deliver another
		return;
	}
	if (vcpu->arch.event_callback_ip) {
		/* A small window may occur when injecting vIRQ while related
		 * handler has not been registered. Don't fire in such case.
		 */
		if (vcpu->virq_to_evtchn[VIRQ_ITC]) {
			send_guest_vcpu_virq(vcpu, VIRQ_ITC);
			PSCBX(vcpu, domain_itm_last) = PSCBX(vcpu, domain_itm);
		}
	} else
		vcpu_pend_interrupt(vcpu, itv);
}

// returns true if ready to deliver a timer interrupt too early
u64 vcpu_timer_pending_early(VCPU * vcpu)
{
	u64 now = ia64_get_itc();
	u64 itm = PSCBX(vcpu, domain_itm);

	if (vcpu_timer_disabled(vcpu))
		return 0;
	if (!itm)
		return 0;
	return (vcpu_deliverable_timer(vcpu) && (now < itm));
}

/**************************************************************************
Privileged operation emulation routines
**************************************************************************/

static void vcpu_force_tlb_miss(VCPU * vcpu, u64 ifa)
{
	PSCB(vcpu, ifa) = ifa;
	PSCB(vcpu, itir) = vcpu_get_itir_on_fault(vcpu, ifa);
	vcpu_thash(current, ifa, &PSCB(current, iha));
}

IA64FAULT vcpu_force_inst_miss(VCPU * vcpu, u64 ifa)
{
	vcpu_force_tlb_miss(vcpu, ifa);
	return vcpu_get_rr_ve(vcpu, ifa) ? IA64_INST_TLB_VECTOR :
		IA64_ALT_INST_TLB_VECTOR;
}

IA64FAULT vcpu_force_data_miss(VCPU * vcpu, u64 ifa)
{
	vcpu_force_tlb_miss(vcpu, ifa);
	return vcpu_get_rr_ve(vcpu, ifa) ? IA64_DATA_TLB_VECTOR :
		IA64_ALT_DATA_TLB_VECTOR;
}

IA64FAULT vcpu_rfi(VCPU * vcpu)
{
	// TODO: Only allowed for current vcpu
	PSR psr;
	u64 int_enable, ifs;
	REGS *regs = vcpu_regs(vcpu);

	psr.i64 = PSCB(vcpu, ipsr);
	if (psr.ia64_psr.cpl < 3)
		psr.ia64_psr.cpl = 2;
	int_enable = psr.ia64_psr.i;
	if (psr.ia64_psr.dfh) {
		PSCB(vcpu, vpsr_dfh) = 1;
	} else {
		psr.ia64_psr.dfh = PSCB(vcpu, hpsr_dfh);
		PSCB(vcpu, vpsr_dfh) = 0;
	}
	if (psr.ia64_psr.ic)
		PSCB(vcpu, interrupt_collection_enabled) = 1;
	if (psr.ia64_psr.dt && psr.ia64_psr.rt && psr.ia64_psr.it)
		vcpu_set_metaphysical_mode(vcpu, FALSE);
	else
		vcpu_set_metaphysical_mode(vcpu, TRUE);
	psr.ia64_psr.ic = 1;
	psr.ia64_psr.i = 1;
	psr.ia64_psr.dt = 1;
	psr.ia64_psr.rt = 1;
	psr.ia64_psr.it = 1;
	psr.ia64_psr.bn = 1;
	//psr.pk = 1;  // checking pkeys shouldn't be a problem but seems broken

	ifs = PSCB(vcpu, ifs);
	if (ifs & 0x8000000000000000UL) 
		regs->cr_ifs = ifs;

	regs->cr_ipsr = psr.i64;
	regs->cr_iip = PSCB(vcpu, iip);
	PSCB(vcpu, interrupt_collection_enabled) = 1;
	vcpu_bsw1(vcpu);
	vcpu->vcpu_info->evtchn_upcall_mask = !int_enable;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_cover(VCPU * vcpu)
{
	// TODO: Only allowed for current vcpu
	REGS *regs = vcpu_regs(vcpu);

	if (!PSCB(vcpu, interrupt_collection_enabled)) {
		PSCB(vcpu, ifs) = regs->cr_ifs;
	}
	regs->cr_ifs = 0;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_thash(VCPU * vcpu, u64 vadr, u64 * pval)
{
	u64 pta = PSCB(vcpu, pta);
	u64 pta_sz = (pta & IA64_PTA_SZ(0x3f)) >> IA64_PTA_SZ_BIT;
	u64 pta_base = pta & ~((1UL << IA64_PTA_BASE_BIT) - 1);
	u64 Mask = (1L << pta_sz) - 1;
	u64 Mask_60_15 = (Mask >> 15) & 0x3fffffffffff;
	u64 compMask_60_15 = ~Mask_60_15;
	u64 rr_ps = vcpu_get_rr_ps(vcpu, vadr);
	u64 VHPT_offset = (vadr >> rr_ps) << 3;
	u64 VHPT_addr1 = vadr & 0xe000000000000000L;
	u64 VHPT_addr2a =
	    ((pta_base >> 15) & 0x3fffffffffff) & compMask_60_15;
	u64 VHPT_addr2b =
	    ((VHPT_offset >> 15) & 0x3fffffffffff) & Mask_60_15;
	u64 VHPT_addr3 = VHPT_offset & 0x7fff;
	u64 VHPT_addr = VHPT_addr1 | ((VHPT_addr2a | VHPT_addr2b) << 15) |
	    VHPT_addr3;

//verbose("vcpu_thash: vadr=%p, VHPT_addr=%p\n",vadr,VHPT_addr);
	*pval = VHPT_addr;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_ttag(VCPU * vcpu, u64 vadr, u64 * padr)
{
	printk("vcpu_ttag: ttag instruction unsupported\n");
	return IA64_ILLOP_FAULT;
}

int warn_region0_address = 0;	// FIXME later: tie to a boot parameter?

/* Return TRUE iff [b1,e1] and [b2,e2] partially or fully overlaps.  */
static inline int range_overlap(u64 b1, u64 e1, u64 b2, u64 e2)
{
	return (b1 <= e2) && (e1 >= b2);
}

/* Crash domain if [base, base + page_size] and Xen virtual space overlaps.
   Note: LSBs of base inside page_size are ignored.  */
static inline void
check_xen_space_overlap(const char *func, u64 base, u64 page_size)
{
	/* Overlaps can occur only in region 7.
	   (This is an optimization to bypass all the checks).  */
	if (REGION_NUMBER(base) != 7)
		return;

	/* Mask LSBs of base.  */
	base &= ~(page_size - 1);

	/* FIXME: ideally an MCA should be generated...  */
	if (range_overlap(HYPERVISOR_VIRT_START, HYPERVISOR_VIRT_END,
			  base, base + page_size)
	    || range_overlap(current->domain->arch.shared_info_va,
			     current->domain->arch.shared_info_va
			     + XSI_SIZE + XMAPPEDREGS_SIZE,
			     base, base + page_size))
		panic_domain(NULL, "%s on Xen virtual space (%lx)\n",
			     func, base);
}

// FIXME: also need to check && (!trp->key || vcpu_pkr_match(trp->key))
static inline int vcpu_match_tr_entry_no_p(TR_ENTRY * trp, u64 ifa,
                                           u64 rid)
{
	return trp->rid == rid
	    && ifa >= trp->vadr && ifa <= (trp->vadr + (1L << trp->ps) - 1);
}

static inline int vcpu_match_tr_entry(TR_ENTRY * trp, u64 ifa, u64 rid)
{
	return trp->pte.p && vcpu_match_tr_entry_no_p(trp, ifa, rid);
}

static inline int
vcpu_match_tr_entry_range(TR_ENTRY * trp, u64 rid, u64 b, u64 e)
{
	return trp->rid == rid
	    && trp->pte.p
	    && range_overlap(b, e, trp->vadr, trp->vadr + (1L << trp->ps) - 1);

}

static TR_ENTRY *vcpu_tr_lookup(VCPU * vcpu, unsigned long va, u64 rid,
                                BOOLEAN is_data)
{
	unsigned char *regions;
	TR_ENTRY *trp;
	int tr_max;
	int i;

	if (is_data) {
		// data
		regions = &vcpu->arch.dtr_regions;
		trp = vcpu->arch.dtrs;
		tr_max = sizeof(vcpu->arch.dtrs) / sizeof(vcpu->arch.dtrs[0]);
	} else {
		// instruction
		regions = &vcpu->arch.itr_regions;
		trp = vcpu->arch.itrs;
		tr_max = sizeof(vcpu->arch.itrs) / sizeof(vcpu->arch.itrs[0]);
	}

	if (!vcpu_quick_region_check(*regions, va)) {
		return NULL;
	}
	for (i = 0; i < tr_max; i++, trp++) {
		if (vcpu_match_tr_entry(trp, va, rid)) {
			return trp;
		}
	}
	return NULL;
}

// return value
// 0: failure
// 1: success
int
vcpu_get_domain_bundle(VCPU * vcpu, REGS * regs, u64 gip,
                       IA64_BUNDLE * bundle)
{
	u64 gpip;		// guest pseudo phyiscal ip
	unsigned long vaddr;
	struct page_info *page;

 again:
#if 0
	// Currently xen doesn't track psr.it bits.
	// it assumes always psr.it = 1.
	if (!(VCPU(vcpu, vpsr) & IA64_PSR_IT)) {
		gpip = gip;
	} else
#endif
	{
		unsigned long region = REGION_NUMBER(gip);
		unsigned long rr = PSCB(vcpu, rrs)[region];
		unsigned long rid = rr & RR_RID_MASK;
		BOOLEAN swap_rr0;
		TR_ENTRY *trp;

		// vcpu->arch.{i, d}tlb are volatile,
		// copy its value to the variable, tr, before use.
		TR_ENTRY tr;

		trp = vcpu_tr_lookup(vcpu, gip, rid, 0);
		if (trp != NULL) {
			tr = *trp;
			goto found;
		}
		// When it failed to get a bundle, itlb miss is reflected.
		// Last itc.i value is cached to PSCBX(vcpu, itlb).
		tr = PSCBX(vcpu, itlb);
		if (vcpu_match_tr_entry(&tr, gip, rid)) {
			//dprintk(XENLOG_WARNING,
			//        "%s gip 0x%lx gpip 0x%lx\n", __func__,
			//	  gip, gpip);
			goto found;
		}
		trp = vcpu_tr_lookup(vcpu, gip, rid, 1);
		if (trp != NULL) {
			tr = *trp;
			goto found;
		}
#if 0
		tr = PSCBX(vcpu, dtlb);
		if (vcpu_match_tr_entry(&tr, gip, rid)) {
			goto found;
		}
#endif

		// try to access gip with guest virtual address
		// This may cause tlb miss. see vcpu_translate(). Be careful!
		swap_rr0 = (!region && PSCB(vcpu, metaphysical_mode));
		if (swap_rr0) {
			set_one_rr(0x0, PSCB(vcpu, rrs[0]));
		}
		*bundle = __get_domain_bundle(gip);
		if (swap_rr0) {
			set_metaphysical_rr0();
		}
		if (bundle->i64[0] == 0 && bundle->i64[1] == 0) {
			dprintk(XENLOG_INFO, "%s gip 0x%lx\n", __func__, gip);
			return 0;
		}
		return 1;

	found:
		gpip = ((tr.pte.ppn >> (tr.ps - 12)) << tr.ps) |
			(gip & ((1 << tr.ps) - 1));
	}

	vaddr = (unsigned long)domain_mpa_to_imva(vcpu->domain, gpip);
	page = virt_to_page(vaddr);
	if (get_page(page, vcpu->domain) == 0) {
		if (page_get_owner(page) != vcpu->domain) {
			// This page might be a page granted by another
			// domain.
			panic_domain(regs, "domain tries to execute foreign "
				     "domain page which might be mapped by "
				     "grant table.\n");
		}
		goto again;
	}
	*bundle = *((IA64_BUNDLE *) vaddr);
	put_page(page);
	return 1;
}

IA64FAULT vcpu_translate(VCPU * vcpu, u64 address, BOOLEAN is_data,
			 u64 * pteval, u64 * itir, u64 * iha)
{
	unsigned long region = address >> 61;
	unsigned long pta, rid, rr;
	union pte_flags pte;
	TR_ENTRY *trp;

	if (PSCB(vcpu, metaphysical_mode) && !(!is_data && region)) {
		// dom0 may generate an uncacheable physical address (msb=1)
		if (region && ((region != 4) || (vcpu->domain != dom0))) {
// FIXME: This seems to happen even though it shouldn't.  Need to track
// this down, but since it has been apparently harmless, just flag it for now
//                      panic_domain(vcpu_regs(vcpu),

			/*
			 * Guest may execute itc.d and rfi with psr.dt=0
			 * When VMM try to fetch opcode, tlb miss may happen,
			 * At this time PSCB(vcpu,metaphysical_mode)=1,
			 * region=5,VMM need to handle this tlb miss as if
			 * PSCB(vcpu,metaphysical_mode)=0
			 */
			printk("vcpu_translate: bad physical address: 0x%lx "
			       "at %lx\n", address, vcpu_regs(vcpu)->cr_iip);

		} else {
			*pteval = (address & _PAGE_PPN_MASK) |
				__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX;
			*itir = PAGE_SHIFT << 2;
			perfc_incr(phys_translate);
			return IA64_NO_FAULT;
		}
	} else if (!region && warn_region0_address) {
		REGS *regs = vcpu_regs(vcpu);
		unsigned long viip = PSCB(vcpu, iip);
		unsigned long vipsr = PSCB(vcpu, ipsr);
		unsigned long iip = regs->cr_iip;
		unsigned long ipsr = regs->cr_ipsr;
		printk("vcpu_translate: bad address 0x%lx, viip=0x%lx, "
		       "vipsr=0x%lx, iip=0x%lx, ipsr=0x%lx continuing\n",
		       address, viip, vipsr, iip, ipsr);
	}

	rr = PSCB(vcpu, rrs)[region];
	rid = rr & RR_RID_MASK;
	if (is_data) {
		trp = vcpu_tr_lookup(vcpu, address, rid, 1);
		if (trp != NULL) {
			*pteval = trp->pte.val;
			*itir = trp->itir;
			perfc_incr(tr_translate);
			return IA64_NO_FAULT;
		}
	}
	// FIXME?: check itr's for data accesses too, else bad things happen?
	/* else */  {
		trp = vcpu_tr_lookup(vcpu, address, rid, 0);
		if (trp != NULL) {
			*pteval = trp->pte.val;
			*itir = trp->itir;
			perfc_incr(tr_translate);
			return IA64_NO_FAULT;
		}
	}

	/* check 1-entry TLB */
	// FIXME?: check dtlb for inst accesses too, else bad things happen?
	trp = &vcpu->arch.dtlb;
	pte = trp->pte;
	if ( /* is_data && */ pte.p
	    && vcpu_match_tr_entry_no_p(trp, address, rid)) {
		*pteval = pte.val;
		*itir = trp->itir;
		perfc_incr(dtlb_translate);
		return IA64_USE_TLB;
	}

	/* check guest VHPT */
	pta = PSCB(vcpu, pta);
	if (pta & IA64_PTA_VF) { /* long format VHPT - not implemented */
		panic_domain(vcpu_regs(vcpu), "can't do long format VHPT\n");
		//return is_data ? IA64_DATA_TLB_VECTOR:IA64_INST_TLB_VECTOR;
	}

	*itir = rr & (RR_RID_MASK | RR_PS_MASK);
	// note: architecturally, iha is optionally set for alt faults but
	// xenlinux depends on it so should document it as part of PV interface
	vcpu_thash(vcpu, address, iha);
	if (!(rr & RR_VE_MASK) || !(pta & IA64_PTA_VE)) {
		REGS *regs = vcpu_regs(vcpu);
		// NOTE: This is specific code for linux kernel
		// We assume region 7 is identity mapped
		if (region == 7 && ia64_psr(regs)->cpl == 2) {
			pte.val = address & _PAGE_PPN_MASK;
			pte.val = pte.val | pgprot_val(PAGE_KERNEL);
			goto out;
		}
		return is_data ? IA64_ALT_DATA_TLB_VECTOR :
			IA64_ALT_INST_TLB_VECTOR;
	}

	/* avoid recursively walking (short format) VHPT */
	if (((address ^ pta) & ((itir_mask(pta) << 3) >> 3)) == 0)
		return is_data ? IA64_DATA_TLB_VECTOR : IA64_INST_TLB_VECTOR;

	if (!__access_ok(*iha)
	    || __copy_from_user(&pte, (void *)(*iha), sizeof(pte)) != 0)
		// virtual VHPT walker "missed" in TLB
		return IA64_VHPT_FAULT;

	/*
	 * Optimisation: this VHPT walker aborts on not-present pages
	 * instead of inserting a not-present translation, this allows
	 * vectoring directly to the miss handler.
	 */
	if (!pte.p)
		return is_data ? IA64_DATA_TLB_VECTOR : IA64_INST_TLB_VECTOR;

	/* found mapping in guest VHPT! */
out:
	*itir = rr & RR_PS_MASK;
	*pteval = pte.val;
	perfc_incr(vhpt_translate);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_tpa(VCPU * vcpu, u64 vadr, u64 * padr)
{
	u64 pteval, itir, mask, iha;
	IA64FAULT fault;

	fault = vcpu_translate(vcpu, vadr, TRUE, &pteval, &itir, &iha);
	if (fault == IA64_NO_FAULT || fault == IA64_USE_TLB) {
		mask = itir_mask(itir);
		*padr = (pteval & _PAGE_PPN_MASK & mask) | (vadr & ~mask);
		return IA64_NO_FAULT;
	}
	return vcpu_force_data_miss(vcpu, vadr);
}

IA64FAULT vcpu_tak(VCPU * vcpu, u64 vadr, u64 * key)
{
	printk("vcpu_tak: tak instruction unsupported\n");
	return IA64_ILLOP_FAULT;
	// HACK ALERT: tak does a thash for now
	//return vcpu_thash(vcpu,vadr,key);
}

/**************************************************************************
 VCPU debug breakpoint register access routines
**************************************************************************/

IA64FAULT vcpu_set_dbr(VCPU * vcpu, u64 reg, u64 val)
{
	// TODO: unimplemented DBRs return a reserved register fault
	// TODO: Should set Logical CPU state, not just physical
	ia64_set_dbr(reg, val);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_ibr(VCPU * vcpu, u64 reg, u64 val)
{
	// TODO: unimplemented IBRs return a reserved register fault
	// TODO: Should set Logical CPU state, not just physical
	ia64_set_ibr(reg, val);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_dbr(VCPU * vcpu, u64 reg, u64 * pval)
{
	// TODO: unimplemented DBRs return a reserved register fault
	u64 val = ia64_get_dbr(reg);
	*pval = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_ibr(VCPU * vcpu, u64 reg, u64 * pval)
{
	// TODO: unimplemented IBRs return a reserved register fault
	u64 val = ia64_get_ibr(reg);
	*pval = val;
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU performance monitor register access routines
**************************************************************************/

IA64FAULT vcpu_set_pmc(VCPU * vcpu, u64 reg, u64 val)
{
	// TODO: Should set Logical CPU state, not just physical
	// NOTE: Writes to unimplemented PMC registers are discarded
#ifdef DEBUG_PFMON
	printk("vcpu_set_pmc(%x,%lx)\n", reg, val);
#endif
	ia64_set_pmc(reg, val);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_pmd(VCPU * vcpu, u64 reg, u64 val)
{
	// TODO: Should set Logical CPU state, not just physical
	// NOTE: Writes to unimplemented PMD registers are discarded
#ifdef DEBUG_PFMON
	printk("vcpu_set_pmd(%x,%lx)\n", reg, val);
#endif
	ia64_set_pmd(reg, val);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_pmc(VCPU * vcpu, u64 reg, u64 * pval)
{
	// NOTE: Reads from unimplemented PMC registers return zero
	u64 val = (u64) ia64_get_pmc(reg);
#ifdef DEBUG_PFMON
	printk("%lx=vcpu_get_pmc(%x)\n", val, reg);
#endif
	*pval = val;
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_pmd(VCPU * vcpu, u64 reg, u64 * pval)
{
	// NOTE: Reads from unimplemented PMD registers return zero
	u64 val = (u64) ia64_get_pmd(reg);
#ifdef DEBUG_PFMON
	printk("%lx=vcpu_get_pmd(%x)\n", val, reg);
#endif
	*pval = val;
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU banked general register access routines
**************************************************************************/
#define vcpu_bsw0_unat(i,b0unat,b1unat,runat,IA64_PT_REGS_R16_SLOT)     \
do{     \
    __asm__ __volatile__ (                      \
        ";;extr.u %0 = %3,%6,16;;\n"            \
        "dep %1 = %0, %1, 0, 16;;\n"            \
        "st8 [%4] = %1\n"                       \
        "extr.u %0 = %2, 16, 16;;\n"            \
        "dep %3 = %0, %3, %6, 16;;\n"           \
        "st8 [%5] = %3\n"                       \
        ::"r"(i),"r"(*b1unat),"r"(*b0unat),"r"(*runat),"r"(b1unat), \
        "r"(runat),"i"(IA64_PT_REGS_R16_SLOT):"memory");    \
}while(0)

IA64FAULT vcpu_bsw0(VCPU * vcpu)
{
	// TODO: Only allowed for current vcpu
	REGS *regs = vcpu_regs(vcpu);
	unsigned long *r = &regs->r16;
	unsigned long *b0 = &PSCB(vcpu, bank0_regs[0]);
	unsigned long *b1 = &PSCB(vcpu, bank1_regs[0]);
	unsigned long *runat = &regs->eml_unat;
	unsigned long *b0unat = &PSCB(vcpu, vbnat);
	unsigned long *b1unat = &PSCB(vcpu, vnat);

	unsigned long i;

	if (VMX_DOMAIN(vcpu)) {
		if (VCPU(vcpu, vpsr) & IA64_PSR_BN) {
			for (i = 0; i < 16; i++) {
				*b1++ = *r;
				*r++ = *b0++;
			}
			vcpu_bsw0_unat(i, b0unat, b1unat, runat,
				       IA64_PT_REGS_R16_SLOT);
			VCPU(vcpu, vpsr) &= ~IA64_PSR_BN;
		}
	} else {
		if (PSCB(vcpu, banknum)) {
			for (i = 0; i < 16; i++) {
				*b1++ = *r;
				*r++ = *b0++;
			}
			vcpu_bsw0_unat(i, b0unat, b1unat, runat,
			               IA64_PT_REGS_R16_SLOT);
			PSCB(vcpu, banknum) = 0;
		}
	}
	return IA64_NO_FAULT;
}

#define vcpu_bsw1_unat(i, b0unat, b1unat, runat, IA64_PT_REGS_R16_SLOT)	\
do {             							\
	__asm__ __volatile__ (";;extr.u %0 = %3,%6,16;;\n"		\
        		      "dep %1 = %0, %1, 16, 16;;\n"		\
			      "st8 [%4] = %1\n"				\
			      "extr.u %0 = %2, 0, 16;;\n"		\
			      "dep %3 = %0, %3, %6, 16;;\n"		\
			      "st8 [%5] = %3\n"				\
			      ::"r"(i), "r"(*b0unat), "r"(*b1unat),	\
			      "r"(*runat), "r"(b0unat), "r"(runat),	\
			      "i"(IA64_PT_REGS_R16_SLOT): "memory");	\
} while(0)

IA64FAULT vcpu_bsw1(VCPU * vcpu)
{
	// TODO: Only allowed for current vcpu
	REGS *regs = vcpu_regs(vcpu);
	unsigned long *r = &regs->r16;
	unsigned long *b0 = &PSCB(vcpu, bank0_regs[0]);
	unsigned long *b1 = &PSCB(vcpu, bank1_regs[0]);
	unsigned long *runat = &regs->eml_unat;
	unsigned long *b0unat = &PSCB(vcpu, vbnat);
	unsigned long *b1unat = &PSCB(vcpu, vnat);

	unsigned long i;

	if (VMX_DOMAIN(vcpu)) {
		if (!(VCPU(vcpu, vpsr) & IA64_PSR_BN)) {
			for (i = 0; i < 16; i++) {
				*b0++ = *r;
				*r++ = *b1++;
			}
			vcpu_bsw1_unat(i, b0unat, b1unat, runat,
			               IA64_PT_REGS_R16_SLOT);
			VCPU(vcpu, vpsr) |= IA64_PSR_BN;
		}
	} else {
		if (!PSCB(vcpu, banknum)) {
			for (i = 0; i < 16; i++) {
				*b0++ = *r;
				*r++ = *b1++;
			}
			vcpu_bsw1_unat(i, b0unat, b1unat, runat,
			               IA64_PT_REGS_R16_SLOT);
			PSCB(vcpu, banknum) = 1;
		}
	}
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU cpuid access routines
**************************************************************************/

IA64FAULT vcpu_get_cpuid(VCPU * vcpu, u64 reg, u64 * pval)
{
	// FIXME: This could get called as a result of a rsvd-reg fault
	// if reg > 3
	switch (reg) {
	case 0:
		memcpy(pval, "Xen/ia64", 8);
		break;
	case 1:
		*pval = 0;
		break;
	case 2:
		*pval = 0;
		break;
	case 3:
		*pval = ia64_get_cpuid(3);
		break;
	case 4:
		*pval = ia64_get_cpuid(4);
		break;
	default:
		if (reg > (ia64_get_cpuid(3) & 0xff))
			return IA64_RSVDREG_FAULT;
		*pval = ia64_get_cpuid(reg);
		break;
	}
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU region register access routines
**************************************************************************/

unsigned long vcpu_get_rr_ve(VCPU * vcpu, u64 vadr)
{
	ia64_rr rr;

	rr.rrval = PSCB(vcpu, rrs)[vadr >> 61];
	return rr.ve;
}

IA64FAULT vcpu_set_rr(VCPU * vcpu, u64 reg, u64 val)
{
	PSCB(vcpu, rrs)[reg >> 61] = val;
	// warning: set_one_rr() does it "live"
	set_one_rr(reg, val);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_get_rr(VCPU * vcpu, u64 reg, u64 * pval)
{
	if (VMX_DOMAIN(vcpu))
		*pval = VMX(vcpu, vrr[reg >> 61]);
	else
		*pval = PSCB(vcpu, rrs)[reg >> 61];

	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU protection key register access routines
**************************************************************************/

IA64FAULT vcpu_get_pkr(VCPU * vcpu, u64 reg, u64 * pval)
{
#ifndef PKR_USE_FIXED
	printk("vcpu_get_pkr: called, not implemented yet\n");
	return IA64_ILLOP_FAULT;
#else
	u64 val = (u64) ia64_get_pkr(reg);
	*pval = val;
	return IA64_NO_FAULT;
#endif
}

IA64FAULT vcpu_set_pkr(VCPU * vcpu, u64 reg, u64 val)
{
#ifndef PKR_USE_FIXED
	printk("vcpu_set_pkr: called, not implemented yet\n");
	return IA64_ILLOP_FAULT;
#else
//      if (reg >= NPKRS)
//		return IA64_ILLOP_FAULT;
	vcpu->pkrs[reg] = val;
	ia64_set_pkr(reg, val);
	return IA64_NO_FAULT;
#endif
}

/**************************************************************************
 VCPU translation register access routines
**************************************************************************/

static void
vcpu_set_tr_entry_rid(TR_ENTRY * trp, u64 pte,
                      u64 itir, u64 ifa, u64 rid)
{
	u64 ps;
	union pte_flags new_pte;

	trp->itir = itir;
	trp->rid = rid;
	ps = trp->ps;
	new_pte.val = pte;
	if (new_pte.pl < 2)
		new_pte.pl = 2;
	trp->vadr = ifa & ~0xfff;
	if (ps > 12) {		// "ignore" relevant low-order bits
		new_pte.ppn &= ~((1UL << (ps - 12)) - 1);
		trp->vadr &= ~((1UL << ps) - 1);
	}

	/* Atomic write.  */
	trp->pte.val = new_pte.val;
}

static inline void
vcpu_set_tr_entry(TR_ENTRY * trp, u64 pte, u64 itir, u64 ifa)
{
	vcpu_set_tr_entry_rid(trp, pte, itir, ifa,
			      VCPU(current, rrs[ifa >> 61]) & RR_RID_MASK);
}

IA64FAULT vcpu_itr_d(VCPU * vcpu, u64 slot, u64 pte,
                     u64 itir, u64 ifa)
{
	TR_ENTRY *trp;

	if (slot >= NDTRS)
		return IA64_RSVDREG_FAULT;

	vcpu_purge_tr_entry(&PSCBX(vcpu, dtlb));

	trp = &PSCBX(vcpu, dtrs[slot]);
//printk("***** itr.d: setting slot %d: ifa=%p\n",slot,ifa);
	vcpu_set_tr_entry(trp, pte, itir, ifa);
	vcpu_quick_region_set(PSCBX(vcpu, dtr_regions), ifa);

	/*
	 * FIXME According to spec, vhpt should be purged, but this
	 * incurs considerable performance loss, since it is safe for
	 * linux not to purge vhpt, vhpt purge is disabled until a
	 * feasible way is found.
	 *
	 * vcpu_flush_tlb_vhpt_range(ifa & itir_mask(itir), itir_ps(itir));
	 */

	return IA64_NO_FAULT;
}

IA64FAULT vcpu_itr_i(VCPU * vcpu, u64 slot, u64 pte,
                     u64 itir, u64 ifa)
{
	TR_ENTRY *trp;

	if (slot >= NITRS)
		return IA64_RSVDREG_FAULT;

	vcpu_purge_tr_entry(&PSCBX(vcpu, itlb));

	trp = &PSCBX(vcpu, itrs[slot]);
//printk("***** itr.i: setting slot %d: ifa=%p\n",slot,ifa);
	vcpu_set_tr_entry(trp, pte, itir, ifa);
	vcpu_quick_region_set(PSCBX(vcpu, itr_regions), ifa);

	/*
	 * FIXME According to spec, vhpt should be purged, but this
	 * incurs considerable performance loss, since it is safe for
	 * linux not to purge vhpt, vhpt purge is disabled until a
	 * feasible way is found.
	 *
	 * vcpu_flush_tlb_vhpt_range(ifa & itir_mask(itir), itir_ps(itir));
	 */

	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_itr(VCPU * vcpu, u64 slot, u64 pte,
                       u64 itir, u64 ifa, u64 rid)
{
	TR_ENTRY *trp;

	if (slot >= NITRS)
		return IA64_RSVDREG_FAULT;
	trp = &PSCBX(vcpu, itrs[slot]);
	vcpu_set_tr_entry_rid(trp, pte, itir, ifa, rid);

	/* Recompute the itr_region.  */
	vcpu->arch.itr_regions = 0;
	for (trp = vcpu->arch.itrs; trp < &vcpu->arch.itrs[NITRS]; trp++)
		if (trp->pte.p)
			vcpu_quick_region_set(vcpu->arch.itr_regions,
			                      trp->vadr);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_set_dtr(VCPU * vcpu, u64 slot, u64 pte,
                       u64 itir, u64 ifa, u64 rid)
{
	TR_ENTRY *trp;

	if (slot >= NDTRS)
		return IA64_RSVDREG_FAULT;
	trp = &PSCBX(vcpu, dtrs[slot]);
	vcpu_set_tr_entry_rid(trp, pte, itir, ifa, rid);

	/* Recompute the dtr_region.  */
	vcpu->arch.dtr_regions = 0;
	for (trp = vcpu->arch.dtrs; trp < &vcpu->arch.dtrs[NDTRS]; trp++)
		if (trp->pte.p)
			vcpu_quick_region_set(vcpu->arch.dtr_regions,
			                      trp->vadr);
	return IA64_NO_FAULT;
}

/**************************************************************************
 VCPU translation cache access routines
**************************************************************************/

void
vcpu_itc_no_srlz(VCPU * vcpu, u64 IorD, u64 vaddr, u64 pte,
                 u64 mp_pte, u64 logps, struct p2m_entry *entry)
{
	unsigned long psr;
	unsigned long ps = (vcpu->domain == dom0) ? logps : PAGE_SHIFT;

	check_xen_space_overlap("itc", vaddr, 1UL << logps);

	// FIXME, must be inlined or potential for nested fault here!
	if ((vcpu->domain == dom0) && (logps < PAGE_SHIFT))
		panic_domain(NULL, "vcpu_itc_no_srlz: domain trying to use "
		             "smaller page size!\n");

	BUG_ON(logps > PAGE_SHIFT);
	vcpu_tlb_track_insert_or_dirty(vcpu, vaddr, entry);
	psr = ia64_clear_ic();
	pte &= ~(_PAGE_RV2 | _PAGE_RV1);	// Mask out the reserved bits.
	ia64_itc(IorD, vaddr, pte, ps);	// FIXME: look for bigger mappings
	ia64_set_psr(psr);
	// ia64_srlz_i(); // no srls req'd, will rfi later
#ifdef VHPT_GLOBAL
	if (vcpu->domain == dom0 && ((vaddr >> 61) == 7)) {
		// FIXME: this is dangerous... vhpt_flush_address ensures these
		// addresses never get flushed.  More work needed if this
		// ever happens.
//printk("vhpt_insert(%p,%p,%p)\n",vaddr,pte,1L<<logps);
		if (logps > PAGE_SHIFT)
			vhpt_multiple_insert(vaddr, pte, logps);
		else
			vhpt_insert(vaddr, pte, logps << 2);
	}
	// even if domain pagesize is larger than PAGE_SIZE, just put
	// PAGE_SIZE mapping in the vhpt for now, else purging is complicated
	else
		vhpt_insert(vaddr, pte, PAGE_SHIFT << 2);
#endif
}

IA64FAULT vcpu_itc_d(VCPU * vcpu, u64 pte, u64 itir, u64 ifa)
{
	unsigned long pteval, logps = itir_ps(itir);
	BOOLEAN swap_rr0 = (!(ifa >> 61) && PSCB(vcpu, metaphysical_mode));
	struct p2m_entry entry;

	if (logps < PAGE_SHIFT)
		panic_domain(NULL, "vcpu_itc_d: domain trying to use "
		             "smaller page size!\n");

 again:
	//itir = (itir & ~0xfc) | (PAGE_SHIFT<<2); // ignore domain's pagesize
	pteval = translate_domain_pte(pte, ifa, itir, &logps, &entry);
	if (!pteval)
		return IA64_ILLOP_FAULT;
	if (swap_rr0)
		set_one_rr(0x0, PSCB(vcpu, rrs[0]));
	vcpu_itc_no_srlz(vcpu, 2, ifa, pteval, pte, logps, &entry);
	if (swap_rr0)
		set_metaphysical_rr0();
	if (p2m_entry_retry(&entry)) {
		vcpu_flush_tlb_vhpt_range(ifa, logps);
		goto again;
	}
	vcpu_set_tr_entry(&PSCBX(vcpu, dtlb), pte, itir, ifa);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_itc_i(VCPU * vcpu, u64 pte, u64 itir, u64 ifa)
{
	unsigned long pteval, logps = itir_ps(itir);
	BOOLEAN swap_rr0 = (!(ifa >> 61) && PSCB(vcpu, metaphysical_mode));
	struct p2m_entry entry;

	if (logps < PAGE_SHIFT)
		panic_domain(NULL, "vcpu_itc_i: domain trying to use "
		             "smaller page size!\n");
      again:
	//itir = (itir & ~0xfc) | (PAGE_SHIFT<<2); // ignore domain's pagesize
	pteval = translate_domain_pte(pte, ifa, itir, &logps, &entry);
	if (!pteval)
		return IA64_ILLOP_FAULT;
	if (swap_rr0)
		set_one_rr(0x0, PSCB(vcpu, rrs[0]));
	vcpu_itc_no_srlz(vcpu, 1, ifa, pteval, pte, logps, &entry);
	if (swap_rr0)
		set_metaphysical_rr0();
	if (p2m_entry_retry(&entry)) {
		vcpu_flush_tlb_vhpt_range(ifa, logps);
		goto again;
	}
	vcpu_set_tr_entry(&PSCBX(vcpu, itlb), pte, itir, ifa);
	return IA64_NO_FAULT;
}

IA64FAULT vcpu_ptc_l(VCPU * vcpu, u64 vadr, u64 log_range)
{
	BUG_ON(vcpu != current);

	check_xen_space_overlap("ptc_l", vadr, 1UL << log_range);

	/* Purge TC  */
	vcpu_purge_tr_entry(&PSCBX(vcpu, dtlb));
	vcpu_purge_tr_entry(&PSCBX(vcpu, itlb));

	/* Purge all tlb and vhpt */
	vcpu_flush_tlb_vhpt_range(vadr, log_range);

	return IA64_NO_FAULT;
}

// At privlvl=0, fc performs no access rights or protection key checks, while
// at privlvl!=0, fc performs access rights checks as if it were a 1-byte
// read but no protection key check.  Thus in order to avoid an unexpected
// access rights fault, we have to translate the virtual address to a
// physical address (possibly via a metaphysical address) and do the fc
// on the physical address, which is guaranteed to flush the same cache line
IA64FAULT vcpu_fc(VCPU * vcpu, u64 vadr)
{
	// TODO: Only allowed for current vcpu
	u64 mpaddr, paddr;
	IA64FAULT fault;

      again:
	fault = vcpu_tpa(vcpu, vadr, &mpaddr);
	if (fault == IA64_NO_FAULT) {
		struct p2m_entry entry;
		paddr = translate_domain_mpaddr(mpaddr, &entry);
		ia64_fc(__va(paddr));
		if (p2m_entry_retry(&entry))
			goto again;
	}
	return fault;
}

IA64FAULT vcpu_ptc_e(VCPU * vcpu, u64 vadr)
{
	// Note that this only needs to be called once, i.e. the
	// architected loop to purge the entire TLB, should use
	//  base = stride1 = stride2 = 0, count0 = count 1 = 1

	vcpu_flush_vtlb_all(current);

	return IA64_NO_FAULT;
}

IA64FAULT vcpu_ptc_g(VCPU * vcpu, u64 vadr, u64 addr_range)
{
	printk("vcpu_ptc_g: called, not implemented yet\n");
	return IA64_ILLOP_FAULT;
}

IA64FAULT vcpu_ptc_ga(VCPU * vcpu, u64 vadr, u64 addr_range)
{
	// FIXME: validate not flushing Xen addresses
	// if (Xen address) return(IA64_ILLOP_FAULT);
	// FIXME: ??breaks if domain PAGE_SIZE < Xen PAGE_SIZE
//printk("######## vcpu_ptc_ga(%p,%p) ##############\n",vadr,addr_range);

	check_xen_space_overlap("ptc_ga", vadr, addr_range);

	domain_flush_vtlb_range(vcpu->domain, vadr, addr_range);

	return IA64_NO_FAULT;
}

IA64FAULT vcpu_ptr_d(VCPU * vcpu, u64 vadr, u64 log_range)
{
	unsigned long region = vadr >> 61;
	u64 addr_range = 1UL << log_range;
	unsigned long rid, rr;
	int i;
	TR_ENTRY *trp;

	BUG_ON(vcpu != current);
	check_xen_space_overlap("ptr_d", vadr, 1UL << log_range);

	rr = PSCB(vcpu, rrs)[region];
	rid = rr & RR_RID_MASK;

	/* Purge TC  */
	vcpu_purge_tr_entry(&PSCBX(vcpu, dtlb));

	/* Purge tr and recompute dtr_regions.  */
	vcpu->arch.dtr_regions = 0;
	for (trp = vcpu->arch.dtrs, i = NDTRS; i; i--, trp++)
		if (vcpu_match_tr_entry_range
		    (trp, rid, vadr, vadr + addr_range))
			vcpu_purge_tr_entry(trp);
		else if (trp->pte.p)
			vcpu_quick_region_set(vcpu->arch.dtr_regions,
					      trp->vadr);

	vcpu_flush_tlb_vhpt_range(vadr, log_range);

	return IA64_NO_FAULT;
}

IA64FAULT vcpu_ptr_i(VCPU * vcpu, u64 vadr, u64 log_range)
{
	unsigned long region = vadr >> 61;
	u64 addr_range = 1UL << log_range;
	unsigned long rid, rr;
	int i;
	TR_ENTRY *trp;

	BUG_ON(vcpu != current);
	check_xen_space_overlap("ptr_i", vadr, 1UL << log_range);

	rr = PSCB(vcpu, rrs)[region];
	rid = rr & RR_RID_MASK;

	/* Purge TC  */
	vcpu_purge_tr_entry(&PSCBX(vcpu, itlb));

	/* Purge tr and recompute itr_regions.  */
	vcpu->arch.itr_regions = 0;
	for (trp = vcpu->arch.itrs, i = NITRS; i; i--, trp++)
		if (vcpu_match_tr_entry_range
		    (trp, rid, vadr, vadr + addr_range))
			vcpu_purge_tr_entry(trp);
		else if (trp->pte.p)
			vcpu_quick_region_set(vcpu->arch.itr_regions,
					      trp->vadr);

	vcpu_flush_tlb_vhpt_range(vadr, log_range);

	return IA64_NO_FAULT;
}
