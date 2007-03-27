/*
 * Privileged operation "API" handling functions.
 * 
 * Copyright (C) 2004 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <asm/privop.h>
#include <asm/vcpu.h>
#include <asm/processor.h>
#include <asm/delay.h>		// Debug only
#include <asm/dom_fw.h>
#include <asm/vhpt.h>
#include <asm/bundle.h>
#include <xen/perfc.h>

long priv_verbose = 0;
unsigned long privop_trace = 0;

/* Set to 1 to handle privified instructions from the privify tool. */
#ifndef CONFIG_PRIVIFY
static const int privify_en = 0;
#else
static const int privify_en = 1;
#endif

/**************************************************************************
Privileged operation emulation routines
**************************************************************************/

static IA64FAULT priv_rfi(VCPU * vcpu, INST64 inst)
{
	return vcpu_rfi(vcpu);
}

static IA64FAULT priv_bsw0(VCPU * vcpu, INST64 inst)
{
	return vcpu_bsw0(vcpu);
}

static IA64FAULT priv_bsw1(VCPU * vcpu, INST64 inst)
{
	return vcpu_bsw1(vcpu);
}

static IA64FAULT priv_cover(VCPU * vcpu, INST64 inst)
{
	return vcpu_cover(vcpu);
}

static IA64FAULT priv_ptc_l(VCPU * vcpu, INST64 inst)
{
	u64 vadr = vcpu_get_gr(vcpu, inst.M45.r3);
	u64 log_range;

	log_range = ((vcpu_get_gr(vcpu, inst.M45.r2) & 0xfc) >> 2);
	return vcpu_ptc_l(vcpu, vadr, log_range);
}

static IA64FAULT priv_ptc_e(VCPU * vcpu, INST64 inst)
{
	unsigned int src = inst.M28.r3;

	// NOTE: ptc_e with source gr > 63 is emulated as a fc r(y-64)
	if (privify_en && src > 63)
		return vcpu_fc(vcpu, vcpu_get_gr(vcpu, src - 64));
	return vcpu_ptc_e(vcpu, vcpu_get_gr(vcpu, src));
}

static IA64FAULT priv_ptc_g(VCPU * vcpu, INST64 inst)
{
	u64 vadr = vcpu_get_gr(vcpu, inst.M45.r3);
	u64 addr_range;

	addr_range = 1 << ((vcpu_get_gr(vcpu, inst.M45.r2) & 0xfc) >> 2);
	return vcpu_ptc_g(vcpu, vadr, addr_range);
}

static IA64FAULT priv_ptc_ga(VCPU * vcpu, INST64 inst)
{
	u64 vadr = vcpu_get_gr(vcpu, inst.M45.r3);
	u64 addr_range;

	addr_range = 1 << ((vcpu_get_gr(vcpu, inst.M45.r2) & 0xfc) >> 2);
	return vcpu_ptc_ga(vcpu, vadr, addr_range);
}

static IA64FAULT priv_ptr_d(VCPU * vcpu, INST64 inst)
{
	u64 vadr = vcpu_get_gr(vcpu, inst.M45.r3);
	u64 log_range;

	log_range = (vcpu_get_gr(vcpu, inst.M45.r2) & 0xfc) >> 2;
	return vcpu_ptr_d(vcpu, vadr, log_range);
}

static IA64FAULT priv_ptr_i(VCPU * vcpu, INST64 inst)
{
	u64 vadr = vcpu_get_gr(vcpu, inst.M45.r3);
	u64 log_range;

	log_range = (vcpu_get_gr(vcpu, inst.M45.r2) & 0xfc) >> 2;
	return vcpu_ptr_i(vcpu, vadr, log_range);
}

static IA64FAULT priv_tpa(VCPU * vcpu, INST64 inst)
{
	u64 padr;
	unsigned int fault;
	unsigned int src = inst.M46.r3;

	// NOTE: tpa with source gr > 63 is emulated as a ttag rx=r(y-64)
	if (privify_en && src > 63)
		fault = vcpu_ttag(vcpu, vcpu_get_gr(vcpu, src - 64), &padr);
	else
		fault = vcpu_tpa(vcpu, vcpu_get_gr(vcpu, src), &padr);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M46.r1, padr, 0);
	else
		return fault;
}

static IA64FAULT priv_tak(VCPU * vcpu, INST64 inst)
{
	u64 key;
	unsigned int fault;
	unsigned int src = inst.M46.r3;

	// NOTE: tak with source gr > 63 is emulated as a thash rx=r(y-64)
	if (privify_en && src > 63)
		fault = vcpu_thash(vcpu, vcpu_get_gr(vcpu, src - 64), &key);
	else
		fault = vcpu_tak(vcpu, vcpu_get_gr(vcpu, src), &key);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M46.r1, key, 0);
	else
		return fault;
}

/************************************
 * Insert translation register/cache
************************************/

static IA64FAULT priv_itr_d(VCPU * vcpu, INST64 inst)
{
	u64 fault, itir, ifa, pte, slot;

	//if (!vcpu_get_psr_ic(vcpu))
	//      return IA64_ILLOP_FAULT;
	fault = vcpu_get_itir(vcpu, &itir);
	if (fault != IA64_NO_FAULT)
		return IA64_ILLOP_FAULT;
	fault = vcpu_get_ifa(vcpu, &ifa);
	if (fault != IA64_NO_FAULT)
		return IA64_ILLOP_FAULT;
	pte = vcpu_get_gr(vcpu, inst.M42.r2);
	slot = vcpu_get_gr(vcpu, inst.M42.r3);

	return vcpu_itr_d(vcpu, slot, pte, itir, ifa);
}

static IA64FAULT priv_itr_i(VCPU * vcpu, INST64 inst)
{
	u64 fault, itir, ifa, pte, slot;

	//if (!vcpu_get_psr_ic(vcpu)) return IA64_ILLOP_FAULT;
	fault = vcpu_get_itir(vcpu, &itir);
	if (fault != IA64_NO_FAULT)
		return IA64_ILLOP_FAULT;
	fault = vcpu_get_ifa(vcpu, &ifa);
	if (fault != IA64_NO_FAULT)
		return IA64_ILLOP_FAULT;
	pte = vcpu_get_gr(vcpu, inst.M42.r2);
	slot = vcpu_get_gr(vcpu, inst.M42.r3);

	return vcpu_itr_i(vcpu, slot, pte, itir, ifa);
}

static IA64FAULT priv_itc_d(VCPU * vcpu, INST64 inst)
{
	u64 fault, itir, ifa, pte;

	//if (!vcpu_get_psr_ic(vcpu)) return IA64_ILLOP_FAULT;
	fault = vcpu_get_itir(vcpu, &itir);
	if (fault != IA64_NO_FAULT)
		return IA64_ILLOP_FAULT;
	fault = vcpu_get_ifa(vcpu, &ifa);
	if (fault != IA64_NO_FAULT)
		return IA64_ILLOP_FAULT;
	pte = vcpu_get_gr(vcpu, inst.M41.r2);

	return vcpu_itc_d(vcpu, pte, itir, ifa);
}

static IA64FAULT priv_itc_i(VCPU * vcpu, INST64 inst)
{
	u64 fault, itir, ifa, pte;

	//if (!vcpu_get_psr_ic(vcpu)) return IA64_ILLOP_FAULT;
	fault = vcpu_get_itir(vcpu, &itir);
	if (fault != IA64_NO_FAULT)
		return IA64_ILLOP_FAULT;
	fault = vcpu_get_ifa(vcpu, &ifa);
	if (fault != IA64_NO_FAULT)
		return IA64_ILLOP_FAULT;
	pte = vcpu_get_gr(vcpu, inst.M41.r2);

	return vcpu_itc_i(vcpu, pte, itir, ifa);
}

/*************************************
 * Moves to semi-privileged registers
*************************************/

static IA64FAULT priv_mov_to_ar_imm(VCPU * vcpu, INST64 inst)
{
	// I27 and M30 are identical for these fields
	u64 ar3 = inst.M30.ar3;
	u64 imm = vcpu_get_gr(vcpu, inst.M30.imm);
	return vcpu_set_ar(vcpu, ar3, imm);
}

static IA64FAULT priv_mov_to_ar_reg(VCPU * vcpu, INST64 inst)
{
	// I26 and M29 are identical for these fields
	u64 ar3 = inst.M29.ar3;

	if (privify_en && inst.M29.r2 > 63 && inst.M29.ar3 < 8) {
		// privified mov from kr
		u64 val;
		if (vcpu_get_ar(vcpu, ar3, &val) != IA64_ILLOP_FAULT)
			return vcpu_set_gr(vcpu, inst.M29.r2 - 64, val, 0);
		else
			return IA64_ILLOP_FAULT;
	} else {
		u64 r2 = vcpu_get_gr(vcpu, inst.M29.r2);
		return vcpu_set_ar(vcpu, ar3, r2);
	}
}

/********************************
 * Moves to privileged registers
********************************/

static IA64FAULT priv_mov_to_pkr(VCPU * vcpu, INST64 inst)
{
	u64 r3 = vcpu_get_gr(vcpu, inst.M42.r3);
	u64 r2 = vcpu_get_gr(vcpu, inst.M42.r2);
	return vcpu_set_pkr(vcpu, r3, r2);
}

static IA64FAULT priv_mov_to_rr(VCPU * vcpu, INST64 inst)
{
	u64 r3 = vcpu_get_gr(vcpu, inst.M42.r3);
	u64 r2 = vcpu_get_gr(vcpu, inst.M42.r2);
	return vcpu_set_rr(vcpu, r3, r2);
}

static IA64FAULT priv_mov_to_dbr(VCPU * vcpu, INST64 inst)
{
	u64 r3 = vcpu_get_gr(vcpu, inst.M42.r3);
	u64 r2 = vcpu_get_gr(vcpu, inst.M42.r2);
	return vcpu_set_dbr(vcpu, r3, r2);
}

static IA64FAULT priv_mov_to_ibr(VCPU * vcpu, INST64 inst)
{
	u64 r3 = vcpu_get_gr(vcpu, inst.M42.r3);
	u64 r2 = vcpu_get_gr(vcpu, inst.M42.r2);
	return vcpu_set_ibr(vcpu, r3, r2);
}

static IA64FAULT priv_mov_to_pmc(VCPU * vcpu, INST64 inst)
{
	u64 r3 = vcpu_get_gr(vcpu, inst.M42.r3);
	u64 r2 = vcpu_get_gr(vcpu, inst.M42.r2);
	return vcpu_set_pmc(vcpu, r3, r2);
}

static IA64FAULT priv_mov_to_pmd(VCPU * vcpu, INST64 inst)
{
	u64 r3 = vcpu_get_gr(vcpu, inst.M42.r3);
	u64 r2 = vcpu_get_gr(vcpu, inst.M42.r2);
	return vcpu_set_pmd(vcpu, r3, r2);
}

static IA64FAULT priv_mov_to_cr(VCPU * vcpu, INST64 inst)
{
	u64 val = vcpu_get_gr(vcpu, inst.M32.r2);
	perfc_incra(mov_to_cr, inst.M32.cr3);
	switch (inst.M32.cr3) {
	case 0:
		return vcpu_set_dcr(vcpu, val);
	case 1:
		return vcpu_set_itm(vcpu, val);
	case 2:
		return vcpu_set_iva(vcpu, val);
	case 8:
		return vcpu_set_pta(vcpu, val);
	case 16:
		return vcpu_set_ipsr(vcpu, val);
	case 17:
		return vcpu_set_isr(vcpu, val);
	case 19:
		return vcpu_set_iip(vcpu, val);
	case 20:
		return vcpu_set_ifa(vcpu, val);
	case 21:
		return vcpu_set_itir(vcpu, val);
	case 22:
		return vcpu_set_iipa(vcpu, val);
	case 23:
		return vcpu_set_ifs(vcpu, val);
	case 24:
		return vcpu_set_iim(vcpu, val);
	case 25:
		return vcpu_set_iha(vcpu, val);
	case 64:
		return vcpu_set_lid(vcpu, val);
	case 65:
		return IA64_ILLOP_FAULT;
	case 66:
		return vcpu_set_tpr(vcpu, val);
	case 67:
		return vcpu_set_eoi(vcpu, val);
	case 68:
		return IA64_ILLOP_FAULT;
	case 69:
		return IA64_ILLOP_FAULT;
	case 70:
		return IA64_ILLOP_FAULT;
	case 71:
		return IA64_ILLOP_FAULT;
	case 72:
		return vcpu_set_itv(vcpu, val);
	case 73:
		return vcpu_set_pmv(vcpu, val);
	case 74:
		return vcpu_set_cmcv(vcpu, val);
	case 80:
		return vcpu_set_lrr0(vcpu, val);
	case 81:
		return vcpu_set_lrr1(vcpu, val);
	default:
		return IA64_ILLOP_FAULT;
	}
}

static IA64FAULT priv_rsm(VCPU * vcpu, INST64 inst)
{
	u64 imm24 = (inst.M44.i << 23) | (inst.M44.i2 << 21) | inst.M44.imm;
	return vcpu_reset_psr_sm(vcpu, imm24);
}

static IA64FAULT priv_ssm(VCPU * vcpu, INST64 inst)
{
	u64 imm24 = (inst.M44.i << 23) | (inst.M44.i2 << 21) | inst.M44.imm;
	return vcpu_set_psr_sm(vcpu, imm24);
}

/**
 * @todo Check for reserved bits and return IA64_RSVDREG_FAULT.
 */
static IA64FAULT priv_mov_to_psr(VCPU * vcpu, INST64 inst)
{
	u64 val = vcpu_get_gr(vcpu, inst.M35.r2);
	return vcpu_set_psr_l(vcpu, val);
}

/**********************************
 * Moves from privileged registers
 **********************************/

static IA64FAULT priv_mov_from_rr(VCPU * vcpu, INST64 inst)
{
	u64 val;
	IA64FAULT fault;
	u64 reg;

	reg = vcpu_get_gr(vcpu, inst.M43.r3);
	if (privify_en && inst.M43.r1 > 63) {
		// privified mov from cpuid
		fault = vcpu_get_cpuid(vcpu, reg, &val);
		if (fault == IA64_NO_FAULT)
			return vcpu_set_gr(vcpu, inst.M43.r1 - 64, val, 0);
	} else {
		fault = vcpu_get_rr(vcpu, reg, &val);
		if (fault == IA64_NO_FAULT)
			return vcpu_set_gr(vcpu, inst.M43.r1, val, 0);
	}
	return fault;
}

static IA64FAULT priv_mov_from_pkr(VCPU * vcpu, INST64 inst)
{
	u64 val;
	IA64FAULT fault;

	fault = vcpu_get_pkr(vcpu, vcpu_get_gr(vcpu, inst.M43.r3), &val);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M43.r1, val, 0);
	else
		return fault;
}

static IA64FAULT priv_mov_from_dbr(VCPU * vcpu, INST64 inst)
{
	u64 val;
	IA64FAULT fault;

	fault = vcpu_get_dbr(vcpu, vcpu_get_gr(vcpu, inst.M43.r3), &val);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M43.r1, val, 0);
	else
		return fault;
}

static IA64FAULT priv_mov_from_ibr(VCPU * vcpu, INST64 inst)
{
	u64 val;
	IA64FAULT fault;

	fault = vcpu_get_ibr(vcpu, vcpu_get_gr(vcpu, inst.M43.r3), &val);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M43.r1, val, 0);
	else
		return fault;
}

static IA64FAULT priv_mov_from_pmc(VCPU * vcpu, INST64 inst)
{
	u64 val;
	IA64FAULT fault;
	u64 reg;

	reg = vcpu_get_gr(vcpu, inst.M43.r3);
	if (privify_en && inst.M43.r1 > 63) {
		// privified mov from pmd
		fault = vcpu_get_pmd(vcpu, reg, &val);
		if (fault == IA64_NO_FAULT)
			return vcpu_set_gr(vcpu, inst.M43.r1 - 64, val, 0);
	} else {
		fault = vcpu_get_pmc(vcpu, reg, &val);
		if (fault == IA64_NO_FAULT)
			return vcpu_set_gr(vcpu, inst.M43.r1, val, 0);
	}
	return fault;
}

#define cr_get(cr) \
	((fault = vcpu_get_##cr(vcpu,&val)) == IA64_NO_FAULT) ? \
		vcpu_set_gr(vcpu, tgt, val, 0) : fault;

static IA64FAULT priv_mov_from_cr(VCPU * vcpu, INST64 inst)
{
	u64 tgt = inst.M33.r1;
	u64 val;
	IA64FAULT fault;

	perfc_incra(mov_from_cr, inst.M33.cr3);
	switch (inst.M33.cr3) {
	case 0:
		return cr_get(dcr);
	case 1:
		return cr_get(itm);
	case 2:
		return cr_get(iva);
	case 8:
		return cr_get(pta);
	case 16:
		return cr_get(ipsr);
	case 17:
		return cr_get(isr);
	case 19:
		return cr_get(iip);
	case 20:
		return cr_get(ifa);
	case 21:
		return cr_get(itir);
	case 22:
		return cr_get(iipa);
	case 23:
		return cr_get(ifs);
	case 24:
		return cr_get(iim);
	case 25:
		return cr_get(iha);
	case 64:
		return cr_get(lid);
	case 65:
		return cr_get(ivr);
	case 66:
		return cr_get(tpr);
	case 67:
		return vcpu_set_gr(vcpu, tgt, 0L, 0);
	case 68:
		return cr_get(irr0);
	case 69:
		return cr_get(irr1);
	case 70:
		return cr_get(irr2);
	case 71:
		return cr_get(irr3);
	case 72:
		return cr_get(itv);
	case 73:
		return cr_get(pmv);
	case 74:
		return cr_get(cmcv);
	case 80:
		return cr_get(lrr0);
	case 81:
		return cr_get(lrr1);
	default:
		return IA64_ILLOP_FAULT;
	}
	return IA64_ILLOP_FAULT;
}

static IA64FAULT priv_mov_from_psr(VCPU * vcpu, INST64 inst)
{
	u64 tgt = inst.M33.r1;
	u64 val;
	IA64FAULT fault;

	fault = vcpu_get_psr(vcpu, &val);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, tgt, val, 0);
	else
		return fault;
}

/**************************************************************************
Privileged operation decode and dispatch routines
**************************************************************************/

static const IA64_SLOT_TYPE slot_types[0x20][3] = {
	{M, I, I}, {M, I, I}, {M, I, I}, {M, I, I},
	{M, I, ILLEGAL}, {M, I, ILLEGAL},
	{ILLEGAL, ILLEGAL, ILLEGAL}, {ILLEGAL, ILLEGAL, ILLEGAL},
	{M, M, I}, {M, M, I}, {M, M, I}, {M, M, I},
	{M, F, I}, {M, F, I},
	{M, M, F}, {M, M, F},
	{M, I, B}, {M, I, B},
	{M, B, B}, {M, B, B},
	{ILLEGAL, ILLEGAL, ILLEGAL}, {ILLEGAL, ILLEGAL, ILLEGAL},
	{B, B, B}, {B, B, B},
	{M, M, B}, {M, M, B},
	{ILLEGAL, ILLEGAL, ILLEGAL}, {ILLEGAL, ILLEGAL, ILLEGAL},
	{M, F, B}, {M, F, B},
	{ILLEGAL, ILLEGAL, ILLEGAL}, {ILLEGAL, ILLEGAL, ILLEGAL}
};

// pointer to privileged emulation function
typedef IA64FAULT(*PPEFCN) (VCPU * vcpu, INST64 inst);

static const PPEFCN Mpriv_funcs[64] = {
	priv_mov_to_rr, priv_mov_to_dbr, priv_mov_to_ibr, priv_mov_to_pkr,
	priv_mov_to_pmc, priv_mov_to_pmd, 0, 0,
	0, priv_ptc_l, priv_ptc_g, priv_ptc_ga,
	priv_ptr_d, priv_ptr_i, priv_itr_d, priv_itr_i,
	priv_mov_from_rr, priv_mov_from_dbr, priv_mov_from_ibr,
	priv_mov_from_pkr,
	priv_mov_from_pmc, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, priv_tpa, priv_tak,
	0, 0, 0, 0,
	priv_mov_from_cr, priv_mov_from_psr, 0, 0,
	0, 0, 0, 0,
	priv_mov_to_cr, priv_mov_to_psr, priv_itc_d, priv_itc_i,
	0, 0, 0, 0,
	priv_ptc_e, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0
};

static IA64FAULT priv_handle_op(VCPU * vcpu, REGS * regs, int privlvl)
{
	IA64_BUNDLE bundle;
	int slot;
	IA64_SLOT_TYPE slot_type;
	INST64 inst;
	PPEFCN pfunc;
	unsigned long ipsr = regs->cr_ipsr;
	u64 iip = regs->cr_iip;
	int x6;

	// make a local copy of the bundle containing the privop
	if (!vcpu_get_domain_bundle(vcpu, regs, iip, &bundle)) {
		//return vcpu_force_data_miss(vcpu, regs->cr_iip);
		return vcpu_force_inst_miss(vcpu, regs->cr_iip);
	}
#if 0
	if (iip == 0xa000000100001820) {
		static int firstpagefault = 1;
		if (firstpagefault) {
			printk("*** First time to domain page fault!\n");
			firstpagefault = 0;
		}
	}
#endif
	if (privop_trace) {
		static long i = 400;
		//if (i > 0) printk("priv_handle_op: at 0x%lx\n",iip);
		if (i > 0)
			printk("priv_handle_op: privop trace at 0x%lx, "
			       "itc=%lx, itm=%lx\n",
			       iip, ia64_get_itc(), ia64_get_itm());
		i--;
	}
	slot = ((struct ia64_psr *)&ipsr)->ri;
	if (!slot)
		inst.inst = (bundle.i64[0] >> 5) & MASK_41;
	else if (slot == 1)
		inst.inst =
		    ((bundle.i64[0] >> 46) | bundle.i64[1] << 18) & MASK_41;
	else if (slot == 2)
		inst.inst = (bundle.i64[1] >> 23) & MASK_41;
	else
		printk("priv_handle_op: illegal slot: %d\n", slot);

	slot_type = slot_types[bundle.template][slot];
	if (priv_verbose) {
		printk("priv_handle_op: checking bundle at 0x%lx "
		       "(op=0x%016lx) slot %d (type=%d)\n",
		       iip, (u64) inst.inst, slot, slot_type);
	}
	if (slot_type == B && inst.generic.major == 0 && inst.B8.x6 == 0x0) {
		// break instr for privified cover
	} else if (privlvl != 2)
		return IA64_ILLOP_FAULT;
	switch (slot_type) {
	case M:
		if (inst.generic.major == 0) {
#if 0
			if (inst.M29.x6 == 0 && inst.M29.x3 == 0) {
				privcnt.cover++;
				return priv_cover(vcpu, inst);
			}
#endif
			if (inst.M29.x3 != 0)
				break;
			if (inst.M30.x4 == 8 && inst.M30.x2 == 2) {
				perfc_incr(mov_to_ar_imm);
				return priv_mov_to_ar_imm(vcpu, inst);
			}
			if (inst.M44.x4 == 6) {
				perfc_incr(ssm);
				return priv_ssm(vcpu, inst);
			}
			if (inst.M44.x4 == 7) {
				perfc_incr(rsm);
				return priv_rsm(vcpu, inst);
			}
			break;
		} else if (inst.generic.major != 1)
			break;
		x6 = inst.M29.x6;
		if (x6 == 0x2a) {
			if (privify_en && inst.M29.r2 > 63 && inst.M29.ar3 < 8)
				perfc_incr(mov_from_ar); // privified mov from kr
			else
				perfc_incr(mov_to_ar_reg);
			return priv_mov_to_ar_reg(vcpu, inst);
		}
		if (inst.M29.x3 != 0)
			break;
		if (!(pfunc = Mpriv_funcs[x6]))
			break;
		if (x6 == 0x1e || x6 == 0x1f) {	// tpa or tak are "special"
			if (privify_en && inst.M46.r3 > 63) {
				if (x6 == 0x1e)
					x6 = 0x1b;
				else
					x6 = 0x1a;
			}
		}
		if (privify_en && x6 == 52 && inst.M28.r3 > 63)
			perfc_incr(fc);
		else if (privify_en && x6 == 16 && inst.M43.r3 > 63)
			perfc_incr(cpuid);
		else
			perfc_incra(misc_privop, x6);
		return (*pfunc) (vcpu, inst);
		break;
	case B:
		if (inst.generic.major != 0)
			break;
		if (inst.B8.x6 == 0x08) {
			IA64FAULT fault;
			perfc_incr(rfi);
			fault = priv_rfi(vcpu, inst);
			if (fault == IA64_NO_FAULT)
				fault = IA64_RFI_IN_PROGRESS;
			return fault;
		}
		if (inst.B8.x6 == 0x0c) {
			perfc_incr(bsw0);
			return priv_bsw0(vcpu, inst);
		}
		if (inst.B8.x6 == 0x0d) {
			perfc_incr(bsw1);
			return priv_bsw1(vcpu, inst);
		}
		if (inst.B8.x6 == 0x0) {
			// break instr for privified cover
			perfc_incr(cover);
			return priv_cover(vcpu, inst);
		}
		break;
	case I:
		if (inst.generic.major != 0)
			break;
#if 0
		if (inst.I26.x6 == 0 && inst.I26.x3 == 0) {
			perfc_incr(cover);
			return priv_cover(vcpu, inst);
		}
#endif
		if (inst.I26.x3 != 0)
			break;	// I26.x3 == I27.x3
		if (inst.I26.x6 == 0x2a) {
			if (privify_en && inst.I26.r2 > 63 && inst.I26.ar3 < 8)
				perfc_incr(mov_from_ar);	// privified mov from kr
			else
				perfc_incr(mov_to_ar_reg);
			return priv_mov_to_ar_reg(vcpu, inst);
		}
		if (inst.I27.x6 == 0x0a) {
			perfc_incr(mov_to_ar_imm);
			return priv_mov_to_ar_imm(vcpu, inst);
		}
		break;
	default:
		break;
	}
	//printk("We who are about do die salute you\n");
	printk("priv_handle_op: can't handle privop at 0x%lx (op=0x%016lx) "
	       "slot %d (type=%d), ipsr=0x%lx\n",
	       iip, (u64) inst.inst, slot, slot_type, ipsr);
	//printk("vtop(0x%lx)==0x%lx\n", iip, tr_vtop(iip));
	//thread_mozambique("privop fault\n");
	return IA64_ILLOP_FAULT;
}

/** Emulate a privileged operation.
 *
 * This should probably return 0 on success and the "trap number"
 * (e.g. illegal operation for bad register, priv op for an
 * instruction that isn't allowed, etc.) on "failure"
 *
 * @param vcpu virtual cpu
 * @param isrcode interrupt service routine code
 * @return fault
 */
IA64FAULT priv_emulate(VCPU * vcpu, REGS * regs, u64 isr)
{
	IA64FAULT fault;
	u64 ipsr = regs->cr_ipsr;
	u64 isrcode = (isr >> 4) & 0xf;
	int privlvl;

	// handle privops masked as illops? and breaks (6)
	if (isrcode != 1 && isrcode != 2 && isrcode != 0 && isrcode != 6) {
		printk("priv_emulate: isrcode != 0 or 1 or 2\n");
		printk("priv_emulate: returning ILLOP, not implemented!\n");
		while (1) ;
		return IA64_ILLOP_FAULT;
	}
	//if (isrcode != 1 && isrcode != 2) return 0;
	privlvl = ia64_get_cpl(ipsr);
	// its OK for a privified-cover to be executed in user-land
	fault = priv_handle_op(vcpu, regs, privlvl);
	if ((fault == IA64_NO_FAULT) || (fault == IA64_EXTINT_VECTOR)) {
		// success!!
		// update iip/ipsr to point to the next instruction
		(void)vcpu_increment_iip(vcpu);
	}
	if (fault == IA64_ILLOP_FAULT)
		printk("priv_emulate: priv_handle_op fails, "
		       "isr=0x%lx iip=%lx\n", isr, regs->cr_iip);
	return fault;
}

/* hyperprivops are generally executed in assembly (with physical psr.ic off)
 * so this code is primarily used for debugging them */
int ia64_hyperprivop(unsigned long iim, REGS * regs)
{
	struct vcpu *v = current;
	u64 val;
	u64 itir, ifa;

	if (!iim || iim > HYPERPRIVOP_MAX) {
		panic_domain(regs, "bad hyperprivop: iim=%lx, iip=0x%lx\n",
			     iim, regs->cr_iip);
		return 1;
	}
	perfc_incra(slow_hyperprivop, iim);
	switch (iim) {
	case HYPERPRIVOP_RFI:
		vcpu_rfi(v);
		return 0;	// don't update iip
	case HYPERPRIVOP_RSM_DT:
		vcpu_reset_psr_dt(v);
		return 1;
	case HYPERPRIVOP_SSM_DT:
		vcpu_set_psr_dt(v);
		return 1;
	case HYPERPRIVOP_COVER:
		vcpu_cover(v);
		return 1;
	case HYPERPRIVOP_ITC_D:
		vcpu_get_itir(v, &itir);
		vcpu_get_ifa(v, &ifa);
		vcpu_itc_d(v, regs->r8, itir, ifa);
		return 1;
	case HYPERPRIVOP_ITC_I:
		vcpu_get_itir(v, &itir);
		vcpu_get_ifa(v, &ifa);
		vcpu_itc_i(v, regs->r8, itir, ifa);
		return 1;
	case HYPERPRIVOP_SSM_I:
		vcpu_set_psr_i(v);
		return 1;
	case HYPERPRIVOP_GET_IVR:
		vcpu_get_ivr(v, &val);
		regs->r8 = val;
		return 1;
	case HYPERPRIVOP_GET_TPR:
		vcpu_get_tpr(v, &val);
		regs->r8 = val;
		return 1;
	case HYPERPRIVOP_SET_TPR:
		vcpu_set_tpr(v, regs->r8);
		return 1;
	case HYPERPRIVOP_EOI:
		vcpu_set_eoi(v, 0L);
		return 1;
	case HYPERPRIVOP_SET_ITM:
		vcpu_set_itm(v, regs->r8);
		return 1;
	case HYPERPRIVOP_THASH:
		vcpu_thash(v, regs->r8, &val);
		regs->r8 = val;
		return 1;
	case HYPERPRIVOP_PTC_GA:
		vcpu_ptc_ga(v, regs->r8, (1L << ((regs->r9 & 0xfc) >> 2)));
		return 1;
	case HYPERPRIVOP_ITR_D:
		vcpu_get_itir(v, &itir);
		vcpu_get_ifa(v, &ifa);
		vcpu_itr_d(v, regs->r8, regs->r9, itir, ifa);
		return 1;
	case HYPERPRIVOP_GET_RR:
		vcpu_get_rr(v, regs->r8, &val);
		regs->r8 = val;
		return 1;
	case HYPERPRIVOP_SET_RR:
		vcpu_set_rr(v, regs->r8, regs->r9);
		return 1;
	case HYPERPRIVOP_SET_KR:
		vcpu_set_ar(v, regs->r8, regs->r9);
		return 1;
	case HYPERPRIVOP_FC:
		vcpu_fc(v, regs->r8);
		return 1;
	case HYPERPRIVOP_GET_CPUID:
		vcpu_get_cpuid(v, regs->r8, &val);
		regs->r8 = val;
		return 1;
	case HYPERPRIVOP_GET_PMD:
		vcpu_get_pmd(v, regs->r8, &val);
		regs->r8 = val;
		return 1;
	case HYPERPRIVOP_GET_EFLAG:
		vcpu_get_ar(v, 24, &val);
		regs->r8 = val;
		return 1;
	case HYPERPRIVOP_SET_EFLAG:
		vcpu_set_ar(v, 24, regs->r8);
		return 1;
	case HYPERPRIVOP_RSM_BE:
		vcpu_reset_psr_sm(v, IA64_PSR_BE);
		return 1;
	case HYPERPRIVOP_GET_PSR:
		vcpu_get_psr(v, &val);
		regs->r8 = val;
		return 1;
	}
	return 0;
}
