/*
 * Privileged operation "API" handling functions.
 * 
 * Copyright (C) 2004 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <asm/privop.h>
#include <asm/privify.h>
#include <asm/vcpu.h>
#include <asm/processor.h>
#include <asm/delay.h>	// Debug only
//#include <debug.h>

long priv_verbose=0;

/**************************************************************************
Hypercall bundle creation
**************************************************************************/


void build_hypercall_bundle(UINT64 *imva, UINT64 breakimm, UINT64 hypnum, UINT64 ret)
{
	INST64_A5 slot0;
	INST64_I19 slot1;
	INST64_B4 slot2;
	IA64_BUNDLE bundle;

	// slot1: mov r2 = hypnum (low 20 bits)
	slot0.inst = 0;
	slot0.qp = 0; slot0.r1 = 2; slot0.r3 = 0; slot0.major = 0x9;
	slot0.imm7b = hypnum; slot0.imm9d = hypnum >> 7;
	slot0.imm5c = hypnum >> 16; slot0.s = 0;
	// slot1: break breakimm
	slot1.inst = 0;
	slot1.qp = 0; slot1.x6 = 0; slot1.x3 = 0; slot1.major = 0x0;
	slot1.imm20 = breakimm; slot1.i = breakimm >> 20;
	// if ret slot2: br.ret.sptk.many rp
	// else slot2: br.cond.sptk.many rp
	slot2.inst = 0; slot2.qp = 0; slot2.p = 1; slot2.b2 = 0;
	slot2.wh = 0; slot2.d = 0; slot2.major = 0x0;
	if (ret) {
		slot2.btype = 4; slot2.x6 = 0x21;
	}
	else {
		slot2.btype = 0; slot2.x6 = 0x20;
	}
	
	bundle.i64[0] = 0; bundle.i64[1] = 0;
	bundle.template = 0x11;
	bundle.slot0 = slot0.inst; bundle.slot2 = slot2.inst;
	bundle.slot1a = slot1.inst; bundle.slot1b = slot1.inst >> 18;
	
	*imva++ = bundle.i64[0]; *imva = bundle.i64[1];
}

/**************************************************************************
Privileged operation emulation routines
**************************************************************************/

IA64FAULT priv_rfi(VCPU *vcpu, INST64 inst)
{
	return vcpu_rfi(vcpu);
}

IA64FAULT priv_bsw0(VCPU *vcpu, INST64 inst)
{
	return vcpu_bsw0(vcpu);
}

IA64FAULT priv_bsw1(VCPU *vcpu, INST64 inst)
{
	return vcpu_bsw1(vcpu);
}

IA64FAULT priv_cover(VCPU *vcpu, INST64 inst)
{
	return vcpu_cover(vcpu);
}

IA64FAULT priv_ptc_l(VCPU *vcpu, INST64 inst)
{
	UINT64 vadr = vcpu_get_gr(vcpu,inst.M45.r3);
	UINT64 addr_range;

	addr_range = 1 << ((vcpu_get_gr(vcpu,inst.M45.r2) & 0xfc) >> 2);
	return vcpu_ptc_l(vcpu,vadr,addr_range);
}

IA64FAULT priv_ptc_e(VCPU *vcpu, INST64 inst)
{
	UINT src = inst.M28.r3;

	// NOTE: ptc_e with source gr > 63 is emulated as a fc r(y-64)
	if (src > 63) return(vcpu_fc(vcpu,vcpu_get_gr(vcpu,src - 64)));
	return vcpu_ptc_e(vcpu,vcpu_get_gr(vcpu,src));
}

IA64FAULT priv_ptc_g(VCPU *vcpu, INST64 inst)
{
	UINT64 vadr = vcpu_get_gr(vcpu,inst.M45.r3);
	UINT64 addr_range;

	addr_range = 1 << ((vcpu_get_gr(vcpu,inst.M45.r2) & 0xfc) >> 2);
	return vcpu_ptc_g(vcpu,vadr,addr_range);
}

IA64FAULT priv_ptc_ga(VCPU *vcpu, INST64 inst)
{
	UINT64 vadr = vcpu_get_gr(vcpu,inst.M45.r3);
	UINT64 addr_range;

	addr_range = 1 << ((vcpu_get_gr(vcpu,inst.M45.r2) & 0xfc) >> 2);
	return vcpu_ptc_ga(vcpu,vadr,addr_range);
}

IA64FAULT priv_ptr_d(VCPU *vcpu, INST64 inst)
{
	UINT64 vadr = vcpu_get_gr(vcpu,inst.M45.r3);
	UINT64 addr_range;

	addr_range = 1 << ((vcpu_get_gr(vcpu,inst.M45.r2) & 0xfc) >> 2);
	return vcpu_ptr_d(vcpu,vadr,addr_range);
}

IA64FAULT priv_ptr_i(VCPU *vcpu, INST64 inst)
{
	UINT64 vadr = vcpu_get_gr(vcpu,inst.M45.r3);
	UINT64 addr_range;

	addr_range = 1 << ((vcpu_get_gr(vcpu,inst.M45.r2) & 0xfc) >> 2);
	return vcpu_ptr_i(vcpu,vadr,addr_range);
}

IA64FAULT priv_tpa(VCPU *vcpu, INST64 inst)
{
	UINT64 padr;
	UINT fault;
	UINT src = inst.M46.r3;

	// NOTE: tpa with source gr > 63 is emulated as a ttag rx=r(y-64)
	if (src > 63)
		fault = vcpu_ttag(vcpu,vcpu_get_gr(vcpu,src-64),&padr);
	else fault = vcpu_tpa(vcpu,vcpu_get_gr(vcpu,src),&padr);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M46.r1, padr);
	else return fault;
}

IA64FAULT priv_tak(VCPU *vcpu, INST64 inst)
{
	UINT64 key;
	UINT fault;
	UINT src = inst.M46.r3;

	// NOTE: tak with source gr > 63 is emulated as a thash rx=r(y-64)
	if (src > 63)
		fault = vcpu_thash(vcpu,vcpu_get_gr(vcpu,src-64),&key);
	else fault = vcpu_tak(vcpu,vcpu_get_gr(vcpu,src),&key);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M46.r1, key);
	else return fault;
}

/************************************
 * Insert translation register/cache
************************************/

IA64FAULT priv_itr_d(VCPU *vcpu, INST64 inst)
{
	UINT64 fault, itir, ifa, pte, slot;

	//if (!vcpu_get_psr_ic(vcpu)) return(IA64_ILLOP_FAULT);
	if ((fault = vcpu_get_itir(vcpu,&itir)) != IA64_NO_FAULT)
		return(IA64_ILLOP_FAULT);
	if ((fault = vcpu_get_ifa(vcpu,&ifa)) != IA64_NO_FAULT)
		return(IA64_ILLOP_FAULT);
	pte = vcpu_get_gr(vcpu,inst.M42.r2);
	slot = vcpu_get_gr(vcpu,inst.M42.r3);

	return (vcpu_itr_d(vcpu,slot,pte,itir,ifa));
}

IA64FAULT priv_itr_i(VCPU *vcpu, INST64 inst)
{
	UINT64 fault, itir, ifa, pte, slot;

	//if (!vcpu_get_psr_ic(vcpu)) return(IA64_ILLOP_FAULT);
	if ((fault = vcpu_get_itir(vcpu,&itir)) != IA64_NO_FAULT)
		return(IA64_ILLOP_FAULT);
	if ((fault = vcpu_get_ifa(vcpu,&ifa)) != IA64_NO_FAULT)
		return(IA64_ILLOP_FAULT);
	pte = vcpu_get_gr(vcpu,inst.M42.r2);
	slot = vcpu_get_gr(vcpu,inst.M42.r3);

	return (vcpu_itr_i(vcpu,slot,pte,itir,ifa));
}

IA64FAULT priv_itc_d(VCPU *vcpu, INST64 inst)
{
	UINT64 fault, itir, ifa, pte;

	//if (!vcpu_get_psr_ic(vcpu)) return(IA64_ILLOP_FAULT);
	if ((fault = vcpu_get_itir(vcpu,&itir)) != IA64_NO_FAULT)
		return(IA64_ILLOP_FAULT);
	if ((fault = vcpu_get_ifa(vcpu,&ifa)) != IA64_NO_FAULT)
		return(IA64_ILLOP_FAULT);
	pte = vcpu_get_gr(vcpu,inst.M41.r2);

	return (vcpu_itc_d(vcpu,pte,itir,ifa));
}

IA64FAULT priv_itc_i(VCPU *vcpu, INST64 inst)
{
	UINT64 fault, itir, ifa, pte;

	//if (!vcpu_get_psr_ic(vcpu)) return(IA64_ILLOP_FAULT);
	if ((fault = vcpu_get_itir(vcpu,&itir)) != IA64_NO_FAULT)
		return(IA64_ILLOP_FAULT);
	if ((fault = vcpu_get_ifa(vcpu,&ifa)) != IA64_NO_FAULT)
		return(IA64_ILLOP_FAULT);
	pte = vcpu_get_gr(vcpu,inst.M41.r2);

	return (vcpu_itc_i(vcpu,pte,itir,ifa));
}

/*************************************
 * Moves to semi-privileged registers
*************************************/

IA64FAULT priv_mov_to_ar_imm(VCPU *vcpu, INST64 inst)
{
	// I27 and M30 are identical for these fields
	UINT64 ar3 = inst.M30.ar3;
	UINT64 imm = vcpu_get_gr(vcpu,inst.M30.imm);
	return (vcpu_set_ar(vcpu,ar3,imm));
}

IA64FAULT priv_mov_to_ar_reg(VCPU *vcpu, INST64 inst)
{
	// I26 and M29 are identical for these fields
	UINT64 ar3 = inst.M29.ar3;

	if (inst.M29.r2 > 63 && inst.M29.ar3 < 8) { // privified mov from kr
		UINT64 val;
		if (vcpu_get_ar(vcpu,ar3,&val) != IA64_ILLOP_FAULT)
			return vcpu_set_gr(vcpu, inst.M29.r2-64, val);
		else return IA64_ILLOP_FAULT;
	}
	else {
		UINT64 r2 = vcpu_get_gr(vcpu,inst.M29.r2);
		return (vcpu_set_ar(vcpu,ar3,r2));
	}
}

/********************************
 * Moves to privileged registers
********************************/

IA64FAULT priv_mov_to_pkr(VCPU *vcpu, INST64 inst)
{
	UINT64 r3 = vcpu_get_gr(vcpu,inst.M42.r3);
	UINT64 r2 = vcpu_get_gr(vcpu,inst.M42.r2);
	return (vcpu_set_pkr(vcpu,r3,r2));
}

IA64FAULT priv_mov_to_rr(VCPU *vcpu, INST64 inst)
{
	UINT64 r3 = vcpu_get_gr(vcpu,inst.M42.r3);
	UINT64 r2 = vcpu_get_gr(vcpu,inst.M42.r2);
	return (vcpu_set_rr(vcpu,r3,r2));
}

IA64FAULT priv_mov_to_dbr(VCPU *vcpu, INST64 inst)
{
	UINT64 r3 = vcpu_get_gr(vcpu,inst.M42.r3);
	UINT64 r2 = vcpu_get_gr(vcpu,inst.M42.r2);
	return (vcpu_set_dbr(vcpu,r3,r2));
}

IA64FAULT priv_mov_to_ibr(VCPU *vcpu, INST64 inst)
{
	UINT64 r3 = vcpu_get_gr(vcpu,inst.M42.r3);
	UINT64 r2 = vcpu_get_gr(vcpu,inst.M42.r2);
	return (vcpu_set_ibr(vcpu,r3,r2));
}

IA64FAULT priv_mov_to_pmc(VCPU *vcpu, INST64 inst)
{
	UINT64 r3 = vcpu_get_gr(vcpu,inst.M42.r3);
	UINT64 r2 = vcpu_get_gr(vcpu,inst.M42.r2);
	return (vcpu_set_pmc(vcpu,r3,r2));
}

IA64FAULT priv_mov_to_pmd(VCPU *vcpu, INST64 inst)
{
	UINT64 r3 = vcpu_get_gr(vcpu,inst.M42.r3);
	UINT64 r2 = vcpu_get_gr(vcpu,inst.M42.r2);
	return (vcpu_set_pmd(vcpu,r3,r2));
}

unsigned long to_cr_cnt[128] = { 0 };

IA64FAULT priv_mov_to_cr(VCPU *vcpu, INST64 inst)
{
	UINT64 val = vcpu_get_gr(vcpu, inst.M32.r2);
	to_cr_cnt[inst.M32.cr3]++;
	switch (inst.M32.cr3) {
	    case 0: return vcpu_set_dcr(vcpu,val);
	    case 1: return vcpu_set_itm(vcpu,val);
	    case 2: return vcpu_set_iva(vcpu,val);
	    case 8: return vcpu_set_pta(vcpu,val);
	    case 16:return vcpu_set_ipsr(vcpu,val);
	    case 17:return vcpu_set_isr(vcpu,val);
	    case 19:return vcpu_set_iip(vcpu,val);
	    case 20:return vcpu_set_ifa(vcpu,val);
	    case 21:return vcpu_set_itir(vcpu,val);
	    case 22:return vcpu_set_iipa(vcpu,val);
	    case 23:return vcpu_set_ifs(vcpu,val);
	    case 24:return vcpu_set_iim(vcpu,val);
	    case 25:return vcpu_set_iha(vcpu,val);
	    case 64:return vcpu_set_lid(vcpu,val);
	    case 65:return IA64_ILLOP_FAULT;
	    case 66:return vcpu_set_tpr(vcpu,val);
	    case 67:return vcpu_set_eoi(vcpu,val);
	    case 68:return IA64_ILLOP_FAULT;
	    case 69:return IA64_ILLOP_FAULT;
	    case 70:return IA64_ILLOP_FAULT;
	    case 71:return IA64_ILLOP_FAULT;
	    case 72:return vcpu_set_itv(vcpu,val);
	    case 73:return vcpu_set_pmv(vcpu,val);
	    case 74:return vcpu_set_cmcv(vcpu,val);
	    case 80:return vcpu_set_lrr0(vcpu,val);
	    case 81:return vcpu_set_lrr1(vcpu,val);
	    default: return IA64_ILLOP_FAULT;
	}
}

IA64FAULT priv_rsm(VCPU *vcpu, INST64 inst)
{
	UINT64 imm24 = (inst.M44.i<<23)|(inst.M44.i2<<21)|inst.M44.imm;
	return vcpu_reset_psr_sm(vcpu,imm24);
}

IA64FAULT priv_ssm(VCPU *vcpu, INST64 inst)
{
	UINT64 imm24 = (inst.M44.i<<23)|(inst.M44.i2<<21)|inst.M44.imm;
	return vcpu_set_psr_sm(vcpu,imm24);
}

/**
 * @todo Check for reserved bits and return IA64_RSVDREG_FAULT.
 */
IA64FAULT priv_mov_to_psr(VCPU *vcpu, INST64 inst)
{
	UINT64 val = vcpu_get_gr(vcpu, inst.M35.r2);
	return vcpu_set_psr_l(vcpu,val);
}

/**********************************
 * Moves from privileged registers
 **********************************/

IA64FAULT priv_mov_from_rr(VCPU *vcpu, INST64 inst)
{
	UINT64 val;
	IA64FAULT fault;
	
	if (inst.M43.r1 > 63) { // privified mov from cpuid
		fault = vcpu_get_cpuid(vcpu,vcpu_get_gr(vcpu,inst.M43.r3),&val);
		if (fault == IA64_NO_FAULT)
			return vcpu_set_gr(vcpu, inst.M43.r1-64, val);
	}
	else {
		fault = vcpu_get_rr(vcpu,vcpu_get_gr(vcpu,inst.M43.r3),&val);
		if (fault == IA64_NO_FAULT)
			return vcpu_set_gr(vcpu, inst.M43.r1, val);
	}
	return fault;
}

IA64FAULT priv_mov_from_pkr(VCPU *vcpu, INST64 inst)
{
	UINT64 val;
	IA64FAULT fault;
	
	fault = vcpu_get_pkr(vcpu,vcpu_get_gr(vcpu,inst.M43.r3),&val);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M43.r1, val);
	else return fault;
}

IA64FAULT priv_mov_from_dbr(VCPU *vcpu, INST64 inst)
{
	UINT64 val;
	IA64FAULT fault;
	
	fault = vcpu_get_dbr(vcpu,vcpu_get_gr(vcpu,inst.M43.r3),&val);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M43.r1, val);
	else return fault;
}

IA64FAULT priv_mov_from_ibr(VCPU *vcpu, INST64 inst)
{
	UINT64 val;
	IA64FAULT fault;
	
	fault = vcpu_get_ibr(vcpu,vcpu_get_gr(vcpu,inst.M43.r3),&val);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M43.r1, val);
	else return fault;
}

IA64FAULT priv_mov_from_pmc(VCPU *vcpu, INST64 inst)
{
	UINT64 val;
	IA64FAULT fault;
	
	fault = vcpu_get_pmc(vcpu,vcpu_get_gr(vcpu,inst.M43.r3),&val);
	if (fault == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, inst.M43.r1, val);
	else return fault;
}

unsigned long from_cr_cnt[128] = { 0 };

#define cr_get(cr) \
	((fault = vcpu_get_##cr(vcpu,&val)) == IA64_NO_FAULT) ? \
		vcpu_set_gr(vcpu, tgt, val) : fault;
	
IA64FAULT priv_mov_from_cr(VCPU *vcpu, INST64 inst)
{
	UINT64 tgt = inst.M33.r1;
	UINT64 val;
	IA64FAULT fault;

	from_cr_cnt[inst.M33.cr3]++;
	switch (inst.M33.cr3) {
	    case 0: return cr_get(dcr);
	    case 1: return cr_get(itm);
	    case 2: return cr_get(iva);
	    case 8: return cr_get(pta);
	    case 16:return cr_get(ipsr);
	    case 17:return cr_get(isr);
	    case 19:return cr_get(iip);
	    case 20:return cr_get(ifa);
	    case 21:return cr_get(itir);
	    case 22:return cr_get(iipa);
	    case 23:return cr_get(ifs);
	    case 24:return cr_get(iim);
	    case 25:return cr_get(iha);
	    case 64:return cr_get(lid);
	    case 65:return cr_get(ivr);
	    case 66:return cr_get(tpr);
	    case 67:return vcpu_set_gr(vcpu,tgt,0L);
	    case 68:return cr_get(irr0);
	    case 69:return cr_get(irr1);
	    case 70:return cr_get(irr2);
	    case 71:return cr_get(irr3);
	    case 72:return cr_get(itv);
	    case 73:return cr_get(pmv);
	    case 74:return cr_get(cmcv);
	    case 80:return cr_get(lrr0);
	    case 81:return cr_get(lrr1);
	    default: return IA64_ILLOP_FAULT;
	}
	return IA64_ILLOP_FAULT;
}

IA64FAULT priv_mov_from_psr(VCPU *vcpu, INST64 inst)
{
	UINT64 tgt = inst.M33.r1;
	UINT64 val;
	IA64FAULT fault;

	if ((fault = vcpu_get_psr(vcpu,&val)) == IA64_NO_FAULT)
		return vcpu_set_gr(vcpu, tgt, val);
	else return fault;
}

/**************************************************************************
Privileged operation decode and dispatch routines
**************************************************************************/

IA64_SLOT_TYPE slot_types[0x20][3] = {
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
typedef IA64FAULT (*PPEFCN)(VCPU *vcpu, INST64 inst);

PPEFCN Mpriv_funcs[64] = {
  priv_mov_to_rr, priv_mov_to_dbr, priv_mov_to_ibr, priv_mov_to_pkr,
  priv_mov_to_pmc, priv_mov_to_pmd, 0, 0,
  0, priv_ptc_l, priv_ptc_g, priv_ptc_ga,
  priv_ptr_d, priv_ptr_i, priv_itr_d, priv_itr_i,
  priv_mov_from_rr, priv_mov_from_dbr, priv_mov_from_ibr, priv_mov_from_pkr,
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

struct {
	unsigned long mov_to_ar_imm;
	unsigned long mov_to_ar_reg;
	unsigned long ssm;
	unsigned long rsm;
	unsigned long rfi;
	unsigned long bsw0;
	unsigned long bsw1;
	unsigned long cover;
	unsigned long Mpriv_cnt[64];
} privcnt = { 0 };

unsigned long privop_trace = 0;

IA64FAULT
priv_handle_op(VCPU *vcpu, REGS *regs, int privlvl)
{
	IA64_BUNDLE bundle, __get_domain_bundle(UINT64);
	int slot;
	IA64_SLOT_TYPE slot_type;
	INST64 inst;
	PPEFCN pfunc;
	unsigned long ipsr = regs->cr_ipsr;
	UINT64 iip = regs->cr_iip;
	int x6;
	
	// make a local copy of the bundle containing the privop
#if 1
	bundle = __get_domain_bundle(iip);
	if (!bundle.i64[0] && !bundle.i64[1]) return IA64_RETRY;
#else
#ifdef AVOIDING_POSSIBLE_DOMAIN_TLB_MISS
	//TODO: this needs to check for faults and behave accordingly
	if (!vcpu_get_iip_bundle(&bundle)) return IA64_DTLB_FAULT;
#else
if (iip < 0x10000) {
 printf("priv_handle_op: unlikely iip=%p,b0=%p\n",iip,regs->b0);
 dummy();
}
        bundle = *(IA64_BUNDLE *)iip;
#endif
#endif
#if 0
	if (iip==0xa000000100001820) {
		static int firstpagefault = 1;
		if (firstpagefault) {
			printf("*** First time to domain page fault!\n");				firstpagefault=0;
		}
	}
#endif
	if (privop_trace) {
		static long i = 400;
		//if (i > 0) printf("privop @%p\n",iip);
		if (i > 0) printf("priv_handle_op: @%p, itc=%lx, itm=%lx\n",
			iip,ia64_get_itc(),ia64_get_itm());
		i--;
	}
	slot = ((struct ia64_psr *)&ipsr)->ri;
	if (!slot) inst.inst = (bundle.i64[0]>>5) & MASK_41;
	else if (slot == 1)
		inst.inst = ((bundle.i64[0]>>46) | bundle.i64[1]<<18) & MASK_41;
	else if (slot == 2) inst.inst = (bundle.i64[1]>>23) & MASK_41; 
	else printf("priv_handle_op: illegal slot: %d\n", slot);

	slot_type = slot_types[bundle.template][slot];
	if (priv_verbose) {
		printf("priv_handle_op: checking bundle at 0x%lx (op=0x%016lx) slot %d (type=%d)\n",
		 iip, (UINT64)inst.inst, slot, slot_type);
	}
	if (slot_type == B && inst.generic.major == 0 && inst.B8.x6 == 0x0) {
		// break instr for privified cover
	}
	else if (privlvl != 2) return (IA64_ILLOP_FAULT);
	switch (slot_type) {
	    case M:
		if (inst.generic.major == 0) {
#if 0
			if (inst.M29.x6 == 0 && inst.M29.x3 == 0) {
				privcnt.cover++;
				return priv_cover(vcpu,inst);
			}
#endif
			if (inst.M29.x3 != 0) break;
			if (inst.M30.x4 == 8 && inst.M30.x2 == 2) {
				privcnt.mov_to_ar_imm++;
				return priv_mov_to_ar_imm(vcpu,inst);
			}
			if (inst.M44.x4 == 6) {
				privcnt.ssm++;
				return priv_ssm(vcpu,inst);
			}
			if (inst.M44.x4 == 7) {
				privcnt.rsm++;
				return priv_rsm(vcpu,inst);
			}
			break;
		}
		else if (inst.generic.major != 1) break;
		x6 = inst.M29.x6;
		if (x6 == 0x2a) {
			privcnt.mov_to_ar_reg++;
			return priv_mov_to_ar_reg(vcpu,inst);
		}
		if (inst.M29.x3 != 0) break;
		if (!(pfunc = Mpriv_funcs[x6])) break;
		if (x6 == 0x1e || x6 == 0x1f)  { // tpa or tak are "special"
			if (inst.M46.r3 > 63) {
				if (x6 == 0x1e) x6 = 0x1b;
				else x6 = 0x1a;
			}
		}
		privcnt.Mpriv_cnt[x6]++;
		return (*pfunc)(vcpu,inst);
		break;
	    case B:
		if (inst.generic.major != 0) break;
		if (inst.B8.x6 == 0x08) {
			IA64FAULT fault;
			privcnt.rfi++;
			fault = priv_rfi(vcpu,inst);
			if (fault == IA64_NO_FAULT) fault = IA64_RFI_IN_PROGRESS;
			return fault;
		}
		if (inst.B8.x6 == 0x0c) {
			privcnt.bsw0++;
			return priv_bsw0(vcpu,inst);
		}
		if (inst.B8.x6 == 0x0d) {
			privcnt.bsw1++;
			return priv_bsw1(vcpu,inst);
		}
		if (inst.B8.x6 == 0x0) { // break instr for privified cover
			privcnt.cover++;
			return priv_cover(vcpu,inst);
		}
		break;
	    case I:
		if (inst.generic.major != 0) break;
#if 0
		if (inst.I26.x6 == 0 && inst.I26.x3 == 0) {
			privcnt.cover++;
			return priv_cover(vcpu,inst);
		}
#endif
		if (inst.I26.x3 != 0) break;  // I26.x3 == I27.x3
		if (inst.I26.x6 == 0x2a) {
			privcnt.mov_to_ar_reg++;
			return priv_mov_to_ar_reg(vcpu,inst);
		}
		if (inst.I27.x6 == 0x0a) {
			privcnt.mov_to_ar_imm++;
			return priv_mov_to_ar_imm(vcpu,inst);
		}
		break;
	    default:
		break;
	}
        //printf("We who are about do die salute you\n");
	printf("handle_op: can't handle privop at 0x%lx (op=0x%016lx) slot %d (type=%d)\n",
		 iip, (UINT64)inst.inst, slot, slot_type);
        //printf("vtop(0x%lx)==0x%lx\r\n", iip, tr_vtop(iip));
        //thread_mozambique("privop fault\n");
	return (IA64_ILLOP_FAULT);
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
IA64FAULT
priv_emulate(VCPU *vcpu, REGS *regs, UINT64 isr)
{
	IA64FAULT fault;
	UINT64 ipsr = regs->cr_ipsr;
	UINT64 isrcode = (isr >> 4) & 0xf;
	int privlvl;

	// handle privops masked as illops? and breaks (6)
	if (isrcode != 1 && isrcode != 2 && isrcode != 0 && isrcode != 6) {
        	printf("priv_emulate: isrcode != 0 or 1 or 2\n");
		printf("priv_emulate: returning ILLOP, not implemented!\n");
		while (1);
		return IA64_ILLOP_FAULT;
	}
	//if (isrcode != 1 && isrcode != 2) return 0;
	vcpu_set_regs(vcpu,regs);
	privlvl = (ipsr & IA64_PSR_CPL) >> IA64_PSR_CPL0_BIT;
	// its OK for a privified-cover to be executed in user-land
	fault = priv_handle_op(vcpu,regs,privlvl);
	if (fault == IA64_NO_FAULT) { // success!!
		// update iip/ipsr to point to the next instruction
		(void)vcpu_increment_iip(vcpu);
	}
	else if (fault == IA64_EXTINT_VECTOR) {
		// update iip/ipsr before delivering interrupt
		(void)vcpu_increment_iip(vcpu);
	}
	else if (fault == IA64_RFI_IN_PROGRESS) return fault;
		// success but don't update to next instruction
        else if (fault == IA64_RETRY) {
            //printf("Priv emulate gets IA64_RETRY\n");
	    //printf("priv_emulate: returning RETRY, not implemented!\n");
	    //while (1);
	    // don't update iip/ipsr, deliver 
	
            vcpu_force_data_miss(vcpu,regs->cr_iip);
	    return IA64_RETRY;
        }
	else if (priv_verbose) printf("unhandled operation from handle_op\n");
//	if (fault == IA64_ILLOP_FAULT) {
//		printf("priv_emulate: returning ILLOP, not implemented!\n");
//		while (1);
//	}
	return fault;
}


/**************************************************************************
Privileged operation instrumentation routines
**************************************************************************/

char *Mpriv_str[64] = {
  "mov_to_rr", "mov_to_dbr", "mov_to_ibr", "mov_to_pkr",
  "mov_to_pmc", "mov_to_pmd", "<0x06>", "<0x07>",
  "<0x08>", "ptc_l", "ptc_g", "ptc_ga",
  "ptr_d", "ptr_i", "itr_d", "itr_i",
  "mov_from_rr", "mov_from_dbr", "mov_from_ibr", "mov_from_pkr",
  "mov_from_pmc", "<0x15>", "<0x16>", "<0x17>",
  "<0x18>", "<0x19>", "privified-thash", "privified-ttag",
  "<0x1c>", "<0x1d>", "tpa", "tak",
  "<0x20>", "<0x21>", "<0x22>", "<0x23>",
  "mov_from_cr", "mov_from_psr", "<0x26>", "<0x27>",
  "<0x28>", "<0x29>", "<0x2a>", "<0x2b>",
  "mov_to_cr", "mov_to_psr", "itc_d", "itc_i",
  "<0x30>", "<0x31>", "<0x32>", "<0x33>",
  "ptc_e", "<0x35>", "<0x36>", "<0x37>",
  "<0x38>", "<0x39>", "<0x3a>", "<0x3b>",
  "<0x3c>", "<0x3d>", "<0x3e>", "<0x3f>"
};

#define RS "Rsvd"
char *cr_str[128] = {
  "dcr","itm","iva",RS,RS,RS,RS,RS,
  "pta",RS,RS,RS,RS,RS,RS,RS,
  "ipsr","isr",RS,"iip","ifa","itir","iipa","ifs",
  "iim","iha",RS,RS,RS,RS,RS,RS,
  RS,RS,RS,RS,RS,RS,RS,RS, RS,RS,RS,RS,RS,RS,RS,RS,
  RS,RS,RS,RS,RS,RS,RS,RS, RS,RS,RS,RS,RS,RS,RS,RS,
  "lid","ivr","tpr","eoi","irr0","irr1","irr2","irr3",
  "itv","pmv","cmcv",RS,RS,RS,RS,RS,
  "lrr0","lrr1",RS,RS,RS,RS,RS,RS,
  RS,RS,RS,RS,RS,RS,RS,RS, RS,RS,RS,RS,RS,RS,RS,RS,
  RS,RS,RS,RS,RS,RS,RS,RS, RS,RS,RS,RS,RS,RS,RS,RS,
  RS,RS,RS,RS,RS,RS,RS,RS
};

void dump_privop_counts(void)
{
	int i, j;
	UINT64 sum = 0;

	// this is ugly and should probably produce sorted output
	// but it will have to do for now
	sum += privcnt.mov_to_ar_imm; sum += privcnt.mov_to_ar_reg;
	sum += privcnt.ssm; sum += privcnt.rsm;
	sum += privcnt.rfi; sum += privcnt.bsw0;
	sum += privcnt.bsw1; sum += privcnt.cover;
	for (i=0; i < 64; i++) sum += privcnt.Mpriv_cnt[i];
	printf("Privop statistics: (Total privops: %ld)\r\n",sum);
	if (privcnt.mov_to_ar_imm)
		printf("%10d  %s [%d%%]\r\n", privcnt.mov_to_ar_imm,
			"mov_to_ar_imm", (privcnt.mov_to_ar_imm*100L)/sum);
	if (privcnt.mov_to_ar_reg)
		printf("%10d  %s [%d%%]\r\n", privcnt.mov_to_ar_reg,
			"mov_to_ar_reg", (privcnt.mov_to_ar_reg*100L)/sum);
	if (privcnt.ssm)
		printf("%10d  %s [%d%%]\r\n", privcnt.ssm,
			"ssm", (privcnt.ssm*100L)/sum);
	if (privcnt.rsm)
		printf("%10d  %s [%d%%]\r\n", privcnt.rsm,
			"rsm", (privcnt.rsm*100L)/sum);
	if (privcnt.rfi)
		printf("%10d  %s [%d%%]\r\n", privcnt.rfi,
			"rfi", (privcnt.rfi*100L)/sum);
	if (privcnt.bsw0)
		printf("%10d  %s [%d%%]\r\n", privcnt.bsw0,
			"bsw0", (privcnt.bsw0*100L)/sum);
	if (privcnt.bsw1)
		printf("%10d  %s [%d%%]\r\n", privcnt.bsw1,
			"bsw1", (privcnt.bsw1*100L)/sum);
	if (privcnt.cover)
		printf("%10d  %s [%d%%]\r\n", privcnt.cover,
			"cover", (privcnt.cover*100L)/sum);
	for (i=0; i < 64; i++) if (privcnt.Mpriv_cnt[i]) {
		if (!Mpriv_str[i]) printf("PRIVSTRING NULL!!\r\n");
		else printf("%10d  %s [%d%%]\r\n", privcnt.Mpriv_cnt[i],
			Mpriv_str[i], (privcnt.Mpriv_cnt[i]*100L)/sum);
		if (i == 0x24) { // mov from CR
			printf("            [");
			for (j=0; j < 128; j++) if (from_cr_cnt[j]) {
				if (!cr_str[j])
					printf("PRIVSTRING NULL!!\r\n");
				printf("%s(%d),",cr_str[j],from_cr_cnt[j]);
			}
			printf("]\r\n");
		}
		else if (i == 0x2c) { // mov to CR
			printf("            [");
			for (j=0; j < 128; j++) if (to_cr_cnt[j]) {
				if (!cr_str[j])
					printf("PRIVSTRING NULL!!\r\n");
				printf("%s(%d),",cr_str[j],to_cr_cnt[j]);
			}
			printf("]\r\n");
		}
	}
}

void zero_privop_counts(void)
{
	int i, j;

	// this is ugly and should probably produce sorted output
	// but it will have to do for now
	printf("Zeroing privop statistics\r\n");
	privcnt.mov_to_ar_imm = 0; privcnt.mov_to_ar_reg = 0;
	privcnt.ssm = 0; privcnt.rsm = 0;
	privcnt.rfi = 0; privcnt.bsw0 = 0;
	privcnt.bsw1 = 0; privcnt.cover = 0;
	for (i=0; i < 64; i++) privcnt.Mpriv_cnt[i] = 0;
	for (j=0; j < 128; j++) from_cr_cnt[j] = 0;
	for (j=0; j < 128; j++) to_cr_cnt[j] = 0;
}
