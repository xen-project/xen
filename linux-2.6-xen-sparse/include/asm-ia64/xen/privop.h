#ifndef _ASM_IA64_XEN_PRIVOP_H
#define _ASM_IA64_XEN_PRIVOP_H

/*
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 *
 * Paravirtualizations of privileged operations for Xen/ia64
 *
 */


#include <xen/interface/arch-ia64.h>

#define IA64_PARAVIRTUALIZED

/* At 1 MB, before per-cpu space but still addressable using addl instead
   of movl. */
#define XSI_BASE				0xfffffffffff00000

/* Address of mapped regs.  */
#define XMAPPEDREGS_BASE		(XSI_BASE + XSI_SIZE)

#ifdef __ASSEMBLY__
#define	XEN_HYPER_RFI			break HYPERPRIVOP_RFI
#define	XEN_HYPER_RSM_PSR_DT		break HYPERPRIVOP_RSM_DT
#define	XEN_HYPER_SSM_PSR_DT		break HYPERPRIVOP_SSM_DT
#define	XEN_HYPER_COVER			break HYPERPRIVOP_COVER
#define	XEN_HYPER_ITC_D			break HYPERPRIVOP_ITC_D
#define	XEN_HYPER_ITC_I			break HYPERPRIVOP_ITC_I
#define	XEN_HYPER_SSM_I			break HYPERPRIVOP_SSM_I
#define	XEN_HYPER_GET_IVR		break HYPERPRIVOP_GET_IVR
#define	XEN_HYPER_GET_TPR		break HYPERPRIVOP_GET_TPR
#define	XEN_HYPER_SET_TPR		break HYPERPRIVOP_SET_TPR
#define	XEN_HYPER_EOI			break HYPERPRIVOP_EOI
#define	XEN_HYPER_SET_ITM		break HYPERPRIVOP_SET_ITM
#define	XEN_HYPER_THASH			break HYPERPRIVOP_THASH
#define	XEN_HYPER_PTC_GA		break HYPERPRIVOP_PTC_GA
#define	XEN_HYPER_ITR_D			break HYPERPRIVOP_ITR_D
#define	XEN_HYPER_GET_RR		break HYPERPRIVOP_GET_RR
#define	XEN_HYPER_SET_RR		break HYPERPRIVOP_SET_RR
#define	XEN_HYPER_SET_KR		break HYPERPRIVOP_SET_KR
#define	XEN_HYPER_FC			break HYPERPRIVOP_FC
#define	XEN_HYPER_GET_CPUID		break HYPERPRIVOP_GET_CPUID
#define	XEN_HYPER_GET_PMD		break HYPERPRIVOP_GET_PMD
#define	XEN_HYPER_GET_EFLAG		break HYPERPRIVOP_GET_EFLAG
#define	XEN_HYPER_SET_EFLAG		break HYPERPRIVOP_SET_EFLAG
#define	XEN_HYPER_GET_PSR		break HYPERPRIVOP_GET_PSR

#define XSI_IFS			(XSI_BASE + XSI_IFS_OFS)
#define XSI_PRECOVER_IFS	(XSI_BASE + XSI_PRECOVER_IFS_OFS)
#define XSI_IFA			(XSI_BASE + XSI_IFA_OFS)
#define XSI_ISR			(XSI_BASE + XSI_ISR_OFS)
#define XSI_IIM			(XSI_BASE + XSI_IIM_OFS)
#define XSI_ITIR		(XSI_BASE + XSI_ITIR_OFS)
#define XSI_PSR_I_ADDR		(XSI_BASE + XSI_PSR_I_ADDR_OFS)
#define XSI_PSR_IC		(XSI_BASE + XSI_PSR_IC_OFS)
#define XSI_IPSR		(XSI_BASE + XSI_IPSR_OFS)
#define XSI_IIP			(XSI_BASE + XSI_IIP_OFS)
#define XSI_B1NAT		(XSI_BASE + XSI_B1NATS_OFS)
#define XSI_BANK1_R16		(XSI_BASE + XSI_BANK1_R16_OFS)
#define XSI_BANKNUM		(XSI_BASE + XSI_BANKNUM_OFS)
#define XSI_IHA			(XSI_BASE + XSI_IHA_OFS)
#endif

#ifndef __ASSEMBLY__
#define	XEN_HYPER_SSM_I		asm("break %0" : : "i" (HYPERPRIVOP_SSM_I))
#define	XEN_HYPER_GET_IVR	asm("break %0" : : "i" (HYPERPRIVOP_GET_IVR))

/************************************************/
/* Instructions paravirtualized for correctness */
/************************************************/

/* "fc" and "thash" are privilege-sensitive instructions, meaning they
 *  may have different semantics depending on whether they are executed
 *  at PL0 vs PL!=0.  When paravirtualized, these instructions mustn't
 *  be allowed to execute directly, lest incorrect semantics result. */
extern unsigned long xen_fc(unsigned long addr);
#define ia64_fc(addr)			xen_fc((unsigned long)(addr))
extern unsigned long xen_thash(unsigned long addr);
#define ia64_thash(addr)		xen_thash((unsigned long)(addr))
/* Note that "ttag" and "cover" are also privilege-sensitive; "ttag"
 * is not currently used (though it may be in a long-format VHPT system!)
 * and the semantics of cover only change if psr.ic is off which is very
 * rare (and currently non-existent outside of assembly code */

/* There are also privilege-sensitive registers.  These registers are
 * readable at any privilege level but only writable at PL0. */
extern unsigned long xen_get_cpuid(int index);
#define	ia64_get_cpuid(i)		xen_get_cpuid(i)
extern unsigned long xen_get_pmd(int index);
#define	ia64_get_pmd(i)			xen_get_pmd(i)
extern unsigned long xen_get_eflag(void);	/* see xen_ia64_getreg */
extern void xen_set_eflag(unsigned long);	/* see xen_ia64_setreg */

/************************************************/
/* Instructions paravirtualized for performance */
/************************************************/

/* Xen uses memory-mapped virtual privileged registers for access to many
 * performance-sensitive privileged registers.  Some, like the processor
 * status register (psr), are broken up into multiple memory locations.
 * Others, like "pend", are abstractions based on privileged registers.
 * "Pend" is guaranteed to be set if reading cr.ivr would return a
 * (non-spurious) interrupt. */
#define XEN_MAPPEDREGS ((struct mapped_regs *)XMAPPEDREGS_BASE)
#define XSI_PSR_I			\
	(*XEN_MAPPEDREGS->interrupt_mask_addr)
#define xen_get_virtual_psr_i()		\
	(!XSI_PSR_I)
#define xen_set_virtual_psr_i(_val)	\
	({ XSI_PSR_I = (uint8_t)(_val) ? 0 : 1; })
#define xen_set_virtual_psr_ic(_val)	\
	({ XEN_MAPPEDREGS->interrupt_collection_enabled = _val ? 1 : 0; })
#define xen_get_virtual_pend()		\
	(*(((uint8_t *)XEN_MAPPEDREGS->interrupt_mask_addr) - 1))

/* Hyperprivops are "break" instructions with a well-defined API.
 * In particular, the virtual psr.ic bit must be off; in this way
 * it is guaranteed to never conflict with a linux break instruction.
 * Normally, this is done in a xen stub but this one is frequent enough
 * that we inline it */
#define xen_hyper_ssm_i()						\
({									\
	XEN_HYPER_SSM_I;						\
})

/* turning off interrupts can be paravirtualized simply by writing
 * to a memory-mapped virtual psr.i bit (implemented as a 16-bit bool) */
#define xen_rsm_i()	xen_set_virtual_psr_i(0)

/* turning on interrupts is a bit more complicated.. write to the
 * memory-mapped virtual psr.i bit first (to avoid race condition),
 * then if any interrupts were pending, we have to execute a hyperprivop
 * to ensure the pending interrupt gets delivered; else we're done! */
#define xen_ssm_i()							\
({									\
	int old = xen_get_virtual_psr_i();				\
	if (!old) {							\
		if (xen_get_virtual_pend())				\
			xen_hyper_ssm_i();				\
		else							\
			xen_set_virtual_psr_i(1);			\
	}								\
})

#define xen_ia64_intrin_local_irq_restore(x)				\
{									\
     if (is_running_on_xen()) {						\
	if ((x) & IA64_PSR_I) { xen_ssm_i(); }				\
	else { xen_rsm_i(); }						\
    }									\
    else __ia64_intrin_local_irq_restore((x));				\
}

#define	xen_get_psr_i()							\
(									\
	(is_running_on_xen()) ?						\
		(xen_get_virtual_psr_i() ? IA64_PSR_I : 0)		\
		: __ia64_get_psr_i()					\
)

#define xen_ia64_ssm(mask)						\
{									\
	if ((mask)==IA64_PSR_I) {					\
		if (is_running_on_xen()) { xen_ssm_i(); }			\
		else { __ia64_ssm(mask); }				\
	}								\
	else { __ia64_ssm(mask); }					\
}

#define xen_ia64_rsm(mask)						\
{									\
	if ((mask)==IA64_PSR_I) {					\
		if (is_running_on_xen()) { xen_rsm_i(); }			\
		else { __ia64_rsm(mask); }				\
	}								\
	else { __ia64_rsm(mask); }					\
}


/* Although all privileged operations can be left to trap and will
 * be properly handled by Xen, some are frequent enough that we use
 * hyperprivops for performance. */

extern unsigned long xen_get_psr(void);
extern unsigned long xen_get_ivr(void);
extern unsigned long xen_get_tpr(void);
extern void xen_set_itm(unsigned long);
extern void xen_set_tpr(unsigned long);
extern void xen_eoi(void);
extern void xen_set_rr(unsigned long index, unsigned long val);
extern unsigned long xen_get_rr(unsigned long index);
extern void xen_set_kr(unsigned long index, unsigned long val);
extern void xen_ptcga(unsigned long addr, unsigned long size);

/* Note: It may look wrong to test for is_running_on_xen() in each case.
 * However regnum is always a constant so, as written, the compiler
 * eliminates the switch statement, whereas is_running_on_xen() must be
 * tested dynamically. */
#define xen_ia64_getreg(regnum)						\
({									\
	__u64 ia64_intri_res;						\
									\
	switch(regnum) {						\
	case _IA64_REG_PSR:						\
		ia64_intri_res = (is_running_on_xen()) ?			\
			xen_get_psr() :					\
			__ia64_getreg(regnum);				\
		break;							\
	case _IA64_REG_CR_IVR:						\
		ia64_intri_res = (is_running_on_xen()) ?			\
			xen_get_ivr() :					\
			__ia64_getreg(regnum);				\
		break;							\
	case _IA64_REG_CR_TPR:						\
		ia64_intri_res = (is_running_on_xen()) ?			\
			xen_get_tpr() :					\
			__ia64_getreg(regnum);				\
		break;							\
	case _IA64_REG_AR_EFLAG:					\
		ia64_intri_res = (is_running_on_xen()) ?			\
			xen_get_eflag() :				\
			__ia64_getreg(regnum);				\
		break;							\
	default:							\
		ia64_intri_res = __ia64_getreg(regnum);			\
		break;							\
	}								\
	ia64_intri_res;							\
})

#define xen_ia64_setreg(regnum,val)					\
({									\
	switch(regnum) {						\
	case _IA64_REG_AR_KR0 ... _IA64_REG_AR_KR7:			\
		(is_running_on_xen()) ?					\
			xen_set_kr((regnum-_IA64_REG_AR_KR0), val) :	\
			__ia64_setreg(regnum,val);			\
		break;							\
	case _IA64_REG_CR_ITM:						\
		(is_running_on_xen()) ?					\
			xen_set_itm(val) :				\
			__ia64_setreg(regnum,val);			\
		break;							\
	case _IA64_REG_CR_TPR:						\
		(is_running_on_xen()) ?					\
			xen_set_tpr(val) :				\
			__ia64_setreg(regnum,val);			\
		break;							\
	case _IA64_REG_CR_EOI:						\
		(is_running_on_xen()) ?					\
			xen_eoi() :					\
			__ia64_setreg(regnum,val);			\
		break;							\
	case _IA64_REG_AR_EFLAG:					\
		(is_running_on_xen()) ?					\
			xen_set_eflag(val) :				\
			__ia64_setreg(regnum,val);			\
		break;							\
	default:							\
		__ia64_setreg(regnum,val);				\
		break;							\
	}								\
})

#define ia64_ssm			xen_ia64_ssm
#define ia64_rsm			xen_ia64_rsm
#define ia64_intrin_local_irq_restore	xen_ia64_intrin_local_irq_restore
#define	ia64_ptcga			xen_ptcga
#define	ia64_set_rr(index,val)		xen_set_rr(index,val)
#define	ia64_get_rr(index)		xen_get_rr(index)
#define ia64_getreg			xen_ia64_getreg
#define ia64_setreg			xen_ia64_setreg
#define	ia64_get_psr_i			xen_get_psr_i

/* the remainder of these are not performance-sensitive so its
 * OK to not paravirtualize and just take a privop trap and emulate */
#define ia64_hint			__ia64_hint
#define ia64_set_pmd			__ia64_set_pmd
#define ia64_itci			__ia64_itci
#define ia64_itcd			__ia64_itcd
#define ia64_itri			__ia64_itri
#define ia64_itrd			__ia64_itrd
#define ia64_tpa			__ia64_tpa
#define ia64_set_ibr			__ia64_set_ibr
#define ia64_set_pkr			__ia64_set_pkr
#define ia64_set_pmc			__ia64_set_pmc
#define ia64_get_ibr			__ia64_get_ibr
#define ia64_get_pkr			__ia64_get_pkr
#define ia64_get_pmc			__ia64_get_pmc
#define ia64_ptce			__ia64_ptce
#define ia64_ptcl			__ia64_ptcl
#define ia64_ptri			__ia64_ptri
#define ia64_ptrd			__ia64_ptrd

#endif /* !__ASSEMBLY__ */

/* these routines utilize privilege-sensitive or performance-sensitive
 * privileged instructions so the code must be replaced with
 * paravirtualized versions */
#define ia64_pal_halt_light		xen_pal_halt_light
#define	ia64_leave_kernel		xen_leave_kernel
#define	ia64_leave_syscall		xen_leave_syscall
#define	ia64_trace_syscall		xen_trace_syscall
#define	ia64_ret_from_clone		xen_ret_from_clone
#define	ia64_switch_to			xen_switch_to
#define	ia64_pal_call_static		xen_pal_call_static

#endif /* _ASM_IA64_XEN_PRIVOP_H */
