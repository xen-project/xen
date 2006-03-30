#ifndef _ASM_IA64_XEN_PRIVOP_H
#define _ASM_IA64_XEN_PRIVOP_H

/*
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 *
 * Paravirtualizations of privileged operations for Xen/ia64
 *
 */


#include <asm/xen/asm-xsi-offsets.h>

#define IA64_PARAVIRTUALIZED

#ifdef __ASSEMBLY__
#define	XEN_HYPER_RFI			break 0x1
#define	XEN_HYPER_RSM_PSR_DT		break 0x2
#define	XEN_HYPER_SSM_PSR_DT		break 0x3
#define	XEN_HYPER_COVER			break 0x4
#define	XEN_HYPER_ITC_D			break 0x5
#define	XEN_HYPER_ITC_I			break 0x6
#define	XEN_HYPER_SSM_I			break 0x7
#define	XEN_HYPER_GET_IVR		break 0x8
#define	XEN_HYPER_GET_TPR		break 0x9
#define	XEN_HYPER_SET_TPR		break 0xa
#define	XEN_HYPER_EOI			break 0xb
#define	XEN_HYPER_SET_ITM		break 0xc
#define	XEN_HYPER_THASH			break 0xd
#define	XEN_HYPER_PTC_GA		break 0xe
#define	XEN_HYPER_ITR_D			break 0xf
#define	XEN_HYPER_GET_RR		break 0x10
#define	XEN_HYPER_SET_RR		break 0x11
#define	XEN_HYPER_SET_KR		break 0x12
#define	XEN_HYPER_FC			break 0x13
#define	XEN_HYPER_GET_CPUID		break 0x14
#define	XEN_HYPER_GET_PMD		break 0x15
#define	XEN_HYPER_GET_EFLAG		break 0x16
#define	XEN_HYPER_SET_EFLAG		break 0x17
#endif

#ifndef __ASSEMBLY__
#ifdef MODULE
extern int is_running_on_xen(void);
#define running_on_xen (is_running_on_xen())
#else
extern int running_on_xen;
#endif

#define	XEN_HYPER_SSM_I			asm("break 0x7");
#define	XEN_HYPER_GET_IVR		asm("break 0x8");

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
#define XSI_PSR_I			\
	(*(uint64_t *)(XSI_PSR_I_ADDR))
#define xen_get_virtual_psr_i()		\
	(!(*(uint8_t *)(XSI_PSR_I)))
#define xen_set_virtual_psr_i(_val)	\
	({ *(uint8_t *)(XSI_PSR_I) = (uint8_t)(_val) ? 0:1; })
#define xen_set_virtual_psr_ic(_val)	\
	({ *(int *)(XSI_PSR_IC) = _val ? 1:0; })
#define xen_get_virtual_pend()		(*(int *)(XSI_PEND))

/* Hyperprivops are "break" instructions with a well-defined API.
 * In particular, the virtual psr.ic bit must be off; in this way
 * it is guaranteed to never conflict with a linux break instruction.
 * Normally, this is done in a xen stub but this one is frequent enough
 * that we inline it */
#define xen_hyper_ssm_i()						\
({									\
	xen_set_virtual_psr_i(0);					\
	xen_set_virtual_psr_ic(0);					\
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
	xen_set_virtual_psr_i(1);					\
	if (!old && xen_get_virtual_pend()) xen_hyper_ssm_i();		\
})

#define xen_ia64_intrin_local_irq_restore(x)				\
{									\
     if (running_on_xen) {						\
	if ((x) & IA64_PSR_I) { xen_ssm_i(); }				\
	else { xen_rsm_i(); }						\
    }									\
    else __ia64_intrin_local_irq_restore((x));				\
}

#define	xen_get_psr_i()							\
(									\
	(running_on_xen) ?						\
		(xen_get_virtual_psr_i() ? IA64_PSR_I : 0)		\
		: __ia64_get_psr_i()					\
)

#define xen_ia64_ssm(mask)						\
{									\
	if ((mask)==IA64_PSR_I) {					\
		if (running_on_xen) { xen_ssm_i(); }			\
		else { __ia64_ssm(mask); }				\
	}								\
	else { __ia64_ssm(mask); }					\
}

#define xen_ia64_rsm(mask)						\
{									\
	if ((mask)==IA64_PSR_I) {					\
		if (running_on_xen) { xen_rsm_i(); }			\
		else { __ia64_rsm(mask); }				\
	}								\
	else { __ia64_rsm(mask); }					\
}


/* Although all privileged operations can be left to trap and will
 * be properly handled by Xen, some are frequent enough that we use
 * hyperprivops for performance. */

extern unsigned long xen_get_ivr(void);
extern unsigned long xen_get_tpr(void);
extern void xen_set_itm(unsigned long);
extern void xen_set_tpr(unsigned long);
extern void xen_eoi(void);
extern void xen_set_rr(unsigned long index, unsigned long val);
extern unsigned long xen_get_rr(unsigned long index);
extern void xen_set_kr(unsigned long index, unsigned long val);

/* Note: It may look wrong to test for running_on_xen in each case.
 * However regnum is always a constant so, as written, the compiler
 * eliminates the switch statement, whereas running_on_xen must be
 * tested dynamically. */
#define xen_ia64_getreg(regnum)						\
({									\
	__u64 ia64_intri_res;						\
									\
	switch(regnum) {						\
	case _IA64_REG_CR_IVR:						\
		ia64_intri_res = (running_on_xen) ?			\
			xen_get_ivr() :					\
			__ia64_getreg(regnum);				\
		break;							\
	case _IA64_REG_CR_TPR:						\
		ia64_intri_res = (running_on_xen) ?			\
			xen_get_tpr() :					\
			__ia64_getreg(regnum);				\
		break;							\
	case _IA64_REG_AR_EFLAG:					\
		ia64_intri_res = (running_on_xen) ?			\
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
		(running_on_xen) ?					\
			xen_set_kr((regnum-_IA64_REG_AR_KR0), val) :	\
			__ia64_setreg(regnum,val);			\
		break;							\
	case _IA64_REG_CR_ITM:						\
		(running_on_xen) ?					\
			xen_set_itm(val) :				\
			__ia64_setreg(regnum,val);			\
		break;							\
	case _IA64_REG_CR_TPR:						\
		(running_on_xen) ?					\
			xen_set_tpr(val) :				\
			__ia64_setreg(regnum,val);			\
		break;							\
	case _IA64_REG_CR_EOI:						\
		(running_on_xen) ?					\
			xen_eoi() :					\
			__ia64_setreg(regnum,val);			\
		break;							\
	case _IA64_REG_AR_EFLAG:					\
		(running_on_xen) ?					\
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
#define	ia64_switch_to			xen_switch_to
#define	ia64_pal_call_static		xen_pal_call_static

#endif /* _ASM_IA64_XEN_PRIVOP_H */
