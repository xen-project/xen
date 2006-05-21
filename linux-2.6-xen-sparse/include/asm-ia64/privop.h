#ifndef _ASM_IA64_PRIVOP_H
#define _ASM_IA64_PRIVOP_H

/*
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 *
 */

#include <linux/config.h>
#ifdef CONFIG_XEN
#include <asm/xen/privop.h>
#endif

#ifndef __ASSEMBLY

#ifndef IA64_PARAVIRTUALIZED

#define ia64_getreg			__ia64_getreg
#define ia64_setreg			__ia64_setreg
#define ia64_hint			__ia64_hint
#define ia64_thash			__ia64_thash
#define ia64_itci			__ia64_itci
#define ia64_itcd			__ia64_itcd
#define ia64_itri			__ia64_itri
#define ia64_itrd			__ia64_itrd
#define ia64_tpa			__ia64_tpa
#define ia64_set_ibr			__ia64_set_ibr
#define ia64_set_pkr			__ia64_set_pkr
#define ia64_set_pmc			__ia64_set_pmc
#define ia64_set_pmd			__ia64_set_pmd
#define ia64_set_rr			__ia64_set_rr
#define ia64_get_cpuid			__ia64_get_cpuid
#define ia64_get_ibr			__ia64_get_ibr
#define ia64_get_pkr			__ia64_get_pkr
#define ia64_get_pmc			__ia64_get_pmc
#define ia64_get_pmd			__ia64_get_pmd
#define ia64_get_rr			__ia64_get_rr
#define ia64_fc				__ia64_fc
#define ia64_ssm			__ia64_ssm
#define ia64_rsm			__ia64_rsm
#define ia64_ptce			__ia64_ptce
#define ia64_ptcga			__ia64_ptcga
#define ia64_ptcl			__ia64_ptcl
#define ia64_ptri			__ia64_ptri
#define ia64_ptrd			__ia64_ptrd
#define ia64_get_psr_i			__ia64_get_psr_i
#define ia64_intrin_local_irq_restore	__ia64_intrin_local_irq_restore
#define ia64_pal_halt_light		__ia64_pal_halt_light
#define ia64_leave_kernel		__ia64_leave_kernel
#define ia64_leave_syscall		__ia64_leave_syscall
#define ia64_trace_syscall		__ia64_trace_syscall
#define ia64_switch_to			__ia64_switch_to
#define ia64_pal_call_static		__ia64_pal_call_static

#endif /* !IA64_PARAVIRTUALIZED */

#endif /* !__ASSEMBLY */

#endif /* _ASM_IA64_PRIVOP_H */
