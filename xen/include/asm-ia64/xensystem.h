#ifndef _ASM_IA64_XENSYSTEM_H
#define _ASM_IA64_XENSYSTEM_H
/*
 * xen specific context definition
 *
 * Copyright (C) 2005 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 * Copyright (C) 2005 Intel Co.
 * 	Kun Tian (Kevin Tian) <kevin.tian@intel.com>
 *
 */
#include <asm/config.h>
#include <linux/kernel.h>

/* Define HV space hierarchy */
#ifdef CONFIG_VTI
#define XEN_VIRT_SPACE_LOW	 0xe800000000000000
#define XEN_VIRT_SPACE_HIGH	 0xf800000000000000	
/* This is address to mapping rr7 switch stub, in region 5 */
#define XEN_RR7_SWITCH_STUB	 0xb700000000000000
#endif // CONFIG_VTI

#define KERNEL_START		 0xf000000004000000
#define PERCPU_ADDR		 0xf100000000000000-PERCPU_PAGE_SIZE
#define SHAREDINFO_ADDR		 0xf100000000000000
#define VHPT_ADDR		 0xf200000000000000

#ifndef __ASSEMBLY__

#define IA64_HAS_EXTRA_STATE(t) 0

#ifdef CONFIG_VTI
extern struct task_struct *vmx_ia64_switch_to (void *next_task);
#define __switch_to(prev,next,last) do {	\
       if (VMX_DOMAIN(prev))                   \
               vmx_save_state(prev);           \
       else {                                  \
               if (IA64_HAS_EXTRA_STATE(prev)) \
                       ia64_save_extra(prev);  \
       }                                       \
       if (VMX_DOMAIN(next))                   \
               vmx_load_state(next);           \
       else {                                  \
               if (IA64_HAS_EXTRA_STATE(next)) \
                       ia64_save_extra(next);  \
       }                                       \
       ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next); \
       (last) = vmx_ia64_switch_to((next));        \
} while (0)
#else // CONFIG_VTI
#define __switch_to(prev,next,last) do {							 \
	if (IA64_HAS_EXTRA_STATE(prev))								 \
		ia64_save_extra(prev);								 \
	if (IA64_HAS_EXTRA_STATE(next))								 \
		ia64_load_extra(next);								 \
	ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next);			 \
	(last) = ia64_switch_to((next));							 \
} while (0)
#endif // CONFIG_VTI

#endif // __ASSEMBLY__
#endif // _ASM_IA64_XENSYSTEM_H
