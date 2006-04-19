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

/* Define HV space hierarchy.
   VMM memory space is protected by CPL for paravirtualized domains and
   by VA for VTi domains.  VTi imposes VA bit 60 != VA bit 59 for VMM.  */
#define XEN_VIRT_SPACE_LOW	 0xe800000000000000
#define XEN_VIRT_SPACE_HIGH	 0xf800000000000000	

#define __IA64_UNCACHED_OFFSET	 0xe800000000000000UL

#define XEN_START_ADDR		 0xf000000000000000
#define HYPERVISOR_VIRT_START	 0xf000000000000000
#define KERNEL_START		 0xf000000004000000
#define SHAREDINFO_ADDR		 0xf100000000000000
#define SHARED_ARCHINFO_ADDR	 (SHAREDINFO_ADDR + PAGE_SIZE)
#define PERCPU_ADDR		 (SHAREDINFO_ADDR - PERCPU_PAGE_SIZE)
#define XSI_OFS 		 (SHARED_ARCHINFO_ADDR - SHAREDINFO_ADDR)
#define VHPT_ADDR		 0xf200000000000000
#ifdef CONFIG_VIRTUAL_FRAME_TABLE
#define VIRT_FRAME_TABLE_ADDR	 0xf300000000000000
#define VIRT_FRAME_TABLE_END	 0xf400000000000000
#endif
#define XEN_END_ADDR		 0xf400000000000000

#define IS_VMM_ADDRESS(addr) ((((addr) >> 60) ^ ((addr) >> 59)) & 1)

#ifndef __ASSEMBLY__

#define IA64_HAS_EXTRA_STATE(t) 0

struct vcpu;
extern void ia64_save_extra (struct vcpu *v);
extern void ia64_load_extra (struct vcpu *v);

extern struct vcpu *vmx_ia64_switch_to (struct vcpu *next_task);
extern struct vcpu *ia64_switch_to (struct vcpu *next_task);

#define __switch_to(prev,next,last) do {	\
       ia64_save_fpu(prev->arch._thread.fph);	\
       ia64_load_fpu(next->arch._thread.fph);	\
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
	/*ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next);*/			 \
       (last) = ia64_switch_to((next));        \
       if (!VMX_DOMAIN(current)){                   \
    	   vcpu_set_next_timer(current);    		\
       }                                       \
} while (0)

// FIXME SMP... see system.h, does this need to be different?
#define switch_to(prev,next,last)	__switch_to(prev, next, last)

#define local_irq_is_enabled() (!irqs_disabled())

#endif // __ASSEMBLY__
#endif // _ASM_IA64_XENSYSTEM_H
