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
#define XEN_VIRT_SPACE_LOW	 0xe800000000000000
#define XEN_VIRT_SPACE_HIGH	 0xf800000000000000	

#define XEN_START_ADDR		 0xf000000000000000
#define HYPERVISOR_VIRT_START	 0xf000000000000000
#undef KERNEL_START
#define KERNEL_START		 0xf000000004000000
#undef PERCPU_ADDR
#define PERCPU_ADDR		 0xf100000000000000-PERCPU_PAGE_SIZE
#define SHAREDINFO_ADDR		 0xf100000000000000
#define VHPT_ADDR		 0xf200000000000000
#define SHARED_ARCHINFO_ADDR	 0xf300000000000000
#define XEN_END_ADDR		 0xf400000000000000

#ifndef __ASSEMBLY__

#undef IA64_HAS_EXTRA_STATE
#define IA64_HAS_EXTRA_STATE(t) 0

#undef __switch_to
#if     1
extern struct task_struct *vmx_ia64_switch_to (void *next_task);
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
#else
#define __switch_to(prev,next,last) do {							 \
	ia64_save_fpu(prev->arch._thread.fph);							\
	ia64_load_fpu(next->arch._thread.fph);							\
	if (IA64_HAS_EXTRA_STATE(prev))								 \
		ia64_save_extra(prev);								 \
	if (IA64_HAS_EXTRA_STATE(next))								 \
		ia64_load_extra(next);								 \
	/*ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next);*/			 \
	(last) = ia64_switch_to((next));							 \
	vcpu_set_next_timer(current);								\
} while (0)
#endif

#undef switch_to
// FIXME SMP... see system.h, does this need to be different?
#define switch_to(prev,next,last)	__switch_to(prev, next, last)

#define __cmpxchg_user(ptr, new, old, _size)				\
({									\
	register long __gu_r8 asm ("r8");				\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old));			\
	asm volatile ("mov %1=r0;;\n"					\
		"[1:]\tcmpxchg"_size".acq %0=[%2],%3,ar.ccv\n"		\
		"\t.xdata4 \"__ex_table\", 1b-., 1f-.\n"		\
		"[1:]"							\
		: "=r"(old), "=r"(__gu_r8) :				\
		"r"(ptr), "r"(new) : "memory");				\
	__gu_r8;							\
})


// NOTE: Xen defines args as pointer,old,new whereas ia64 uses pointer,new,old
//  so reverse them here
#define cmpxchg_user(_p,_o,_n)					\
({								\
	register long _rc;					\
	ia64_mf();						\
	switch ( sizeof(*(_p)) ) {				\
	    case 1: _rc = __cmpxchg_user(_p,_n,_o,"1"); break;	\
	    case 2: _rc = __cmpxchg_user(_p,_n,_o,"2"); break;	\
	    case 4: _rc = __cmpxchg_user(_p,_n,_o,"4"); break;	\
	    case 8: _rc = __cmpxchg_user(_p,_n,_o,"8"); break;	\
	}							\
	ia64_mf();						\
	_rc;							\
})

#endif // __ASSEMBLY__
#endif // _ASM_IA64_XENSYSTEM_H
