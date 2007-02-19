/*
 * include/asm-i386/irqflags.h
 *
 * IRQ flags handling
 *
 * This file gets included from lowlevel asm headers too, to provide
 * wrapped versions of the local_irq_*() APIs, based on the
 * raw_local_irq_*() functions from the lowlevel headers.
 */
#ifndef _ASM_IRQFLAGS_H
#define _ASM_IRQFLAGS_H

#ifndef __ASSEMBLY__

/* 
 * The use of 'barrier' in the following reflects their use as local-lock
 * operations. Reentrancy must be prevented (e.g., __cli()) /before/ following
 * critical operations are executed. All critical operations must complete
 * /before/ reentrancy is permitted (e.g., __sti()). Alpha architecture also
 * includes these barriers, for example.
 */

#define __raw_local_save_flags() (current_vcpu_info()->evtchn_upcall_mask)

#define raw_local_save_flags(flags) \
		do { (flags) = __raw_local_save_flags(); } while (0)

#define raw_local_irq_restore(x)					\
do {									\
	vcpu_info_t *_vcpu;						\
	barrier();							\
	_vcpu = current_vcpu_info();					\
	if ((_vcpu->evtchn_upcall_mask = (x)) == 0) {			\
		barrier(); /* unmask then check (avoid races) */	\
		if (unlikely(_vcpu->evtchn_upcall_pending))		\
			force_evtchn_callback();			\
	}								\
} while (0)

#define raw_local_irq_disable()						\
do {									\
	current_vcpu_info()->evtchn_upcall_mask = 1;			\
	barrier();							\
} while (0)

#define raw_local_irq_enable()						\
do {									\
	vcpu_info_t *_vcpu;						\
	barrier();							\
	_vcpu = current_vcpu_info();					\
	_vcpu->evtchn_upcall_mask = 0;					\
	barrier(); /* unmask then check (avoid races) */		\
	if (unlikely(_vcpu->evtchn_upcall_pending))			\
		force_evtchn_callback();				\
} while (0)

/*
 * Used in the idle loop; sti takes one instruction cycle
 * to complete:
 */
void raw_safe_halt(void);

/*
 * Used when interrupts are already enabled or to
 * shutdown the processor:
 */
void halt(void);

static inline int raw_irqs_disabled_flags(unsigned long flags)
{
	return (flags != 0);
}

#define raw_irqs_disabled()						\
({									\
	unsigned long flags = __raw_local_save_flags();			\
									\
	raw_irqs_disabled_flags(flags);					\
})

/*
 * For spinlocks, etc:
 */
#define __raw_local_irq_save()						\
({									\
	unsigned long flags = __raw_local_save_flags();			\
									\
	raw_local_irq_disable();					\
									\
	flags;								\
})

#define raw_local_irq_save(flags) \
		do { (flags) = __raw_local_irq_save(); } while (0)

#endif /* __ASSEMBLY__ */

/*
 * Do the CPU's IRQ-state tracing from assembly code. We call a
 * C function, so save all the C-clobbered registers:
 */
#ifdef CONFIG_TRACE_IRQFLAGS

# define TRACE_IRQS_ON				\
	pushl %eax;				\
	pushl %ecx;				\
	pushl %edx;				\
	call trace_hardirqs_on;			\
	popl %edx;				\
	popl %ecx;				\
	popl %eax;

# define TRACE_IRQS_OFF				\
	pushl %eax;				\
	pushl %ecx;				\
	pushl %edx;				\
	call trace_hardirqs_off;		\
	popl %edx;				\
	popl %ecx;				\
	popl %eax;

#else
# define TRACE_IRQS_ON
# define TRACE_IRQS_OFF
#endif

#endif
