#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

/*
 *	linux/include/asm/hw_irq.h
 *
 *	(C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar
 */

#include <linux/config.h>
#include <linux/smp.h>
#include <asm/atomic.h>
#include <asm/irq.h>

#define SYSCALL_VECTOR		0x80

extern int irq_vector[NR_IRQS];

extern atomic_t irq_err_count;
extern atomic_t irq_mis_count;

extern char _stext, _etext;

extern unsigned long prof_cpu_mask;
extern unsigned int * prof_buffer;
extern unsigned long prof_len;
extern unsigned long prof_shift;

/*
 * x86 profiling function, SMP safe. We might want to do this in
 * assembly totally?
 */
static inline void x86_do_profile (unsigned long eip)
{
        if (!prof_buffer)
                return;

        /*
         * Only measure the CPUs specified by /proc/irq/prof_cpu_mask.
         * (default is all CPUs.)
         */
        if (!((1<<smp_processor_id()) & prof_cpu_mask))
                return;

        eip -= (unsigned long) &_stext;
        eip >>= prof_shift;
        /*
         * Don't ignore out-of-bounds EIP values silently,
         * put them into the last histogram slot, so if
         * present, they will show up as a sharp peak.
         */
        if (eip > prof_len-1)
                eip = prof_len-1;
        atomic_inc((atomic_t *)&prof_buffer[eip]);
}

static inline void hw_resend_irq(struct hw_interrupt_type *h,
                                 unsigned int i)
{}

#endif /* _ASM_HW_IRQ_H */
