/*
 * This file should contain #defines for all of the interrupt vector
 * numbers used by this architecture.
 *
 * In addition, there are some standard defines:
 *
 *	FIRST_EXTERNAL_VECTOR:
 *		The first free place for external interrupts
 *
 *	SYSCALL_VECTOR:
 *		The IRQ vector a syscall makes the user to kernel transition
 *		under.
 *
 *	TIMER_IRQ:
 *		The IRQ number the timer interrupt comes in at.
 *
 *	NR_IRQS:
 *		The total number of interrupt vectors (including all the
 *		architecture specific interrupts) needed.
 *
 */			
#ifndef _ASM_IRQ_VECTORS_H
#define _ASM_IRQ_VECTORS_H

/*
 * IDT vectors usable for external interrupt sources start
 * at 0x20:
 */
#define FIRST_EXTERNAL_VECTOR	0x20

#define SYSCALL_VECTOR		0x80

/*
 * Vectors 0x20-0x2f are used for ISA interrupts.
 */

#if 0
/*
 * Special IRQ vectors used by the SMP architecture, 0xf0-0xff
 *
 *  some of the following vectors are 'rare', they are merged
 *  into a single vector (CALL_FUNCTION_VECTOR) to save vector space.
 *  TLB, reschedule and local APIC vectors are performance-critical.
 *
 *  Vectors 0xf0-0xfa are free (reserved for future Linux use).
 */
#define INVALIDATE_TLB_VECTOR	0xfd
#define RESCHEDULE_VECTOR	0xfc
#define CALL_FUNCTION_VECTOR	0xfb

#define THERMAL_APIC_VECTOR	0xf0
/*
 * Local APIC timer IRQ vector is on a different priority level,
 * to work around the 'lost local interrupt if more than 2 IRQ
 * sources per level' errata.
 */
#define LOCAL_TIMER_VECTOR	0xef
#endif

#define SPURIOUS_APIC_VECTOR	0xff
#define ERROR_APIC_VECTOR	0xfe

/*
 * First APIC vector available to drivers: (vectors 0x30-0xee)
 * we start at 0x31 to spread out vectors evenly between priority
 * levels. (0x80 is the syscall vector)
 */
#define FIRST_DEVICE_VECTOR	0x31
#define FIRST_SYSTEM_VECTOR	0xef

/*
 * 16 8259A IRQ's, 208 potential APIC interrupt sources.
 * Right now the APIC is mostly only used for SMP.
 * 256 vectors is an architectural limit. (we can have
 * more than 256 devices theoretically, but they will
 * have to use shared interrupts)
 * Since vectors 0x00-0x1f are used/reserved for the CPU,
 * the usable vector space is 0x20-0xff (224 vectors)
 */

#define RESCHEDULE_VECTOR	0
#define CALL_FUNCTION_VECTOR	1
#define NR_IPIS			2

/*
 * The maximum number of vectors supported by i386 processors
 * is limited to 256. For processors other than i386, NR_VECTORS
 * should be changed accordingly.
 */
#define NR_VECTORS 256

#define FPU_IRQ			13

#define	FIRST_VM86_IRQ		3
#define LAST_VM86_IRQ		15
#define invalid_vm86_irq(irq)	((irq) < 3 || (irq) > 15)

/*
 * The flat IRQ space is divided into two regions:
 *  1. A one-to-one mapping of real physical IRQs. This space is only used
 *     if we have physical device-access privilege. This region is at the 
 *     start of the IRQ space so that existing device drivers do not need
 *     to be modified to translate physical IRQ numbers into our IRQ space.
 *  3. A dynamic mapping of inter-domain and Xen-sourced virtual IRQs. These
 *     are bound using the provided bind/unbind functions.
 */

#define PIRQ_BASE		0
#define NR_PIRQS		256

#define DYNIRQ_BASE		(PIRQ_BASE + NR_PIRQS)
#define NR_DYNIRQS		256

#define NR_IRQS			(NR_PIRQS + NR_DYNIRQS)
#define NR_IRQ_VECTORS		NR_IRQS

#define pirq_to_irq(_x)		((_x) + PIRQ_BASE)
#define irq_to_pirq(_x)		((_x) - PIRQ_BASE)

#define dynirq_to_irq(_x)	((_x) + DYNIRQ_BASE)
#define irq_to_dynirq(_x)	((_x) - DYNIRQ_BASE)

#endif /* _ASM_IRQ_VECTORS_H */
