#ifndef _ASM_IRQ_VECTORS_H
#define _ASM_IRQ_VECTORS_H

/* Processor-initiated interrupts are all high priority. */
#define SPURIOUS_APIC_VECTOR	0xff
#define ERROR_APIC_VECTOR	0xfe
#define INVALIDATE_TLB_VECTOR	0xfd
#define EVENT_CHECK_VECTOR	0xfc
#define CALL_FUNCTION_VECTOR	0xfb
#define LOCAL_TIMER_VECTOR	0xfa
#define PMU_APIC_VECTOR 	0xf9
/*
 * High-priority dynamically-allocated vectors. For interrupts that
 * must be higher priority than any guest-bound interrupt.
 */
#define FIRST_HIPRIORITY_VECTOR	0xf1
#define LAST_HIPRIORITY_VECTOR  0xf8
/* IRQ0 (timer) is statically allocated but must be high priority. */
#define IRQ0_VECTOR             0xf0

/* Legacy PIC uses vectors 0x20-0x2f. */
#define FIRST_LEGACY_VECTOR     FIRST_DYNAMIC_VECTOR
#define LAST_LEGACY_VECTOR      (FIRST_LEGACY_VECTOR + 0xf)

#define HYPERCALL_VECTOR	0x82
#define LEGACY_SYSCALL_VECTOR   0x80

/*
 * Dynamically-allocated vectors available to any driver. Note that the
 * legacy vector range is a sub-range of this one, re-used on CPUs not
 * sharing vectors with CPU 0.
 */
#define FIRST_DYNAMIC_VECTOR    0x20
#define LAST_DYNAMIC_VECTOR     0xef
#define NR_DYNAMIC_VECTORS	(LAST_DYNAMIC_VECTOR - FIRST_DYNAMIC_VECTOR + 1)

/* There's no IRQ2 at the PIC. */
#define IRQ_MOVE_CLEANUP_VECTOR (FIRST_LEGACY_VECTOR + 2)

#define FIRST_IRQ_VECTOR        FIRST_DYNAMIC_VECTOR
#define LAST_IRQ_VECTOR         LAST_HIPRIORITY_VECTOR

#endif /* _ASM_IRQ_VECTORS_H */
