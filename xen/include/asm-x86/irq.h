#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

/* (C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar */

#include <xen/config.h>
#include <asm/atomic.h>
#include <asm/asm_defns.h>

extern void disable_irq(unsigned int);
extern void disable_irq_nosync(unsigned int);
extern void enable_irq(unsigned int);

/*
 * IDT vectors usable for external interrupt sources start
 * at 0x20:
 */
#define FIRST_EXTERNAL_VECTOR   0x30

#define NR_IRQS (256 - FIRST_EXTERNAL_VECTOR)

#define HYPERCALL_VECTOR        0x82

/*
 * Vectors 0x30-0x3f are used for ISA interrupts.
 */

/*
 * Special IRQ vectors used by the SMP architecture, 0xf0-0xff
 */
#define SPURIOUS_APIC_VECTOR    0xff
#define ERROR_APIC_VECTOR       0xfe
#define INVALIDATE_TLB_VECTOR   0xfd
#define EVENT_CHECK_VECTOR      0xfc
#define CALL_FUNCTION_VECTOR    0xfb
#define KDB_VECTOR              0xfa

/*
 * Local APIC timer IRQ vector is on a different priority level,
 * to work around the 'lost local interrupt if more than 2 IRQ
 * sources per level' errata.
 */
#define LOCAL_TIMER_VECTOR      0xef

/*
 * First APIC vector available to drivers: (vectors 0x40-0xee)
 * we start at 0x41 to spread out vectors evenly between priority
 * levels. (0x82 is the hypercall vector)
 */
#define FIRST_DEVICE_VECTOR     0x41
#define FIRST_SYSTEM_VECTOR     0xef

extern int irq_vector[NR_IRQS];
#define IO_APIC_VECTOR(irq)     irq_vector[irq]

/*
 * Various low-level irq details needed by irq.c, process.c,
 * time.c, io_apic.c and smp.c
 *
 * Interrupt entry/exit code at both C and assembly level
 */

extern void mask_irq(unsigned int irq);
extern void unmask_irq(unsigned int irq);
extern void disable_8259A_irq(unsigned int irq);
extern void enable_8259A_irq(unsigned int irq);
extern int i8259A_irq_pending(unsigned int irq);
extern void make_8259A_irq(unsigned int irq);
extern void init_8259A(int aeoi);
extern void send_IPI_self(int vector);
extern void init_VISWS_APIC_irqs(void);
extern void setup_IO_APIC(void);
extern void disable_IO_APIC(void);
extern void print_IO_APIC(void);
extern int IO_APIC_get_PCI_irq_vector(int bus, int slot, int fn);
extern void send_IPI(int dest, int vector);

extern unsigned long io_apic_irqs;

extern atomic_t irq_err_count;
extern atomic_t irq_mis_count;

extern char _stext, _etext;

#define IO_APIC_IRQ(x) (((x) >= 16) || ((1<<(x)) & io_apic_irqs))

#include <xen/irq.h>

static inline void hw_resend_irq(struct hw_interrupt_type *h, unsigned int i)
{
#if defined(CONFIG_X86_IO_APIC)
    if (IO_APIC_IRQ(i))
        send_IPI_self(IO_APIC_VECTOR(i));
#endif
}

#endif /* _ASM_HW_IRQ_H */
