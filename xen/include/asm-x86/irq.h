#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

/* (C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar */

#include <xen/config.h>
#include <asm/atomic.h>

extern void disable_irq(unsigned int);
extern void disable_irq_nosync(unsigned int);
extern void enable_irq(unsigned int);

/*
 * IDT vectors usable for external interrupt sources start
 * at 0x20:
 */
#define FIRST_EXTERNAL_VECTOR	0x30

#define NR_IRQS (256 - FIRST_EXTERNAL_VECTOR)

#define HYPERCALL_VECTOR	0x82

/*
 * Vectors 0x30-0x3f are used for ISA interrupts.
 */

/*
 * Special IRQ vectors used by the SMP architecture, 0xf0-0xff
 */
#define SPURIOUS_APIC_VECTOR	0xff
#define ERROR_APIC_VECTOR	0xfe
#define INVALIDATE_TLB_VECTOR	0xfd
#define EVENT_CHECK_VECTOR	0xfc
#define CALL_FUNCTION_VECTOR	0xfb
#define KDB_VECTOR		0xfa

/*
 * Local APIC timer IRQ vector is on a different priority level,
 * to work around the 'lost local interrupt if more than 2 IRQ
 * sources per level' errata.
 */
#define LOCAL_TIMER_VECTOR	0xef

/*
 * First APIC vector available to drivers: (vectors 0x40-0xee)
 * we start at 0x41 to spread out vectors evenly between priority
 * levels. (0x82 is the hypercall vector)
 */
#define FIRST_DEVICE_VECTOR	0x41
#define FIRST_SYSTEM_VECTOR	0xef

extern int irq_vector[NR_IRQS];
#define IO_APIC_VECTOR(irq)	irq_vector[irq]

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

#define __STR(x) #x
#define STR(x) __STR(x)

#if defined(__i386__)

#define SAVE_ALL \
	"cld\n\t" \
	"pushl %gs\n\t" \
	"pushl %fs\n\t" \
	"pushl %es\n\t" \
	"pushl %ds\n\t" \
	"pushl %eax\n\t" \
	"pushl %ebp\n\t" \
	"pushl %edi\n\t" \
	"pushl %esi\n\t" \
	"pushl %edx\n\t" \
	"pushl %ecx\n\t" \
	"pushl %ebx\n\t" \
	"movl $" STR(__HYPERVISOR_DS) ",%edx\n\t" \
	"movl %edx,%ds\n\t" \
	"movl %edx,%es\n\t" \
	"movl %edx,%fs\n\t" \
	"movl %edx,%gs\n\t"

#else

#define SAVE_ALL

#endif

#define BUILD_SMP_INTERRUPT(x,v) XBUILD_SMP_INTERRUPT(x,v)
#define XBUILD_SMP_INTERRUPT(x,v)\
asmlinkage void x(void); \
asmlinkage void call_##x(void); \
__asm__( \
"\n"__ALIGN_STR"\n" \
SYMBOL_NAME_STR(x) ":\n\t" \
	"push"__OS" $"#v"\n\t" \
	SAVE_ALL \
	SYMBOL_NAME_STR(call_##x)":\n\t" \
	"call "SYMBOL_NAME_STR(smp_##x)"\n\t" \
	"jmp ret_from_intr\n");

#define BUILD_SMP_TIMER_INTERRUPT(x,v) XBUILD_SMP_TIMER_INTERRUPT(x,v)
#define XBUILD_SMP_TIMER_INTERRUPT(x,v) \
asmlinkage void x(struct xen_regs * regs); \
asmlinkage void call_##x(void); \
__asm__( \
"\n"__ALIGN_STR"\n" \
SYMBOL_NAME_STR(x) ":\n\t" \
	"push"__OS" $"#v"\n\t" \
	SAVE_ALL \
	"mov %"__OP"sp,%"__OP"ax\n\t" \
	"push %"__OP"ax\n\t" \
	SYMBOL_NAME_STR(call_##x)":\n\t" \
	"call "SYMBOL_NAME_STR(smp_##x)"\n\t" \
	"add $4,%"__OP"sp\n\t" \
	"jmp ret_from_intr\n");

#define BUILD_COMMON_IRQ() \
asmlinkage void call_do_IRQ(void); \
__asm__( \
	"\n" __ALIGN_STR"\n" \
	"common_interrupt:\n\t" \
	SAVE_ALL \
	SYMBOL_NAME_STR(call_do_IRQ)":\n\t" \
	"call " SYMBOL_NAME_STR(do_IRQ) "\n\t" \
	"jmp ret_from_intr\n");

#define IRQ_NAME2(nr) nr##_interrupt(void)
#define IRQ_NAME(nr) IRQ_NAME2(IRQ##nr)

#define BUILD_IRQ(nr) \
asmlinkage void IRQ_NAME(nr); \
__asm__( \
"\n"__ALIGN_STR"\n" \
SYMBOL_NAME_STR(IRQ) #nr "_interrupt:\n\t" \
	"push"__OS" $"#nr"\n\t" \
	"jmp common_interrupt");

extern unsigned long prof_cpu_mask;
extern unsigned int *prof_buffer;
extern unsigned long prof_len;
extern unsigned long prof_shift;

#include <xen/irq.h>

static inline void hw_resend_irq(struct hw_interrupt_type *h, unsigned int i)
{
#if defined(CONFIG_X86_IO_APIC)
        if (IO_APIC_IRQ(i))
                send_IPI_self(IO_APIC_VECTOR(i));
#endif
}

#endif /* _ASM_HW_IRQ_H */
