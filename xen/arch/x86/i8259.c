/******************************************************************************
 * i8259.c
 * 
 * Well, this is required for SMP systems as well, as it build interrupt
 * tables for IO APICS as well as uniprocessor 8259-alikes.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <asm/regs.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/desc.h>
#include <asm/bitops.h>
#include <xen/delay.h>
#include <asm/apic.h>
#include <asm/asm_defns.h>
#include <io_ports.h>

/*
 * Common place to define all x86 IRQ vectors
 *
 * This builds up the IRQ handler stubs using some ugly macros in irq.h
 *
 * These macros create the low-level assembly IRQ routines that save
 * register context and call do_IRQ(). do_IRQ() then does all the
 * operations that are needed to keep the AT (or SMP IOAPIC)
 * interrupt-controller happy.
 */

BUILD_COMMON_IRQ()

#define BI(x,y) \
    BUILD_IRQ(x##y)

#define BUILD_16_IRQS(x) \
    BI(x,0) BI(x,1) BI(x,2) BI(x,3) \
    BI(x,4) BI(x,5) BI(x,6) BI(x,7) \
    BI(x,8) BI(x,9) BI(x,a) BI(x,b) \
    BI(x,c) BI(x,d) BI(x,e) BI(x,f)

BUILD_16_IRQS(0x0) BUILD_16_IRQS(0x1) BUILD_16_IRQS(0x2) BUILD_16_IRQS(0x3)
BUILD_16_IRQS(0x4) BUILD_16_IRQS(0x5) BUILD_16_IRQS(0x6) BUILD_16_IRQS(0x7)
BUILD_16_IRQS(0x8) BUILD_16_IRQS(0x9) BUILD_16_IRQS(0xa) BUILD_16_IRQS(0xb)
BUILD_16_IRQS(0xc) BUILD_16_IRQS(0xd) BUILD_16_IRQS(0xe) BUILD_16_IRQS(0xf)

#undef BUILD_16_IRQS
#undef BI


/*
 * The following vectors are part of the Linux architecture, there
 * is no hardware IRQ pin equivalent for them, they are triggered
 * through the ICC by us (IPIs)
 */
BUILD_SMP_INTERRUPT(event_check_interrupt,EVENT_CHECK_VECTOR)
BUILD_SMP_INTERRUPT(invalidate_interrupt,INVALIDATE_TLB_VECTOR)
BUILD_SMP_INTERRUPT(call_function_interrupt,CALL_FUNCTION_VECTOR)

/*
 * Every pentium local APIC has two 'local interrupts', with a
 * soft-definable vector attached to both interrupts, one of
 * which is a timer interrupt, the other one is error counter
 * overflow. Linux uses the local APIC timer interrupt to get
 * a much simpler SMP time architecture:
 */
BUILD_SMP_INTERRUPT(apic_timer_interrupt,LOCAL_TIMER_VECTOR)
BUILD_SMP_INTERRUPT(error_interrupt,ERROR_APIC_VECTOR)
BUILD_SMP_INTERRUPT(spurious_interrupt,SPURIOUS_APIC_VECTOR)
BUILD_SMP_INTERRUPT(pmu_apic_interrupt,PMU_APIC_VECTOR)
BUILD_SMP_INTERRUPT(thermal_interrupt,THERMAL_APIC_VECTOR)
BUILD_SMP_INTERRUPT(cmci_interrupt, CMCI_APIC_VECTOR)

#define IRQ(x,y) \
    IRQ##x##y##_interrupt

#define IRQLIST_16(x) \
    IRQ(x,0), IRQ(x,1), IRQ(x,2), IRQ(x,3), \
    IRQ(x,4), IRQ(x,5), IRQ(x,6), IRQ(x,7), \
    IRQ(x,8), IRQ(x,9), IRQ(x,a), IRQ(x,b), \
    IRQ(x,c), IRQ(x,d), IRQ(x,e), IRQ(x,f)

    static void (*interrupt[])(void) = {
        IRQLIST_16(0x0), IRQLIST_16(0x1), IRQLIST_16(0x2), IRQLIST_16(0x3),
        IRQLIST_16(0x4), IRQLIST_16(0x5), IRQLIST_16(0x6), IRQLIST_16(0x7),
        IRQLIST_16(0x8), IRQLIST_16(0x9), IRQLIST_16(0xa), IRQLIST_16(0xb),
        IRQLIST_16(0xc), IRQLIST_16(0xd), IRQLIST_16(0xe), IRQLIST_16(0xf)
    };

#undef IRQ
#undef IRQLIST_16

/*
 * This is the 'legacy' 8259A Programmable Interrupt Controller,
 * present in the majority of PC/AT boxes.
 * plus some generic x86 specific things if generic specifics makes
 * any sense at all.
 * this file should become arch/i386/kernel/irq.c when the old irq.c
 * moves to arch independent land
 */

static DEFINE_SPINLOCK(i8259A_lock);

static void disable_8259A_vector(unsigned int vector)
{
    disable_8259A_irq(LEGACY_IRQ_FROM_VECTOR(vector));
}

static void enable_8259A_vector(unsigned int vector)
{
    enable_8259A_irq(LEGACY_IRQ_FROM_VECTOR(vector));
}

static void mask_and_ack_8259A_vector(unsigned int);

static void end_8259A_vector(unsigned int vector)
{
    if (!(irq_desc[vector].status & (IRQ_DISABLED|IRQ_INPROGRESS)))
        enable_8259A_vector(vector);
}

static unsigned int startup_8259A_vector(unsigned int vector)
{ 
    enable_8259A_vector(vector);
    return 0; /* never anything pending */
}

static struct hw_interrupt_type i8259A_irq_type = {
    .typename = "XT-PIC",
    .startup  = startup_8259A_vector,
    .shutdown = disable_8259A_vector,
    .enable   = enable_8259A_vector,
    .disable  = disable_8259A_vector,
    .ack      = mask_and_ack_8259A_vector,
    .end      = end_8259A_vector
};

/*
 * 8259A PIC functions to handle ISA devices:
 */

/*
 * This contains the irq mask for both 8259A irq controllers,
 */
static unsigned int cached_irq_mask = 0xffff;

#define __byte(x,y) (((unsigned char *)&(y))[x])
#define cached_21   (__byte(0,cached_irq_mask))
#define cached_A1   (__byte(1,cached_irq_mask))

/*
 * Not all IRQs can be routed through the IO-APIC, eg. on certain (older)
 * boards the timer interrupt is not really connected to any IO-APIC pin,
 * it's fed to the master 8259A's IR0 line only.
 *
 * Any '1' bit in this mask means the IRQ is routed through the IO-APIC.
 * this 'mixed mode' IRQ handling costs nothing because it's only used
 * at IRQ setup time.
 */
unsigned long io_apic_irqs;

void disable_8259A_irq(unsigned int irq)
{
    unsigned int mask = 1 << irq;
    unsigned long flags;

    spin_lock_irqsave(&i8259A_lock, flags);
    cached_irq_mask |= mask;
    if (irq & 8)
        outb(cached_A1,0xA1);
    else
        outb(cached_21,0x21);
    spin_unlock_irqrestore(&i8259A_lock, flags);
}

void enable_8259A_irq(unsigned int irq)
{
    unsigned int mask = ~(1 << irq);
    unsigned long flags;

    spin_lock_irqsave(&i8259A_lock, flags);
    cached_irq_mask &= mask;
    if (irq & 8)
        outb(cached_A1,0xA1);
    else
        outb(cached_21,0x21);
    spin_unlock_irqrestore(&i8259A_lock, flags);
}

int i8259A_irq_pending(unsigned int irq)
{
    unsigned int mask = 1<<irq;
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&i8259A_lock, flags);
    if (irq < 8)
        ret = inb(0x20) & mask;
    else
        ret = inb(0xA0) & (mask >> 8);
    spin_unlock_irqrestore(&i8259A_lock, flags);

    return ret;
}

/*
 * This function assumes to be called rarely. Switching between
 * 8259A registers is slow.
 * This has to be protected by the irq controller spinlock
 * before being called.
 */
static inline int i8259A_irq_real(unsigned int irq)
{
    int value;
    int irqmask = 1<<irq;

    if (irq < 8) {
        outb(0x0B,0x20);                /* ISR register */
        value = inb(0x20) & irqmask;
        outb(0x0A,0x20);                /* back to the IRR register */
        return value;
    }
    outb(0x0B,0xA0);                    /* ISR register */
    value = inb(0xA0) & (irqmask >> 8);
    outb(0x0A,0xA0);                    /* back to the IRR register */
    return value;
}

/*
 * Careful! The 8259A is a fragile beast, it pretty
 * much _has_ to be done exactly like this (mask it
 * first, _then_ send the EOI, and the order of EOI
 * to the two 8259s is important!
 */
static void mask_and_ack_8259A_vector(unsigned int vector)
{
    unsigned int irq = LEGACY_IRQ_FROM_VECTOR(vector);
    unsigned int irqmask = 1 << irq;
    unsigned long flags;

    spin_lock_irqsave(&i8259A_lock, flags);
    /*
     * Lightweight spurious IRQ detection. We do not want
     * to overdo spurious IRQ handling - it's usually a sign
     * of hardware problems, so we only do the checks we can
     * do without slowing down good hardware unnecesserily.
     *
     * Note that IRQ7 and IRQ15 (the two spurious IRQs
     * usually resulting from the 8259A-1|2 PICs) occur
     * even if the IRQ is masked in the 8259A. Thus we
     * can check spurious 8259A IRQs without doing the
     * quite slow i8259A_irq_real() call for every IRQ.
     * This does not cover 100% of spurious interrupts,
     * but should be enough to warn the user that there
     * is something bad going on ...
     */
    if (cached_irq_mask & irqmask)
        goto spurious_8259A_irq;
    cached_irq_mask |= irqmask;

 handle_real_irq:
    if (irq & 8) {
        inb(0xA1);              /* DUMMY - (do we need this?) */
        outb(cached_A1,0xA1);
        outb(0x60+(irq&7),0xA0);/* 'Specific EOI' to slave */
        outb(0x62,0x20);        /* 'Specific EOI' to master-IRQ2 */
    } else {
        inb(0x21);              /* DUMMY - (do we need this?) */
        outb(cached_21,0x21);
        outb(0x60+irq,0x20);    /* 'Specific EOI' to master */
    }
    spin_unlock_irqrestore(&i8259A_lock, flags);
    return;

 spurious_8259A_irq:
    /*
     * this is the slow path - should happen rarely.
     */
    if (i8259A_irq_real(irq))
        /*
         * oops, the IRQ _is_ in service according to the
         * 8259A - not spurious, go handle it.
         */
        goto handle_real_irq;

    {
        static int spurious_irq_mask;
        /*
         * At this point we can be sure the IRQ is spurious,
         * lets ACK and report it. [once per IRQ]
         */
        if (!(spurious_irq_mask & irqmask)) {
            printk("spurious 8259A interrupt: IRQ%d.\n", irq);
            spurious_irq_mask |= irqmask;
        }
        atomic_inc(&irq_err_count);
        /*
         * Theoretically we do not have to handle this IRQ,
         * but in Linux this does not cause problems and is
         * simpler for us.
         */
        goto handle_real_irq;
    }
}

static char irq_trigger[2];
/**
 * ELCR registers (0x4d0, 0x4d1) control edge/level of IRQ
 */
static void restore_ELCR(char *trigger)
{
    outb(trigger[0], 0x4d0);
    outb(trigger[1], 0x4d1);
}

static void save_ELCR(char *trigger)
{
    /* IRQ 0,1,2,8,13 are marked as reserved */
    trigger[0] = inb(0x4d0) & 0xF8;
    trigger[1] = inb(0x4d1) & 0xDE;
}

int i8259A_resume(void)
{
    init_8259A(0);
    restore_ELCR(irq_trigger);
    return 0;
}

int i8259A_suspend(void)
{
    save_ELCR(irq_trigger);
    return 0;
}

void __devinit init_8259A(int auto_eoi)
{
    unsigned long flags;

    spin_lock_irqsave(&i8259A_lock, flags);

    outb(0xff, 0x21);   /* mask all of 8259A-1 */
    outb(0xff, 0xA1);   /* mask all of 8259A-2 */

    /*
     * outb_p - this has to work on a wide range of PC hardware.
     */
    outb_p(0x11, 0x20);     /* ICW1: select 8259A-1 init */
    outb_p(FIRST_LEGACY_VECTOR + 0, 0x21); /* ICW2: 8259A-1 IR0-7 */
    outb_p(0x04, 0x21);     /* 8259A-1 (the master) has a slave on IR2 */
    if (auto_eoi)
        outb_p(0x03, 0x21); /* master does Auto EOI */
    else
        outb_p(0x01, 0x21); /* master expects normal EOI */

    outb_p(0x11, 0xA0);     /* ICW1: select 8259A-2 init */
    outb_p(FIRST_LEGACY_VECTOR + 8, 0xA1); /* ICW2: 8259A-2 IR0-7 */
    outb_p(0x02, 0xA1);     /* 8259A-2 is a slave on master's IR2 */
    outb_p(0x01, 0xA1);     /* (slave's support for AEOI in flat mode
                               is to be investigated) */

    if (auto_eoi)
        /*
         * in AEOI mode we just have to mask the interrupt
         * when acking.
         */
        i8259A_irq_type.ack = disable_8259A_vector;
    else
        i8259A_irq_type.ack = mask_and_ack_8259A_vector;

    udelay(100);            /* wait for 8259A to initialize */

    outb(cached_21, 0x21);  /* restore master IRQ mask */
    outb(cached_A1, 0xA1);  /* restore slave IRQ mask */

    spin_unlock_irqrestore(&i8259A_lock, flags);
}

static struct irqaction cascade = { no_action, "cascade", NULL};

void __init init_IRQ(void)
{
    int i;

    init_bsp_APIC();

    init_8259A(0);

    for ( i = 0; i < NR_VECTORS; i++ )
    {
        irq_desc[i].status  = IRQ_DISABLED;
        irq_desc[i].handler = &no_irq_type;
        irq_desc[i].action  = NULL;
        irq_desc[i].depth   = 1;
        spin_lock_init(&irq_desc[i].lock);
        cpus_setall(irq_desc[i].affinity);
        if ( i >= 0x20 )
            set_intr_gate(i, interrupt[i]);
    }

    irq_vector = xmalloc_array(u8, nr_irqs_gsi);
    memset(irq_vector, 0, nr_irqs_gsi * sizeof(*irq_vector));

    for ( i = 0; i < 16; i++ )
    {
        vector_irq[LEGACY_VECTOR(i)] = i;
        irq_desc[LEGACY_VECTOR(i)].handler = &i8259A_irq_type;
    }

    /* Never allocate the hypercall vector or Linux/BSD fast-trap vector. */
    vector_irq[HYPERCALL_VECTOR] = NEVER_ASSIGN_IRQ;
    vector_irq[0x80] = NEVER_ASSIGN_IRQ;

    apic_intr_init();

    /* Set the clock to HZ Hz */
#define CLOCK_TICK_RATE 1193182 /* crystal freq (Hz) */
#define LATCH (((CLOCK_TICK_RATE)+(HZ/2))/HZ)
    outb_p(0x34, PIT_MODE);        /* binary, mode 2, LSB/MSB, ch 0 */
    outb_p(LATCH & 0xff, PIT_CH0); /* LSB */
    outb(LATCH >> 8, PIT_CH0);     /* MSB */

    setup_irq(2, &cascade);
}

