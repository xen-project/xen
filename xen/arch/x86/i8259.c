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
#include <xen/bitops.h>
#include <xen/delay.h>
#include <asm/apic.h>
#include <asm/asm_defns.h>
#include <io_ports.h>

/*
 * This is the 'legacy' 8259A Programmable Interrupt Controller,
 * present in the majority of PC/AT boxes.
 * plus some generic x86 specific things if generic specifics makes
 * any sense at all.
 * this file should become arch/i386/kernel/irq.c when the old irq.c
 * moves to arch independent land
 */

static DEFINE_SPINLOCK(i8259A_lock);

static bool_t _mask_and_ack_8259A_irq(unsigned int irq);

bool_t bogus_8259A_irq(unsigned int irq)
{
    return _mask_and_ack_8259A_irq(irq);
}

static void mask_and_ack_8259A_irq(struct irq_desc *desc)
{
    _mask_and_ack_8259A_irq(desc->irq);
}

static unsigned int startup_8259A_irq(struct irq_desc *desc)
{
    enable_8259A_irq(desc);
    return 0; /* never anything pending */
}

static void end_8259A_irq(struct irq_desc *desc, u8 vector)
{
    if (!(desc->status & (IRQ_DISABLED|IRQ_INPROGRESS)))
        enable_8259A_irq(desc);
}

static struct hw_interrupt_type __read_mostly i8259A_irq_type = {
    .typename = "XT-PIC",
    .startup  = startup_8259A_irq,
    .shutdown = disable_8259A_irq,
    .enable   = enable_8259A_irq,
    .disable  = disable_8259A_irq,
    .ack      = mask_and_ack_8259A_irq,
    .end      = end_8259A_irq
};

/*
 * 8259A PIC functions to handle ISA devices:
 */

#define aeoi_mode (i8259A_irq_type.ack == disable_8259A_irq)

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
unsigned int __read_mostly io_apic_irqs;

static void _disable_8259A_irq(unsigned int irq)
{
    unsigned int mask = 1 << irq;
    unsigned long flags;

    spin_lock_irqsave(&i8259A_lock, flags);
    cached_irq_mask |= mask;
    if (irq & 8)
        outb(cached_A1,0xA1);
    else
        outb(cached_21,0x21);
    per_cpu(vector_irq, 0)[LEGACY_VECTOR(irq)] = ~irq;
    spin_unlock_irqrestore(&i8259A_lock, flags);
}

void disable_8259A_irq(struct irq_desc *desc)
{
    _disable_8259A_irq(desc->irq);
}

void enable_8259A_irq(struct irq_desc *desc)
{
    unsigned int mask = ~(1 << desc->irq);
    unsigned long flags;

    spin_lock_irqsave(&i8259A_lock, flags);
    cached_irq_mask &= mask;
    per_cpu(vector_irq, 0)[LEGACY_VECTOR(desc->irq)] = desc->irq;
    if (desc->irq & 8)
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

void mask_8259A(void)
{
    unsigned long flags;

    spin_lock_irqsave(&i8259A_lock, flags);
    outb(0xff, 0xA1);
    outb(0xff, 0x21);
    spin_unlock_irqrestore(&i8259A_lock, flags);
}

void unmask_8259A(void)
{
    unsigned long flags;

    spin_lock_irqsave(&i8259A_lock, flags);
    outb(cached_A1, 0xA1);
    outb(cached_21, 0x21);
    spin_unlock_irqrestore(&i8259A_lock, flags);
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
 * to the two 8259s is important!  Return a boolean
 * indicating whether the irq was genuine or spurious.
 */
static bool_t _mask_and_ack_8259A_irq(unsigned int irq)
{
    unsigned int irqmask = 1 << irq;
    unsigned long flags;
    bool_t is_real_irq = 1; /* Assume real unless spurious */

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
    if ((cached_irq_mask & irqmask) && !i8259A_irq_real(irq)) {
        static int spurious_irq_mask;
        is_real_irq = 0;
        /* Report spurious IRQ, once per IRQ line. */
        if (!(spurious_irq_mask & irqmask)) {
            printk("spurious 8259A interrupt: IRQ%d.\n", irq);
            spurious_irq_mask |= irqmask;
        }
        /*
         * Theoretically we do not have to handle this IRQ,
         * but in Linux this does not cause problems and is
         * simpler for us.
         */
    }

    cached_irq_mask |= irqmask;

    if (irq & 8) {
        inb(0xA1);              /* DUMMY - (do we need this?) */
        outb(cached_A1,0xA1);
        if (!aeoi_mode) {
            outb(0x60 + (irq & 7), 0xA0);/* 'Specific EOI' to slave */
            outb(0x62,0x20);        /* 'Specific EOI' to master-IRQ2 */
        }
    } else {
        inb(0x21);              /* DUMMY - (do we need this?) */
        outb(cached_21,0x21);
        if (!aeoi_mode)
            outb(0x60 + irq, 0x20);/* 'Specific EOI' to master */
    }

    spin_unlock_irqrestore(&i8259A_lock, flags);

    return is_real_irq;
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
    init_8259A(aeoi_mode);
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
        i8259A_irq_type.ack = disable_8259A_irq;
    else
        i8259A_irq_type.ack = mask_and_ack_8259A_irq;

    udelay(100);            /* wait for 8259A to initialize */

    outb(cached_21, 0x21);  /* restore master IRQ mask */
    outb(cached_A1, 0xA1);  /* restore slave IRQ mask */

    spin_unlock_irqrestore(&i8259A_lock, flags);
}

void __init make_8259A_irq(unsigned int irq)
{
    io_apic_irqs &= ~(1 << irq);
    irq_to_desc(irq)->handler = &i8259A_irq_type;
}

static struct irqaction __read_mostly cascade = { no_action, "cascade", NULL};

void __init init_IRQ(void)
{
    int irq, cpu = smp_processor_id();

    init_bsp_APIC();

    init_8259A(0);

    BUG_ON(init_irq_data() < 0);

    for (irq = 0; platform_legacy_irq(irq); irq++) {
        struct irq_desc *desc = irq_to_desc(irq);
        
        if ( irq == 2 ) /* IRQ2 doesn't exist */
            continue;
        desc->handler = &i8259A_irq_type;
        per_cpu(vector_irq, cpu)[FIRST_LEGACY_VECTOR + irq] = irq;
        cpumask_copy(desc->arch.cpu_mask, cpumask_of(cpu));
        desc->arch.vector = FIRST_LEGACY_VECTOR + irq;
    }
    
    per_cpu(vector_irq, cpu)[IRQ0_VECTOR] = 0;

    apic_intr_init();

    /* Set the clock to HZ Hz */
#define CLOCK_TICK_RATE 1193182 /* crystal freq (Hz) */
#define LATCH (((CLOCK_TICK_RATE)+(HZ/2))/HZ)
    outb_p(0x34, PIT_MODE);        /* binary, mode 2, LSB/MSB, ch 0 */
    outb_p(LATCH & 0xff, PIT_CH0); /* LSB */
    outb(LATCH >> 8, PIT_CH0);     /* MSB */

    setup_irq(2, 0, &cascade);
}

