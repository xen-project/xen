/*
 *  linux/arch/i386/kernel/time.c
 *
 *  Copyright (C) 1991, 1992, 1995  Linus Torvalds
 */

#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/lib.h>
#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/interrupt.h>
#include <xeno/time.h>

#include <asm/io.h>
#include <xeno/smp.h>
#include <xeno/irq.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#include <asm/fixmap.h>

unsigned long cpu_khz;	/* Detected as we calibrate the TSC */
unsigned long ticks_per_usec; /* TSC ticks per microsecond. */

spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;

/*
 * timer_interrupt() needs to keep up the real-time clock,
 * as well as call the "do_timer()" routine every clocktick
 */
int timer_ack=0;
extern spinlock_t i8259A_lock;
static inline void do_timer_interrupt(int irq, 
                                      void *dev_id, struct pt_regs *regs)
{
#ifdef CONFIG_X86_IO_APIC
    if (timer_ack) {
        /*
         * Subtle, when I/O APICs are used we have to ack timer IRQ
         * manually to reset the IRR bit for do_slow_gettimeoffset().
         * This will also deassert NMI lines for the watchdog if run
         * on an 82489DX-based system.
         */
        spin_lock(&i8259A_lock);
        outb(0x0c, 0x20);
        /* Ack the IRQ; AEOI will end it automatically. */
        inb(0x20);
        spin_unlock(&i8259A_lock);
    }
#endif
    do_timer(regs);
}

/*
 * This is the same as the above, except we _also_ save the current
 * Time Stamp Counter value at the time of the timer interrupt, so that
 * we later on can estimate the time of day more exactly.
 */
static void timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    do_timer_interrupt(irq, NULL, regs);
}

static struct irqaction irq0  = { timer_interrupt, SA_INTERRUPT, 0, "timer", NULL, NULL};

/* ------ Calibrate the TSC ------- 
 * Return processor ticks per second / CALIBRATE_FRAC.
 */

#define CLOCK_TICK_RATE 1193180 /* system crystal frequency (Hz) */
#define CALIBRATE_FRAC  20     /* calibrate over 50ms */
#define CALIBRATE_LATCH ((CLOCK_TICK_RATE+(CALIBRATE_FRAC/2))/CALIBRATE_FRAC)

static unsigned long __init calibrate_tsc(void)
{
    /* Set the Gate high, disable speaker */
    outb((inb(0x61) & ~0x02) | 0x01, 0x61);

	/*
	 * Now let's take care of CTC channel 2
	 *
	 * Set the Gate high, program CTC channel 2 for mode 0,
	 * (interrupt on terminal count mode), binary count,
	 * load 5 * LATCH count, (LSB and MSB) to begin countdown.
	 */
    outb(0xb0, 0x43);			/* binary, mode 0, LSB/MSB, Ch 2 */
    outb(CALIBRATE_LATCH & 0xff, 0x42);	/* LSB of count */
    outb(CALIBRATE_LATCH >> 8, 0x42);	/* MSB of count */

    {
        unsigned long startlow, starthigh;
        unsigned long endlow, endhigh;
        unsigned long count;

        rdtsc(startlow,starthigh);
        count = 0;
        do {
            count++;
        } while ((inb(0x61) & 0x20) == 0);
        rdtsc(endlow,endhigh);

        /* Error: ECTCNEVERSET */
        if (count <= 1)
            goto bad_ctc;

        /* 64-bit subtract - gcc just messes up with long longs */
        __asm__("subl %2,%0\n\t"
                "sbbl %3,%1"
                :"=a" (endlow), "=d" (endhigh)
                :"g" (startlow), "g" (starthigh),
                "0" (endlow), "1" (endhigh));

        /* Error: ECPUTOOFAST */
        if (endhigh)
            goto bad_ctc;

        return endlow;
    }

    /*
     * The CTC wasn't reliable: we got a hit on the very first read, or the 
     * CPU was so fast/slow that the quotient wouldn't fit in 32 bits..
     */
 bad_ctc:
    return 0;
}

void __init time_init(void)
{
    unsigned long ticks_per_frac = calibrate_tsc();

    if ( !ticks_per_frac )
        panic("Error calibrating TSC\n");

    ticks_per_usec = ticks_per_frac / (1000000/CALIBRATE_FRAC);
    cpu_khz = ticks_per_frac / (1000/CALIBRATE_FRAC);

    printk("Detected %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    setup_irq(0, &irq0);
}
