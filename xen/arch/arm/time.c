/*
 * xen/arch/arm/time.c
 *
 * Time and timer support, using the ARM Generic Timer interfaces
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/config.h>
#include <xen/console.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <asm/system.h>

/* Unfortunately the hypervisor timer interrupt appears to be buggy */
#define USE_HYP_TIMER 0

/* For fine-grained timekeeping, we use the ARM "Generic Timer", a
 * register-mapped time source in the SoC. */
static uint32_t __read_mostly cntfrq;      /* Ticks per second */
static uint64_t __read_mostly boot_count;  /* Counter value at boot time */

/*static inline*/ s_time_t ticks_to_ns(uint64_t ticks)
{
    return muldiv64(ticks, SECONDS(1), cntfrq);
}

/*static inline*/ uint64_t ns_to_ticks(s_time_t ns)
{
    return muldiv64(ns, cntfrq, SECONDS(1));
}

/* TODO: On a real system the firmware would have set the frequency in
   the CNTFRQ register.  Also we'd need to use devicetree to find
   the RTC.  When we've seen some real systems, we can delete this.
static uint32_t calibrate_timer(void)
{
    uint32_t sec;
    uint64_t start, end;
    paddr_t rtc_base = 0x1C170000ull;
    volatile uint32_t *rtc;

    ASSERT(!local_irq_is_enabled());
    set_fixmap(FIXMAP_MISC, rtc_base >> PAGE_SHIFT, DEV_SHARED);
    rtc = (uint32_t *) FIXMAP_ADDR(FIXMAP_MISC);

    printk("Calibrating timer against RTC...");
    // Turn on the RTC
    rtc[3] = 1;
    // Wait for an edge
    sec = rtc[0] + 1;
    do {} while ( rtc[0] != sec );
    // Now time a few seconds
    start = READ_CP64(CNTPCT);
    do {} while ( rtc[0] < sec + 32 );
    end = READ_CP64(CNTPCT);
    printk("done.\n");

    clear_fixmap(FIXMAP_MISC);
    return (end - start) / 32;
}
*/

/* Set up the timer on the boot CPU */
int __init init_xen_time(void)
{
    /* Check that this CPU supports the Generic Timer interface */
    if ( (READ_CP32(ID_PFR1) & ID_PFR1_GT_MASK) != ID_PFR1_GT_v1 )
        panic("CPU does not support the Generic Timer v1 interface.\n");

    cntfrq = READ_CP32(CNTFRQ);
    boot_count = READ_CP64(CNTPCT);
    printk("Using generic timer at %"PRIu32" Hz\n", cntfrq);

    return 0;
}

/* Return number of nanoseconds since boot */
s_time_t get_s_time(void)
{
    uint64_t ticks = READ_CP64(CNTPCT) - boot_count;
    return ticks_to_ns(ticks);
}

/* Set the timer to wake us up at a particular time.
 * Timeout is a Xen system time (nanoseconds since boot); 0 disables the timer.
 * Returns 1 on success; 0 if the timeout is too soon or is in the past. */
int reprogram_timer(s_time_t timeout)
{
    uint64_t deadline;

    if ( timeout == 0 )
    {
#if USE_HYP_TIMER
        WRITE_CP32(0, CNTHP_CTL);
#else
        WRITE_CP32(0, CNTP_CTL);
#endif
        return 1;
    }

    deadline = ns_to_ticks(timeout) + boot_count;
#if USE_HYP_TIMER
    WRITE_CP64(deadline, CNTHP_CVAL);
    WRITE_CP32(CNTx_CTL_ENABLE, CNTHP_CTL);
#else
    WRITE_CP64(deadline, CNTP_CVAL);
    WRITE_CP32(CNTx_CTL_ENABLE, CNTP_CTL);
#endif
    isb();

    /* No need to check for timers in the past; the Generic Timer fires
     * on a signed 63-bit comparison. */
    return 1;
}

/* Handle the firing timer */
static void timer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    if ( irq == 26 && READ_CP32(CNTHP_CTL) & CNTx_CTL_PENDING )
    {
        /* Signal the generic timer code to do its work */
        raise_softirq(TIMER_SOFTIRQ);
        /* Disable the timer to avoid more interrupts */
        WRITE_CP32(0, CNTHP_CTL);
    }

    if (irq == 30 && READ_CP32(CNTP_CTL) & CNTx_CTL_PENDING )
    {
        /* Signal the generic timer code to do its work */
        raise_softirq(TIMER_SOFTIRQ);
        /* Disable the timer to avoid more interrupts */
        WRITE_CP32(0, CNTP_CTL);
    }
}

/* Set up the timer interrupt on this CPU */
void __cpuinit init_timer_interrupt(void)
{
    /* Sensible defaults */
    WRITE_CP64(0, CNTVOFF);     /* No VM-specific offset */
    WRITE_CP32(0, CNTKCTL);     /* No user-mode access */
#if USE_HYP_TIMER
    /* Let the VMs read the physical counter and timer so they can tell time */
    WRITE_CP32(CNTHCTL_PA|CNTHCTL_TA, CNTHCTL);
#else
    /* Cannot let VMs access physical counter if we are using it */
    WRITE_CP32(0, CNTHCTL);
#endif
    WRITE_CP32(0, CNTP_CTL);    /* Physical timer disabled */
    WRITE_CP32(0, CNTHP_CTL);   /* Hypervisor's timer disabled */
    isb();

    /* XXX Need to find this IRQ number from devicetree? */
    request_irq(26, timer_interrupt, 0, "hyptimer", NULL);
    request_irq(30, timer_interrupt, 0, "phytimer", NULL);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
