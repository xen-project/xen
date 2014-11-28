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
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/softirq.h>
#include <xen/sched.h>
#include <xen/time.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/system.h>
#include <asm/time.h>
#include <asm/gic.h>
#include <asm/cpufeature.h>
#include <asm/platform.h>

/*
 * Unfortunately the hypervisor timer interrupt appears to be buggy in
 * some versions of the model. Disable this to use the physical timer
 * instead.
 */
#define USE_HYP_TIMER 1

uint64_t __read_mostly boot_count;

/* For fine-grained timekeeping, we use the ARM "Generic Timer", a
 * register-mapped time source in the SoC. */
unsigned long __read_mostly cpu_khz;  /* CPU clock frequency in kHz. */

static struct dt_irq timer_irq[MAX_TIMER_PPI];

const struct dt_irq *timer_dt_irq(enum timer_ppi ppi)
{
    ASSERT(ppi >= TIMER_PHYS_SECURE_PPI && ppi < MAX_TIMER_PPI);

    return &timer_irq[ppi];
}

/*static inline*/ s_time_t ticks_to_ns(uint64_t ticks)
{
    return muldiv64(ticks, SECONDS(1), 1000 * cpu_khz);
}

/*static inline*/ uint64_t ns_to_ticks(s_time_t ns)
{
    return muldiv64(ns, 1000 * cpu_khz, SECONDS(1));
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
    start = READ_SYSREG64(CNTPCT_EL0);
    do {} while ( rtc[0] < sec + 32 );
    end = READ_SYSREG64(CNTPCT_EL0);
    printk("done.\n");

    clear_fixmap(FIXMAP_MISC);
    return (end - start) / 32;
}
*/

/* Set up the timer on the boot CPU */
int __init init_xen_time(void)
{
    static const struct dt_device_match timer_ids[] __initconst =
    {
        DT_MATCH_TIMER,
        { /* sentinel */ },
    };
    struct dt_device_node *dev;
    int res;
    unsigned int i;
    u32 rate;

    dev = dt_find_matching_node(NULL, timer_ids);
    if ( !dev )
        panic("Unable to find a compatible timer in the device tree");

    dt_device_set_used_by(dev, DOMID_XEN);

    /* Retrieve all IRQs for the timer */
    for ( i = TIMER_PHYS_SECURE_PPI; i < MAX_TIMER_PPI; i++ )
    {
        res = dt_device_get_irq(dev, i, &timer_irq[i]);
        if ( res )
            panic("Timer: Unable to retrieve IRQ %u from the device tree", i);
    }

    printk("Generic Timer IRQ: phys=%u hyp=%u virt=%u\n",
           timer_irq[TIMER_PHYS_NONSECURE_PPI].irq,
           timer_irq[TIMER_HYP_PPI].irq,
           timer_irq[TIMER_VIRT_PPI].irq);

    res = platform_init_time();
    if ( res )
        panic("Timer: Cannot initialize platform timer");

    /* Check that this CPU supports the Generic Timer interface */
    if ( !cpu_has_gentimer )
        panic("CPU does not support the Generic Timer v1 interface");

    res = dt_property_read_u32(dev, "clock-frequency", &rate);
    if ( res )
        cpu_khz = rate / 1000;
    else
        cpu_khz = READ_SYSREG32(CNTFRQ_EL0) / 1000;

    boot_count = READ_SYSREG64(CNTPCT_EL0);
    printk("Using generic timer at %lu KHz\n", cpu_khz);

    return 0;
}

/* Return number of nanoseconds since boot */
s_time_t get_s_time(void)
{
    uint64_t ticks = READ_SYSREG64(CNTPCT_EL0) - boot_count;
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
        WRITE_SYSREG32(0, CNTHP_CTL_EL2);
#else
        WRITE_SYSREG32(0, CNTP_CTL_EL0);
#endif
        return 1;
    }

    deadline = ns_to_ticks(timeout) + boot_count;
#if USE_HYP_TIMER
    WRITE_SYSREG64(deadline, CNTHP_CVAL_EL2);
    WRITE_SYSREG32(CNTx_CTL_ENABLE, CNTHP_CTL_EL2);
#else
    WRITE_SYSREG64(deadline, CNTP_CVAL_EL0);
    WRITE_SYSREG32(CNTx_CTL_ENABLE, CNTP_CTL_EL0);
#endif
    isb();

    /* No need to check for timers in the past; the Generic Timer fires
     * on a signed 63-bit comparison. */
    return 1;
}

/* Handle the firing timer */
static void timer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    if ( irq == (timer_irq[TIMER_HYP_PPI].irq) &&
         READ_SYSREG32(CNTHP_CTL_EL2) & CNTx_CTL_PENDING )
    {
        /* Signal the generic timer code to do its work */
        raise_softirq(TIMER_SOFTIRQ);
        /* Disable the timer to avoid more interrupts */
        WRITE_SYSREG32(0, CNTHP_CTL_EL2);
    }

    if ( irq == (timer_irq[TIMER_PHYS_NONSECURE_PPI].irq) &&
         READ_SYSREG32(CNTP_CTL_EL0) & CNTx_CTL_PENDING )
    {
        /* Signal the generic timer code to do its work */
        raise_softirq(TIMER_SOFTIRQ);
        /* Disable the timer to avoid more interrupts */
        WRITE_SYSREG32(0, CNTP_CTL_EL0);
    }
}

static void vtimer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    /*
     * Edge-triggered interrupts can be used for the virtual timer. Even
     * if the timer output signal is masked in the context switch, the
     * GIC will keep track that of any interrupts raised while IRQS are
     * disabled. As soon as IRQs are re-enabled, the virtual interrupt
     * will be injected to Xen.
     *
     * If an IDLE vCPU was scheduled next then we should ignore the
     * interrupt.
     */
    if ( unlikely(is_idle_vcpu(current)) )
        return;

    current->arch.virt_timer.ctl = READ_SYSREG32(CNTV_CTL_EL0);
    WRITE_SYSREG32(current->arch.virt_timer.ctl | CNTx_CTL_MASK, CNTV_CTL_EL0);
    vgic_vcpu_inject_irq(current, current->arch.virt_timer.irq, 1);
}

/* Route timer's IRQ on this CPU */
void __cpuinit route_timer_interrupt(void)
{
    gic_route_dt_irq(&timer_irq[TIMER_PHYS_NONSECURE_PPI],
                     cpumask_of(smp_processor_id()), 0xa0);
    gic_route_dt_irq(&timer_irq[TIMER_HYP_PPI],
                     cpumask_of(smp_processor_id()), 0xa0);
    gic_route_dt_irq(&timer_irq[TIMER_VIRT_PPI],
                     cpumask_of(smp_processor_id()), 0xa0);
}

/* Set up the timer interrupt on this CPU */
void __cpuinit init_timer_interrupt(void)
{
    /* Sensible defaults */
    WRITE_SYSREG64(0, CNTVOFF_EL2);     /* No VM-specific offset */
#if USE_HYP_TIMER
    /* Do not let the VMs program the physical timer, only read the physical counter */
    WRITE_SYSREG32(CNTHCTL_PA, CNTHCTL_EL2);
#else
    /* Cannot let VMs access physical counter if we are using it */
    WRITE_SYSREG32(0, CNTHCTL_EL2);
#endif
    WRITE_SYSREG32(0, CNTP_CTL_EL0);    /* Physical timer disabled */
    WRITE_SYSREG32(0, CNTHP_CTL_EL2);   /* Hypervisor's timer disabled */
    isb();

    request_dt_irq(&timer_irq[TIMER_HYP_PPI], timer_interrupt,
                   "hyptimer", NULL);
    request_dt_irq(&timer_irq[TIMER_VIRT_PPI], vtimer_interrupt,
                   "virtimer", NULL);
    request_dt_irq(&timer_irq[TIMER_PHYS_NONSECURE_PPI], timer_interrupt,
                   "phytimer", NULL);
}

/* Wait a set number of microseconds */
void udelay(unsigned long usecs)
{
    s_time_t deadline = get_s_time() + 1000 * (s_time_t) usecs;
    while ( get_s_time() - deadline < 0 )
        ;
    dsb();
    isb();
}

/* VCPU PV timers. */
void send_timer_event(struct vcpu *v)
{
    send_guest_vcpu_virq(v, VIRQ_TIMER);
}

/* VCPU PV clock. */
void update_vcpu_system_time(struct vcpu *v)
{
    /* XXX update shared_info->wc_* */
}

void domain_set_time_offset(struct domain *d, int32_t time_offset_seconds)
{
    d->time_offset_seconds = time_offset_seconds;
    /* XXX update guest visible wallclock time */
}

struct tm wallclock_time(void)
{
    return (struct tm) { 0 };
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
