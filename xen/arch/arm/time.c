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
#include <asm/vgic.h>
#include <asm/cpufeature.h>
#include <asm/platform.h>

uint64_t __read_mostly boot_count;

/* For fine-grained timekeeping, we use the ARM "Generic Timer", a
 * register-mapped time source in the SoC. */
unsigned long __read_mostly cpu_khz;  /* CPU clock frequency in kHz. */

static unsigned int timer_irq[MAX_TIMER_PPI];

unsigned int timer_get_irq(enum timer_ppi ppi)
{
    ASSERT(ppi >= TIMER_PHYS_SECURE_PPI && ppi < MAX_TIMER_PPI);

    return timer_irq[ppi];
}

/*static inline*/ s_time_t ticks_to_ns(uint64_t ticks)
{
    return muldiv64(ticks, SECONDS(1), 1000 * cpu_khz);
}

/*static inline*/ uint64_t ns_to_ticks(s_time_t ns)
{
    return muldiv64(ns, 1000 * cpu_khz, SECONDS(1));
}

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
        res = platform_get_irq(dev, i);

        if ( res < 0 )
            panic("Timer: Unable to retrieve IRQ %u from the device tree", i);
        timer_irq[i] = res;
    }

    printk("Generic Timer IRQ: phys=%u hyp=%u virt=%u\n",
           timer_irq[TIMER_PHYS_NONSECURE_PPI],
           timer_irq[TIMER_HYP_PPI],
           timer_irq[TIMER_VIRT_PPI]);

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
        WRITE_SYSREG32(0, CNTHP_CTL_EL2);
        return 1;
    }

    deadline = ns_to_ticks(timeout) + boot_count;
    WRITE_SYSREG64(deadline, CNTHP_CVAL_EL2);
    WRITE_SYSREG32(CNTx_CTL_ENABLE, CNTHP_CTL_EL2);
    isb();

    /* No need to check for timers in the past; the Generic Timer fires
     * on a signed 63-bit comparison. */
    return 1;
}

/* Handle the firing timer */
static void timer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    if ( irq == (timer_irq[TIMER_HYP_PPI]) &&
         READ_SYSREG32(CNTHP_CTL_EL2) & CNTx_CTL_PENDING )
    {
        /* Signal the generic timer code to do its work */
        raise_softirq(TIMER_SOFTIRQ);
        /* Disable the timer to avoid more interrupts */
        WRITE_SYSREG32(0, CNTHP_CTL_EL2);
    }

    if ( irq == (timer_irq[TIMER_PHYS_NONSECURE_PPI]) &&
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
    vgic_vcpu_inject_irq(current, current->arch.virt_timer.irq);
}

/* Set up the timer interrupt on this CPU */
void __cpuinit init_timer_interrupt(void)
{
    /* Sensible defaults */
    WRITE_SYSREG64(0, CNTVOFF_EL2);     /* No VM-specific offset */
    /* Do not let the VMs program the physical timer, only read the physical counter */
    WRITE_SYSREG32(CNTHCTL_PA, CNTHCTL_EL2);
    WRITE_SYSREG32(0, CNTP_CTL_EL0);    /* Physical timer disabled */
    WRITE_SYSREG32(0, CNTHP_CTL_EL2);   /* Hypervisor's timer disabled */
    isb();

    request_irq(timer_irq[TIMER_HYP_PPI], 0, timer_interrupt,
                "hyptimer", NULL);
    request_irq(timer_irq[TIMER_VIRT_PPI], 0, vtimer_interrupt,
                   "virtimer", NULL);
    request_irq(timer_irq[TIMER_PHYS_NONSECURE_PPI], 0, timer_interrupt,
                "phytimer", NULL);
}

/* Wait a set number of microseconds */
void udelay(unsigned long usecs)
{
    s_time_t deadline = get_s_time() + 1000 * (s_time_t) usecs;
    while ( get_s_time() - deadline < 0 )
        ;
    dsb(sy);
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

struct tm wallclock_time(uint64_t *ns)
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
