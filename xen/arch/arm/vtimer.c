/*
 * xen/arch/arm/vtimer.c
 *
 * ARM Virtual Timer emulation support
 *
 * Ian Campbell <ian.campbell@citrix.com>
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

#include <xen/lib.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/timer.h>

#include <asm/cpregs.h>
#include <asm/div64.h>
#include <asm/gic.h>
#include <asm/irq.h>
#include <asm/regs.h>
#include <asm/time.h>
#include <asm/vgic.h>
#include <asm/vreg.h>
#include <asm/regs.h>

/*
 * Check if regs is allowed access, user_gate is tail end of a
 * CNTKCTL_EL1_ bit name which gates user access
 */
#define ACCESS_ALLOWED(regs, user_gate) \
    ( !psr_mode_is_user(regs) || \
      (READ_SYSREG(CNTKCTL_EL1) & CNTKCTL_EL1_##user_gate) )

static void phys_timer_expired(void *data)
{
    struct vtimer *t = data;
    t->ctl |= CNTx_CTL_PENDING;
    if ( !(t->ctl & CNTx_CTL_MASK) )
    {
        perfc_incr(vtimer_phys_inject);
        vgic_vcpu_inject_irq(t->v, t->irq);
    }
    else
        perfc_incr(vtimer_phys_masked);
}

static void virt_timer_expired(void *data)
{
    struct vtimer *t = data;
    t->ctl |= CNTx_CTL_MASK;
    vgic_vcpu_inject_irq(t->v, t->irq);
    perfc_incr(vtimer_virt_inject);
}

int domain_vtimer_init(struct domain *d, struct xen_arch_domainconfig *config)
{
    d->arch.phys_timer_base.offset = NOW();
    d->arch.virt_timer_base.offset = READ_SYSREG64(CNTPCT_EL0);
    d->time_offset_seconds = ticks_to_ns(d->arch.virt_timer_base.offset - boot_count);
    do_div(d->time_offset_seconds, 1000000000);

    config->clock_frequency = timer_dt_clock_frequency;

    /* At this stage vgic_reserve_virq can't fail */
    if ( is_hardware_domain(d) )
    {
        if ( !vgic_reserve_virq(d, timer_get_irq(TIMER_PHYS_SECURE_PPI)) )
            BUG();

        if ( !vgic_reserve_virq(d, timer_get_irq(TIMER_PHYS_NONSECURE_PPI)) )
            BUG();

        if ( !vgic_reserve_virq(d, timer_get_irq(TIMER_VIRT_PPI)) )
            BUG();
    }
    else
    {
        if ( !vgic_reserve_virq(d, GUEST_TIMER_PHYS_S_PPI) )
            BUG();

        if ( !vgic_reserve_virq(d, GUEST_TIMER_PHYS_NS_PPI) )
            BUG();

        if ( !vgic_reserve_virq(d, GUEST_TIMER_VIRT_PPI) )
            BUG();
    }

    return 0;
}

int vcpu_vtimer_init(struct vcpu *v)
{
    struct vtimer *t = &v->arch.phys_timer;
    bool d0 = is_hardware_domain(v->domain);

    /*
     * Hardware domain uses the hardware interrupts, guests get the virtual
     * platform.
     */

    init_timer(&t->timer, phys_timer_expired, t, v->processor);
    t->ctl = 0;
    t->cval = NOW();
    t->irq = d0
        ? timer_get_irq(TIMER_PHYS_NONSECURE_PPI)
        : GUEST_TIMER_PHYS_NS_PPI;
    t->v = v;

    t = &v->arch.virt_timer;
    init_timer(&t->timer, virt_timer_expired, t, v->processor);
    t->ctl = 0;
    t->irq = d0
        ? timer_get_irq(TIMER_VIRT_PPI)
        : GUEST_TIMER_VIRT_PPI;
    t->v = v;

    v->arch.vtimer_initialized = 1;

    return 0;
}

void vcpu_timer_destroy(struct vcpu *v)
{
    if ( !v->arch.vtimer_initialized )
        return;

    kill_timer(&v->arch.virt_timer.timer);
    kill_timer(&v->arch.phys_timer.timer);
}

int virt_timer_save(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

    v->arch.virt_timer.ctl = READ_SYSREG32(CNTV_CTL_EL0);
    WRITE_SYSREG32(v->arch.virt_timer.ctl & ~CNTx_CTL_ENABLE, CNTV_CTL_EL0);
    v->arch.virt_timer.cval = READ_SYSREG64(CNTV_CVAL_EL0);
    if ( (v->arch.virt_timer.ctl & CNTx_CTL_ENABLE) &&
         !(v->arch.virt_timer.ctl & CNTx_CTL_MASK))
    {
        set_timer(&v->arch.virt_timer.timer, ticks_to_ns(v->arch.virt_timer.cval +
                  v->domain->arch.virt_timer_base.offset - boot_count));
    }
    return 0;
}

int virt_timer_restore(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

    stop_timer(&v->arch.virt_timer.timer);
    migrate_timer(&v->arch.virt_timer.timer, v->processor);
    migrate_timer(&v->arch.phys_timer.timer, v->processor);

    WRITE_SYSREG64(v->domain->arch.virt_timer_base.offset, CNTVOFF_EL2);
    WRITE_SYSREG64(v->arch.virt_timer.cval, CNTV_CVAL_EL0);
    WRITE_SYSREG32(v->arch.virt_timer.ctl, CNTV_CTL_EL0);
    return 0;
}

static bool vtimer_cntp_ctl(struct cpu_user_regs *regs, uint32_t *r, bool read)
{
    struct vcpu *v = current;

    if ( !ACCESS_ALLOWED(regs, EL0PTEN) )
        return false;

    if ( read )
    {
        *r = v->arch.phys_timer.ctl;
    }
    else
    {
        uint32_t ctl = *r & ~CNTx_CTL_PENDING;
        if ( ctl & CNTx_CTL_ENABLE )
            ctl |= v->arch.phys_timer.ctl & CNTx_CTL_PENDING;
        v->arch.phys_timer.ctl = ctl;

        if ( v->arch.phys_timer.ctl & CNTx_CTL_ENABLE )
        {
            set_timer(&v->arch.phys_timer.timer,
                      v->arch.phys_timer.cval + v->domain->arch.phys_timer_base.offset);
        }
        else
            stop_timer(&v->arch.phys_timer.timer);
    }
    return true;
}

static bool vtimer_cntp_tval(struct cpu_user_regs *regs, uint32_t *r,
                             bool read)
{
    struct vcpu *v = current;
    s_time_t now;

    if ( !ACCESS_ALLOWED(regs, EL0PTEN) )
        return false;

    now = NOW() - v->domain->arch.phys_timer_base.offset;

    if ( read )
    {
        *r = (uint32_t)(ns_to_ticks(v->arch.phys_timer.cval - now) & 0xffffffffull);
    }
    else
    {
        v->arch.phys_timer.cval = now + ticks_to_ns(*r);
        if ( v->arch.phys_timer.ctl & CNTx_CTL_ENABLE )
        {
            v->arch.phys_timer.ctl &= ~CNTx_CTL_PENDING;
            set_timer(&v->arch.phys_timer.timer,
                      v->arch.phys_timer.cval +
                      v->domain->arch.phys_timer_base.offset);
        }
    }
    return true;
}

static bool vtimer_cntp_cval(struct cpu_user_regs *regs, uint64_t *r,
                             bool read)
{
    struct vcpu *v = current;

    if ( !ACCESS_ALLOWED(regs, EL0PTEN) )
        return false;

    if ( read )
    {
        *r = ns_to_ticks(v->arch.phys_timer.cval);
    }
    else
    {
        v->arch.phys_timer.cval = ticks_to_ns(*r);
        if ( v->arch.phys_timer.ctl & CNTx_CTL_ENABLE )
        {
            v->arch.phys_timer.ctl &= ~CNTx_CTL_PENDING;
            set_timer(&v->arch.phys_timer.timer,
                      v->arch.phys_timer.cval +
                      v->domain->arch.phys_timer_base.offset);
        }
    }
    return true;
}

static bool vtimer_emulate_cp32(struct cpu_user_regs *regs, union hsr hsr)
{
    struct hsr_cp32 cp32 = hsr.cp32;

    if ( cp32.read )
        perfc_incr(vtimer_cp32_reads);
    else
        perfc_incr(vtimer_cp32_writes);

    switch ( hsr.bits & HSR_CP32_REGS_MASK )
    {
    case HSR_CPREG32(CNTP_CTL):
        return vreg_emulate_cp32(regs, hsr, vtimer_cntp_ctl);

    case HSR_CPREG32(CNTP_TVAL):
        return vreg_emulate_cp32(regs, hsr, vtimer_cntp_tval);

    default:
        return false;
    }
}

static bool vtimer_emulate_cp64(struct cpu_user_regs *regs, union hsr hsr)
{
    struct hsr_cp64 cp64 = hsr.cp64;

    if ( cp64.read )
        perfc_incr(vtimer_cp64_reads);
    else
        perfc_incr(vtimer_cp64_writes);

    switch ( hsr.bits & HSR_CP64_REGS_MASK )
    {
    case HSR_CPREG64(CNTP_CVAL):
        return vreg_emulate_cp64(regs, hsr, vtimer_cntp_cval);

    default:
        return false;
    }
}

#ifdef CONFIG_ARM_64
static bool vtimer_emulate_sysreg(struct cpu_user_regs *regs, union hsr hsr)
{
    struct hsr_sysreg sysreg = hsr.sysreg;

    if ( sysreg.read )
        perfc_incr(vtimer_sysreg_reads);
    else
        perfc_incr(vtimer_sysreg_writes);

    switch ( hsr.bits & HSR_SYSREG_REGS_MASK )
    {
    case HSR_SYSREG_CNTP_CTL_EL0:
        return vreg_emulate_sysreg32(regs, hsr, vtimer_cntp_ctl);
    case HSR_SYSREG_CNTP_TVAL_EL0:
        return vreg_emulate_sysreg32(regs, hsr, vtimer_cntp_tval);
    case HSR_SYSREG_CNTP_CVAL_EL0:
        return vreg_emulate_sysreg64(regs, hsr, vtimer_cntp_cval);

    default:
        return false;
    }

}
#endif

bool vtimer_emulate(struct cpu_user_regs *regs, union hsr hsr)
{

    switch (hsr.ec) {
    case HSR_EC_CP15_32:
        return vtimer_emulate_cp32(regs, hsr);
    case HSR_EC_CP15_64:
        return vtimer_emulate_cp64(regs, hsr);
#ifdef CONFIG_ARM_64
    case HSR_EC_SYSREG:
        return vtimer_emulate_sysreg(regs, hsr);
#endif
    default:
        return false;
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
