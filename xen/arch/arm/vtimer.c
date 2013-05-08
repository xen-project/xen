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

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/timer.h>
#include <xen/sched.h>
#include <asm/irq.h>
#include <asm/time.h>
#include <asm/gic.h>
#include <asm/regs.h>

extern s_time_t ticks_to_ns(uint64_t ticks);
extern uint64_t ns_to_ticks(s_time_t ns);

static void phys_timer_expired(void *data)
{
    struct vtimer *t = data;
    t->ctl |= CNTx_CTL_PENDING;
    if ( !(t->ctl & CNTx_CTL_MASK) )
        vgic_vcpu_inject_irq(t->v, 30, 1);
}

static void virt_timer_expired(void *data)
{
    struct vtimer *t = data;
    t->ctl |= CNTx_CTL_MASK;
    vgic_vcpu_inject_irq(t->v, 27, 1);
}

int vcpu_domain_init(struct domain *d)
{
    d->arch.phys_timer_base.offset = NOW();
    d->arch.virt_timer_base.offset = READ_SYSREG64(CNTVCT_EL0) +
                                     READ_SYSREG64(CNTVOFF_EL2);
    return 0;
}

int vcpu_vtimer_init(struct vcpu *v)
{
    struct vtimer *t = &v->arch.phys_timer;

    init_timer(&t->timer, phys_timer_expired, t, v->processor);
    t->ctl = 0;
    t->cval = NOW();
    t->irq = 30;
    t->v = v;

    t = &v->arch.virt_timer;
    init_timer(&t->timer, virt_timer_expired, t, v->processor);
    t->ctl = 0;
    t->cval = 0;
    t->irq = 27;
    t->v = v;

    return 0;
}

void vcpu_timer_destroy(struct vcpu *v)
{
    kill_timer(&v->arch.virt_timer.timer);
    kill_timer(&v->arch.phys_timer.timer);
}

int virt_timer_save(struct vcpu *v)
{
    if ( is_idle_domain(v->domain) )
        return 0;

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
    if ( is_idle_domain(v->domain) )
        return 0;

    stop_timer(&v->arch.virt_timer.timer);
    migrate_timer(&v->arch.virt_timer.timer, v->processor);
    migrate_timer(&v->arch.phys_timer.timer, v->processor);

    WRITE_SYSREG64(v->domain->arch.virt_timer_base.offset, CNTVOFF_EL2);
    WRITE_SYSREG64(v->arch.virt_timer.cval, CNTV_CVAL_EL0);
    WRITE_SYSREG32(v->arch.virt_timer.ctl, CNTV_CTL_EL0);
    return 0;
}

static int vtimer_emulate_32(struct cpu_user_regs *regs, union hsr hsr)
{
    struct vcpu *v = current;
    struct hsr_cp32 cp32 = hsr.cp32;
    uint32_t *r = (uint32_t *)select_user_reg(regs, cp32.reg);
    s_time_t now;

    switch ( hsr.bits & HSR_CP32_REGS_MASK )
    {
    case HSR_CPREG32(CNTP_CTL):
        if ( cp32.read )
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
                          v->arch.phys_timer.cval +
                          v->domain->arch.phys_timer_base.offset);
            }
            else
                stop_timer(&v->arch.phys_timer.timer);
        }

        return 1;

    case HSR_CPREG32(CNTP_TVAL):
        now = NOW() - v->domain->arch.phys_timer_base.offset;
        if ( cp32.read )
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

        return 1;

    default:
        return 0;
    }
}

static int vtimer_emulate_64(struct cpu_user_regs *regs, union hsr hsr)
{
    struct vcpu *v = current;
    struct hsr_cp64 cp64 = hsr.cp64;
    uint32_t *r1 = (uint32_t *)select_user_reg(regs, cp64.reg1);
    uint32_t *r2 = (uint32_t *)select_user_reg(regs, cp64.reg2);
    uint64_t ticks;
    s_time_t now;

    switch ( hsr.bits & HSR_CP64_REGS_MASK )
    {
    case HSR_CPREG64(CNTPCT):
        if ( cp64.read )
        {
            now = NOW() - v->domain->arch.phys_timer_base.offset;
            ticks = ns_to_ticks(now);
            *r1 = (uint32_t)(ticks & 0xffffffff);
            *r2 = (uint32_t)(ticks >> 32);
            return 1;
        }
        else
        {
            printk("READ from R/O CNTPCT\n");
            return 0;
        }

    default:
        return 0;
    }
}

int vtimer_emulate(struct cpu_user_regs *regs, union hsr hsr)
{
    if ( !is_pv32_domain(current->domain) )
        return -EINVAL;

    switch (hsr.ec) {
    case HSR_EC_CP15_32:
        return vtimer_emulate_32(regs, hsr);
    case HSR_EC_CP15_64:
        return vtimer_emulate_64(regs, hsr);
    default:
        return 0;
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
