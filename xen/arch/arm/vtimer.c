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
    t->ctl &= ~CNTx_CTL_MASK;
    vgic_vcpu_inject_irq(t->v, 30, 1);
}

static void virt_timer_expired(void *data)
{
    struct vtimer *t = data;
    t->ctl |= CNTx_CTL_MASK;
    vgic_vcpu_inject_irq(t->v, 27, 1);
}
 
int vcpu_vtimer_init(struct vcpu *v)
{
    struct vtimer *t = &v->arch.phys_timer;

    init_timer(&t->timer, phys_timer_expired, t, smp_processor_id());
    t->ctl = 0;
    t->offset = NOW();
    t->cval = NOW();
    t->irq = 30;
    t->v = v;

    t = &v->arch.virt_timer;
    init_timer(&t->timer, virt_timer_expired, t, smp_processor_id());
    t->ctl = 0;
    t->offset = READ_CP64(CNTVCT) + READ_CP64(CNTVOFF);
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

    v->arch.virt_timer.ctl = READ_CP32(CNTV_CTL);
    WRITE_CP32(v->arch.virt_timer.ctl & ~CNTx_CTL_ENABLE, CNTV_CTL);
    v->arch.virt_timer.cval = READ_CP64(CNTV_CVAL);
    if ( v->arch.virt_timer.ctl & CNTx_CTL_ENABLE )
    {
        set_timer(&v->arch.virt_timer.timer, ticks_to_ns(v->arch.virt_timer.cval +
                  v->arch.virt_timer.offset - boot_count));
    }
    return 0;
}

int virt_timer_restore(struct vcpu *v)
{
    if ( is_idle_domain(v->domain) )
        return 0;

    stop_timer(&v->arch.virt_timer.timer);

    WRITE_CP64(v->arch.virt_timer.offset, CNTVOFF);
    WRITE_CP64(v->arch.virt_timer.cval, CNTV_CVAL);
    WRITE_CP32(v->arch.virt_timer.ctl, CNTV_CTL);
    return 0;
}
 
static int vtimer_emulate_32(struct cpu_user_regs *regs, union hsr hsr)
{
    struct vcpu *v = current;
    struct hsr_cp32 cp32 = hsr.cp32;
    uint32_t *r = select_user_reg(regs, cp32.reg);
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
            v->arch.phys_timer.ctl = *r;

            if ( v->arch.phys_timer.ctl & CNTx_CTL_ENABLE )
            {
                set_timer(&v->arch.phys_timer.timer,
                          v->arch.phys_timer.cval + v->arch.phys_timer.offset);
            }
            else
                stop_timer(&v->arch.phys_timer.timer);
        }

        return 1;

    case HSR_CPREG32(CNTP_TVAL):
        now = NOW() - v->arch.phys_timer.offset;
        if ( cp32.read )
        {
            *r = (uint32_t)(ns_to_ticks(v->arch.phys_timer.cval - now) & 0xffffffffull);
        }
        else
        {
            v->arch.phys_timer.cval = now + ticks_to_ns(*r);
            if ( v->arch.phys_timer.ctl & CNTx_CTL_ENABLE )
            {
                set_timer(&v->arch.phys_timer.timer,
                          v->arch.phys_timer.cval + v->arch.phys_timer.offset);
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
    uint32_t *r1 = select_user_reg(regs, cp64.reg1);
    uint32_t *r2 = select_user_reg(regs, cp64.reg2);
    uint64_t ticks;
    s_time_t now;

    switch ( hsr.bits & HSR_CP64_REGS_MASK )
    {
    case HSR_CPREG64(CNTPCT):
        if ( cp64.read )
        {
            now = NOW() - v->arch.phys_timer.offset;
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
