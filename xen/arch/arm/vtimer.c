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
#include "gic.h"

extern s_time_t ticks_to_ns(uint64_t ticks);
extern uint64_t ns_to_ticks(s_time_t ns);

static void vtimer_expired(void *data)
{
    struct vcpu *v = data;
    v->arch.vtimer.ctl |= CNTx_CTL_PENDING;
    v->arch.vtimer.ctl &= ~CNTx_CTL_MASK;
    vgic_vcpu_inject_irq(v, 30, 1);
}

int vcpu_vtimer_init(struct vcpu *v)
{
    init_timer(&v->arch.vtimer.timer,
               vtimer_expired, v,
               smp_processor_id());
    v->arch.vtimer.ctl = 0;
    v->arch.vtimer.offset = NOW();
    v->arch.vtimer.cval = NOW();
    return 0;
}

static int vtimer_emulate_32(struct cpu_user_regs *regs, union hsr hsr)
{
    struct vcpu *v = current;
    struct hsr_cp32 cp32 = hsr.cp32;
    uint32_t *r = &regs->r0 + cp32.reg;
    s_time_t now;

    switch ( hsr.bits & HSR_CP32_REGS_MASK )
    {
    case HSR_CPREG32(CNTP_CTL):
        if ( cp32.read )
        {
            *r = v->arch.vtimer.ctl;
        }
        else
        {
            v->arch.vtimer.ctl = *r;

            if ( v->arch.vtimer.ctl & CNTx_CTL_ENABLE )
            {
                set_timer(&v->arch.vtimer.timer,
                          v->arch.vtimer.cval + v->arch.vtimer.offset);
            }
            else
                stop_timer(&v->arch.vtimer.timer);
        }

        return 1;

    case HSR_CPREG32(CNTP_TVAL):
        now = NOW() - v->arch.vtimer.offset;
        if ( cp32.read )
        {
            *r = (uint32_t)(ns_to_ticks(v->arch.vtimer.cval - now) & 0xffffffffull);
        }
        else
        {
            v->arch.vtimer.cval = now + ticks_to_ns(*r);
            if ( v->arch.vtimer.ctl & CNTx_CTL_ENABLE )
            {
                set_timer(&v->arch.vtimer.timer,
                          v->arch.vtimer.cval + v->arch.vtimer.offset);
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
    uint32_t *r1 = &regs->r0 + cp64.reg1;
    uint32_t *r2 = &regs->r0 + cp64.reg2;
    s_time_t now;

    switch ( hsr.bits & HSR_CP64_REGS_MASK )
    {
    case HSR_CPREG64(CNTPCT):
        if ( cp64.read )
        {
            now = NOW() - v->arch.vtimer.offset;
            *r1 = (uint32_t)(now & 0xffffffff);
            *r2 = (uint32_t)(now >> 32);
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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
