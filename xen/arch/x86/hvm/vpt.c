/*
 * vpt.c: Virtual Platform Timer
 *
 * Copyright (c) 2006, Xiaowei Yang, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */
#include <xen/time.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/event.h>

static __inline__ void missed_ticks(struct periodic_time *pt)
{
    s_time_t missed_ticks;

    missed_ticks = NOW() - pt->scheduled;
    if ( missed_ticks > 0 ) 
    {
        missed_ticks = missed_ticks / (s_time_t) pt->period + 1;
        if ( missed_ticks > 1000 )
        {
            /* TODO: Adjust guest time together */
            pt->pending_intr_nr++;
        }
        else
        {
            pt->pending_intr_nr += missed_ticks;
        }
        pt->scheduled += missed_ticks * pt->period;
    }
}

void pt_freeze_time(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct list_head *list;
    struct periodic_time *pt;

    if ( test_bit(_VPF_blocked, &v->pause_flags) )
        return;

    v->arch.hvm_vcpu.guest_time = hvm_get_guest_time(v);

    list_for_each( list, head )
    {
        pt = list_entry(list, struct periodic_time, list);
        stop_timer(&pt->timer);
    }
}

void pt_thaw_time(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct list_head *list;
    struct periodic_time *pt;

    if ( v->arch.hvm_vcpu.guest_time )
    {
        hvm_set_guest_time(v, v->arch.hvm_vcpu.guest_time);
        v->arch.hvm_vcpu.guest_time = 0;

        list_for_each( list, head )
        {
            pt = list_entry(list, struct periodic_time, list);
            missed_ticks(pt);
            set_timer(&pt->timer, pt->scheduled);
        }
    }
}

/* Hook function for the platform periodic time */
void pt_timer_fn(void *data)
{
    struct periodic_time *pt = data;

    pt->pending_intr_nr++;
    pt->scheduled += pt->period;

    missed_ticks(pt);

    if ( !pt->one_shot )
        set_timer(&pt->timer, pt->scheduled);

    vcpu_kick(pt->vcpu);
}

void pt_update_irq(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct list_head *list;
    struct periodic_time *pt;
    uint64_t max_lag = -1ULL;
    int irq = -1;

    list_for_each( list, head )
    {
        pt = list_entry(list, struct periodic_time, list);
        if ( !is_isa_irq_masked(v, pt->irq) && pt->pending_intr_nr &&
             ((pt->last_plt_gtime + pt->period_cycles) < max_lag) )
        {
            max_lag = pt->last_plt_gtime + pt->period_cycles;
            irq = pt->irq;
        }
    }

    if ( is_lvtt(v, irq) )
    {
        vlapic_set_irq(vcpu_vlapic(v), irq, 0);
    }
    else if ( irq >= 0 )
    {
        hvm_isa_irq_deassert(v->domain, irq);
        hvm_isa_irq_assert(v->domain, irq);
    }
}

struct periodic_time *is_pt_irq(struct vcpu *v, int vector, int type)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct list_head *list;
    struct periodic_time *pt;
    struct RTCState *rtc = &v->domain->arch.hvm_domain.pl_time.vrtc;
    int vec;

    list_for_each( list, head )
    {
        pt = list_entry(list, struct periodic_time, list);
        if ( !pt->pending_intr_nr )
            continue;

        if ( is_lvtt(v, pt->irq) )
        {
            if ( pt->irq != vector )
                continue;
            return pt;
        }

        vec = get_isa_irq_vector(v, pt->irq, type);

        /* RTC irq need special care */
        if ( (vector != vec) || (pt->irq == 8 && !is_rtc_periodic_irq(rtc)) )
            continue;

        return pt;
    }

    return NULL;
}

void pt_intr_post(struct vcpu *v, int vector, int type)
{
    struct periodic_time *pt = is_pt_irq(v, vector, type);

    if ( pt == NULL )
        return;

    pt->pending_intr_nr--;
    pt->last_plt_gtime += pt->period_cycles;

    if ( hvm_get_guest_time(pt->vcpu) < pt->last_plt_gtime )
        hvm_set_guest_time(pt->vcpu, pt->last_plt_gtime);

    if ( pt->cb != NULL )
        pt->cb(pt->vcpu, pt->priv);
}

/* If pt is enabled, discard pending intr */
void pt_reset(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct list_head *list;
    struct periodic_time *pt;

    list_for_each( list, head )
    {
	pt = list_entry(list, struct periodic_time, list);
	if ( pt->enabled )
        {
            pt->pending_intr_nr = 0;
            pt->last_plt_gtime = hvm_get_guest_time(pt->vcpu);
            pt->scheduled = NOW() + pt->period;
            set_timer(&pt->timer, pt->scheduled);
        }
    }
}

void create_periodic_time(struct vcpu *v, struct periodic_time *pt, uint64_t period,
                          uint8_t irq, char one_shot, time_cb *cb, void *data)
{
    destroy_periodic_time(pt);

    pt->enabled = 1;
    if ( period < 900000 ) /* < 0.9 ms */
    {
        gdprintk(XENLOG_WARNING,
                 "HVM_PlatformTime: program too small period %"PRIu64"\n",
                 period);
        period = 900000; /* force to 0.9ms */
    }
    pt->period = period;
    pt->vcpu = v;
    pt->last_plt_gtime = hvm_get_guest_time(pt->vcpu);
    pt->irq = irq;
    pt->period_cycles = (u64)period * cpu_khz / 1000000L;
    pt->one_shot = one_shot;
    pt->scheduled = NOW() + period;
    pt->cb = cb;
    pt->priv = data;

    list_add(&pt->list, &v->arch.hvm_vcpu.tm_list);
    set_timer(&pt->timer, pt->scheduled);
}

void destroy_periodic_time(struct periodic_time *pt)
{
    if ( pt->enabled )
    {
        pt->enabled = 0;
        pt->pending_intr_nr = 0;
        list_del(&pt->list);
        stop_timer(&pt->timer);
    }
}
