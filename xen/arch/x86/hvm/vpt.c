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

#define mode_is(d, name) \
    ((d)->arch.hvm_domain.params[HVM_PARAM_TIMER_MODE] == HVMPTM_##name)

static void pt_lock(struct periodic_time *pt)
{
    struct vcpu *v;

    for ( ; ; )
    {
        v = pt->vcpu;
        spin_lock(&v->arch.hvm_vcpu.tm_lock);
        if ( likely(pt->vcpu == v) )
            break;
        spin_unlock(&v->arch.hvm_vcpu.tm_lock);
    }
}

static void pt_unlock(struct periodic_time *pt)
{
    spin_unlock(&pt->vcpu->arch.hvm_vcpu.tm_lock);
}

static void pt_process_missed_ticks(struct periodic_time *pt)
{
    s_time_t missed_ticks, now = NOW();

    if ( pt->one_shot )
        return;

    missed_ticks = now - pt->scheduled;
    if ( missed_ticks <= 0 )
        return;

    missed_ticks = missed_ticks / (s_time_t) pt->period + 1;
    if ( mode_is(pt->vcpu->domain, no_missed_ticks_pending) )
        pt->do_not_freeze = !pt->pending_intr_nr;
    else
        pt->pending_intr_nr += missed_ticks;
    pt->scheduled += missed_ticks * pt->period;
}

static void pt_freeze_time(struct vcpu *v)
{
    if ( !mode_is(v->domain, delay_for_missed_ticks) )
        return;

    v->arch.hvm_vcpu.guest_time = hvm_get_guest_time(v);
}

static void pt_thaw_time(struct vcpu *v)
{
    if ( !mode_is(v->domain, delay_for_missed_ticks) )
        return;

    if ( v->arch.hvm_vcpu.guest_time == 0 )
        return;

    hvm_set_guest_time(v, v->arch.hvm_vcpu.guest_time);
    v->arch.hvm_vcpu.guest_time = 0;
}

void pt_save_timer(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    if ( test_bit(_VPF_blocked, &v->pause_flags) )
        return;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
        if ( !pt->do_not_freeze )
            stop_timer(&pt->timer);

    pt_freeze_time(v);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void pt_restore_timer(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
    {
        pt_process_missed_ticks(pt);
        set_timer(&pt->timer, pt->scheduled);
    }

    pt_thaw_time(v);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

static void pt_timer_fn(void *data)
{
    struct periodic_time *pt = data;

    pt_lock(pt);

    pt->pending_intr_nr++;

    if ( !pt->one_shot )
    {
        pt->scheduled += pt->period;
        pt_process_missed_ticks(pt);
        set_timer(&pt->timer, pt->scheduled);
    }

    vcpu_kick(pt->vcpu);

    pt_unlock(pt);
}

void pt_update_irq(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;
    uint64_t max_lag = -1ULL;
    int irq = -1;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
    {
        if ( !is_isa_irq_masked(v, pt->irq) && pt->pending_intr_nr &&
             ((pt->last_plt_gtime + pt->period_cycles) < max_lag) )
        {
            max_lag = pt->last_plt_gtime + pt->period_cycles;
            irq = pt->irq;
        }
    }

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);

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

static struct periodic_time *is_pt_irq(
    struct vcpu *v, struct hvm_intack intack)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;
    struct RTCState *rtc = &v->domain->arch.hvm_domain.pl_time.vrtc;
    int vector;

    list_for_each_entry ( pt, head, list )
    {
        if ( !pt->pending_intr_nr )
            continue;

        if ( is_lvtt(v, pt->irq) )
        {
            if ( pt->irq != intack.vector )
                continue;
            return pt;
        }

        vector = get_isa_irq_vector(v, pt->irq, intack.source);

        /* RTC irq need special care */
        if ( (intack.vector != vector) ||
             ((pt->irq == 8) && !is_rtc_periodic_irq(rtc)) )
            continue;

        return pt;
    }

    return NULL;
}

void pt_intr_post(struct vcpu *v, struct hvm_intack intack)
{
    struct periodic_time *pt;
    time_cb *cb;
    void *cb_priv;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    pt = is_pt_irq(v, intack);
    if ( pt == NULL )
    {
        spin_unlock(&v->arch.hvm_vcpu.tm_lock);
        return;
    }

    pt->do_not_freeze = 0;

    if ( pt->one_shot )
    {
        if ( pt->on_list )
            list_del(&pt->list);
        pt->on_list = 0;
    }
    else
    {
        if ( mode_is(v->domain, one_missed_tick_pending) )
        {
            pt->last_plt_gtime = hvm_get_guest_time(v);
            pt->pending_intr_nr = 0; /* 'collapse' all missed ticks */
        }
        else
        {
            pt->last_plt_gtime += pt->period_cycles;
            pt->pending_intr_nr--;
        }
    }

    if ( mode_is(v->domain, delay_for_missed_ticks) &&
         (hvm_get_guest_time(v) < pt->last_plt_gtime) )
        hvm_set_guest_time(v, pt->last_plt_gtime);

    cb = pt->cb;
    cb_priv = pt->priv;

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);

    if ( cb != NULL )
        cb(v, cb_priv);
}

void pt_reset(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
    {
        pt->pending_intr_nr = 0;
        pt->last_plt_gtime = hvm_get_guest_time(pt->vcpu);
        pt->scheduled = NOW() + pt->period;
        set_timer(&pt->timer, pt->scheduled);
    }

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void pt_migrate(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm_vcpu.tm_list;
    struct periodic_time *pt;

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    list_for_each_entry ( pt, head, list )
        migrate_timer(&pt->timer, v->processor);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void create_periodic_time(
    struct vcpu *v, struct periodic_time *pt, uint64_t period,
    uint8_t irq, char one_shot, time_cb *cb, void *data)
{
    destroy_periodic_time(pt);

    spin_lock(&v->arch.hvm_vcpu.tm_lock);

    pt->pending_intr_nr = 0;
    pt->do_not_freeze = 0;

    /* Periodic timer must be at least 0.9ms. */
    if ( (period < 900000) && !one_shot )
    {
        gdprintk(XENLOG_WARNING,
                 "HVM_PlatformTime: program too small period %"PRIu64"\n",
                 period);
        period = 900000;
    }

    pt->period = period;
    pt->vcpu = v;
    pt->last_plt_gtime = hvm_get_guest_time(pt->vcpu);
    pt->irq = irq;
    pt->period_cycles = (u64)period * cpu_khz / 1000000L;
    pt->one_shot = one_shot;
    pt->scheduled = NOW() + period;
    /*
     * Offset LAPIC ticks from other timer ticks. Otherwise guests which use
     * LAPIC ticks for process accounting can see long sequences of process
     * ticks incorrectly accounted to interrupt processing.
     */
    if ( is_lvtt(v, irq) )
        pt->scheduled += period >> 1;
    pt->cb = cb;
    pt->priv = data;

    pt->on_list = 1;
    list_add(&pt->list, &v->arch.hvm_vcpu.tm_list);

    init_timer(&pt->timer, pt_timer_fn, pt, v->processor);
    set_timer(&pt->timer, pt->scheduled);

    spin_unlock(&v->arch.hvm_vcpu.tm_lock);
}

void destroy_periodic_time(struct periodic_time *pt)
{
    /* Was this structure previously initialised by create_periodic_time()? */
    if ( pt->vcpu == NULL )
        return;

    pt_lock(pt);
    if ( pt->on_list )
        list_del(&pt->list);
    pt->on_list = 0;
    pt_unlock(pt);

    /*
     * pt_timer_fn() can run until this kill_timer() returns. We must do this
     * outside pt_lock() otherwise we can deadlock with pt_timer_fn().
     */
    kill_timer(&pt->timer);
}
