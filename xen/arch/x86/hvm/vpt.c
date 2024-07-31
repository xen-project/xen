/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vpt.c: Virtual Platform Timer
 *
 * Copyright (c) 2006, Xiaowei Yang, Intel Corporation.
 */

#include <xen/sched.h>
#include <xen/time.h>
#include <asm/hvm/vpt.h>
#include <asm/event.h>
#include <asm/apic.h>
#include <asm/mc146818rtc.h>
#include <public/hvm/params.h>

#define mode_is(d, name) \
    ((d)->arch.hvm.params[HVM_PARAM_TIMER_MODE] == HVMPTM_##name)

void hvm_init_guest_time(struct domain *d)
{
    struct pl_time *pl = d->arch.hvm.pl_time;

    spin_lock_init(&pl->pl_time_lock);
    pl->stime_offset = -(u64)get_s_time();
    pl->last_guest_time = 0;
}

uint64_t hvm_get_guest_time_fixed(const struct vcpu *v, uint64_t at_tsc)
{
    struct pl_time *pl = v->domain->arch.hvm.pl_time;
    u64 now;

    /* Called from device models shared with PV guests. Be careful. */
    ASSERT(is_hvm_vcpu(v));

    spin_lock(&pl->pl_time_lock);
    now = get_s_time_fixed(at_tsc) + pl->stime_offset;

    if ( !at_tsc )
    {
        if ( (int64_t)(now - pl->last_guest_time) > 0 )
            pl->last_guest_time = now;
        else
            now = ++pl->last_guest_time;
    }
    spin_unlock(&pl->pl_time_lock);

    return now + v->arch.hvm.stime_offset;
}

void hvm_set_guest_time(struct vcpu *v, u64 guest_time)
{
    u64 offset = guest_time - hvm_get_guest_time(v);

    if ( offset )
    {
        v->arch.hvm.stime_offset += offset;
        /*
         * If hvm.stime_offset is updated make sure to
         * also update vcpu time, since this value is used to
         * calculate the TSC.
         */
        if ( v == current )
            update_vcpu_system_time(v);
    }
}

static int pt_irq_vector(struct periodic_time *pt, enum hvm_intsrc src)
{
    struct vcpu *v = pt->vcpu;
    unsigned int gsi, isa_irq;
    int vector;

    if ( pt->source == PTSRC_lapic )
        return pt->irq;

    isa_irq = pt->irq;

    if ( src == hvm_intsrc_pic )
        return (v->domain->arch.hvm.vpic[isa_irq >> 3].irq_base
                + (isa_irq & 7));

    ASSERT(src == hvm_intsrc_lapic);
    gsi = pt->source == PTSRC_isa ? hvm_isa_irq_to_gsi(isa_irq) : pt->irq;
    vector = vioapic_get_vector(v->domain, gsi);
    if ( vector < 0 )
    {
        dprintk(XENLOG_WARNING, "d%u: invalid GSI (%u) for platform timer\n",
                v->domain->domain_id, gsi);
        domain_crash(v->domain);
        return -1;
    }

    return vector;
}

static int pt_irq_masked(struct periodic_time *pt)
{
    struct vcpu *v = pt->vcpu;
    unsigned int gsi = pt->irq;

    switch ( pt->source )
    {
    case PTSRC_lapic:
    {
        struct vlapic *vlapic = vcpu_vlapic(v);

        return (!vlapic_enabled(vlapic) ||
                (vlapic_get_reg(vlapic, APIC_LVTT) & APIC_LVT_MASKED));
    }

    case PTSRC_isa:
    {
        uint8_t pic_imr = v->domain->arch.hvm.vpic[pt->irq >> 3].imr;

        /* Check if the interrupt is unmasked in the PIC. */
        if ( !(pic_imr & (1 << (pt->irq & 7))) && vlapic_accept_pic_intr(v) )
            return 0;

        gsi = hvm_isa_irq_to_gsi(pt->irq);
    }
        fallthrough;
    case PTSRC_ioapic:
    {
        int mask = vioapic_get_mask(v->domain, gsi);

        if ( mask < 0 )
        {
            dprintk(XENLOG_WARNING,
                    "d%d: invalid GSI (%u) for platform timer\n",
                    v->domain->domain_id, gsi);
            domain_crash(v->domain);
            return -1;
        }

        return mask;
    }
    }

    ASSERT_UNREACHABLE();
    return 1;
}

/*
 * Functions which read (maybe write) all periodic_time instances
 * attached to a particular vCPU use pt_vcpu_{un}lock locking helpers.
 *
 * Such users are explicitly forbidden from changing the value of the
 * pt->vcpu field, because another thread holding the pt_migrate lock
 * may already be spinning waiting for your vcpu lock.
 */
static always_inline void pt_vcpu_lock(struct vcpu *v)
{
    spin_lock(&v->arch.hvm.tm_lock);
}

static void pt_vcpu_unlock(struct vcpu *v)
{
    spin_unlock(&v->arch.hvm.tm_lock);
}

/*
 * Functions which want to modify a particular periodic_time object
 * use pt_{un}lock locking helpers.
 *
 * These users lock whichever vCPU the periodic_time is attached to,
 * but since the vCPU could be modified without holding any lock, they
 * need to take an additional lock that protects against pt->vcpu
 * changing.
 */
static always_inline void pt_lock(struct periodic_time *pt)
{
    /*
     * Use the speculation unsafe variant for the first lock, as the following
     * lock taking helper already includes a speculation barrier.
     */
    _read_lock(&pt->vcpu->domain->arch.hvm.pl_time->pt_migrate);
    spin_lock(&pt->vcpu->arch.hvm.tm_lock);
}

static void pt_unlock(struct periodic_time *pt)
{
    spin_unlock(&pt->vcpu->arch.hvm.tm_lock);
    read_unlock(&pt->vcpu->domain->arch.hvm.pl_time->pt_migrate);
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

    v->arch.hvm.guest_time = hvm_get_guest_time(v);
}

static void pt_thaw_time(struct vcpu *v)
{
    if ( !mode_is(v->domain, delay_for_missed_ticks) )
        return;

    if ( v->arch.hvm.guest_time == 0 )
        return;

    hvm_set_guest_time(v, v->arch.hvm.guest_time);
    v->arch.hvm.guest_time = 0;
}

void pt_save_timer(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm.tm_list;
    struct periodic_time *pt;

    if ( v->pause_flags & VPF_blocked )
        return;

    pt_vcpu_lock(v);

    list_for_each_entry ( pt, head, list )
        if ( !pt->do_not_freeze )
            stop_timer(&pt->timer);

    pt_freeze_time(v);

    pt_vcpu_unlock(v);
}

void pt_restore_timer(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm.tm_list;
    struct periodic_time *pt;

    pt_vcpu_lock(v);

    list_for_each_entry ( pt, head, list )
    {
        if ( pt->pending_intr_nr == 0 )
        {
            pt_process_missed_ticks(pt);
            set_timer(&pt->timer, pt->scheduled);
        }
    }

    pt_thaw_time(v);

    pt_vcpu_unlock(v);
}

static void cf_check pt_timer_fn(void *data)
{
    struct periodic_time *pt = data;

    pt_lock(pt);

    pt->pending_intr_nr++;
    pt->scheduled += pt->period;
    pt->do_not_freeze = 0;

    vcpu_kick(pt->vcpu);

    pt_unlock(pt);
}

static void pt_irq_fired(struct vcpu *v, struct periodic_time *pt)
{
    pt->irq_issued = false;

    if ( pt->one_shot )
    {
        if ( pt->on_list )
            list_del(&pt->list);
        pt->on_list = false;
        pt->pending_intr_nr = 0;
    }
    else if ( mode_is(v->domain, one_missed_tick_pending) ||
              mode_is(v->domain, no_missed_ticks_pending) )
    {
        pt->last_plt_gtime = hvm_get_guest_time(v);
        pt_process_missed_ticks(pt);
        pt->pending_intr_nr = 0; /* 'collapse' all missed ticks */
        set_timer(&pt->timer, pt->scheduled);
    }
    else
    {
        pt->last_plt_gtime += pt->period;
        if ( --pt->pending_intr_nr == 0 )
        {
            pt_process_missed_ticks(pt);
            if ( pt->pending_intr_nr == 0 )
                set_timer(&pt->timer, pt->scheduled);
        }
    }

    if ( mode_is(v->domain, delay_for_missed_ticks) &&
         (hvm_get_guest_time(v) < pt->last_plt_gtime) )
        hvm_set_guest_time(v, pt->last_plt_gtime);
}

int pt_update_irq(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm.tm_list;
    struct periodic_time *pt, *temp, *earliest_pt;
    uint64_t max_lag;
    int irq, pt_vector = -1;
    bool level;

    pt_vcpu_lock(v);

    earliest_pt = NULL;
    max_lag = -1ULL;
    list_for_each_entry_safe ( pt, temp, head, list )
    {
        if ( pt->pending_intr_nr )
        {
            /* RTC code takes care of disabling the timer itself. */
            if ( (pt->irq != RTC_IRQ || !pt->priv) && pt_irq_masked(pt) &&
                 /* Level interrupts should be asserted even if masked. */
                 !pt->level )
            {
                /* suspend timer emulation */
                list_del(&pt->list);
                pt->on_list = 0;
            }
            else
            {
                if ( (pt->last_plt_gtime + pt->period) < max_lag )
                {
                    max_lag = pt->last_plt_gtime + pt->period;
                    earliest_pt = pt;
                }
            }
        }
    }

    if ( earliest_pt == NULL )
    {
        pt_vcpu_unlock(v);
        return -1;
    }

    earliest_pt->irq_issued = 1;
    irq = earliest_pt->irq;
    level = earliest_pt->level;

    pt_vcpu_unlock(v);

    switch ( earliest_pt->source )
    {
    case PTSRC_lapic:
        /*
         * If periodic timer interrupt is handled by lapic, its vector in
         * IRR is returned and used to set eoi_exit_bitmap for virtual
         * interrupt delivery case. Otherwise return -1 to do nothing.
         */
        vlapic_set_irq(vcpu_vlapic(v), irq, 0);
        pt_vector = irq;
        break;

    case PTSRC_isa:
        hvm_isa_irq_deassert(v->domain, irq);
        if ( platform_legacy_irq(irq) && vlapic_accept_pic_intr(v) &&
             v->domain->arch.hvm.vpic[irq >> 3].int_output )
            hvm_isa_irq_assert(v->domain, irq, NULL);
        else
        {
            pt_vector = hvm_isa_irq_assert(v->domain, irq, vioapic_get_vector);
            /*
             * hvm_isa_irq_assert may not set the corresponding bit in vIRR
             * when mask field of IOAPIC RTE is set. Check it again.
             */
            if ( pt_vector < 0 || !vlapic_test_irq(vcpu_vlapic(v), pt_vector) )
                pt_vector = -1;
        }
        break;

    case PTSRC_ioapic:
        pt_vector = hvm_ioapic_assert(v->domain, irq, level);
        if ( pt_vector < 0 || !vlapic_test_irq(vcpu_vlapic(v), pt_vector) )
        {
            pt_vector = -1;
            if ( level )
            {
                /*
                 * Level interrupts are always asserted because the pin assert
                 * count is incremented regardless of whether the pin is masked
                 * or the vector latched in IRR, so also execute the callback
                 * associated with the timer.
                 */
                time_cb *cb = NULL;
                void *cb_priv = NULL;

                pt_vcpu_lock(v);
                /* Make sure the timer is still on the list. */
                list_for_each_entry ( pt, &v->arch.hvm.tm_list, list )
                    if ( pt == earliest_pt )
                    {
                        pt_irq_fired(v, pt);
                        cb = pt->cb;
                        cb_priv = pt->priv;
                        break;
                    }
                pt_vcpu_unlock(v);

                if ( cb != NULL )
                    cb(v, cb_priv);
            }
        }
        break;
    }

    return pt_vector;
}

static struct periodic_time *is_pt_irq(
    struct vcpu *v, struct hvm_intack intack)
{
    struct list_head *head = &v->arch.hvm.tm_list;
    struct periodic_time *pt;

    list_for_each_entry ( pt, head, list )
    {
        if ( pt->pending_intr_nr && pt->irq_issued &&
             (intack.vector == pt_irq_vector(pt, intack.source)) )
            return pt;
    }

    return NULL;
}

void pt_intr_post(struct vcpu *v, struct hvm_intack intack)
{
    struct periodic_time *pt;
    time_cb *cb;
    void *cb_priv;

    if ( intack.source == hvm_intsrc_vector )
        return;

    pt_vcpu_lock(v);

    pt = is_pt_irq(v, intack);
    if ( pt == NULL )
    {
        pt_vcpu_unlock(v);
        return;
    }

    pt_irq_fired(v, pt);

    cb = pt->cb;
    cb_priv = pt->priv;

    pt_vcpu_unlock(v);

    if ( cb != NULL )
        cb(v, cb_priv);
}

void pt_migrate(struct vcpu *v)
{
    struct list_head *head = &v->arch.hvm.tm_list;
    struct periodic_time *pt;

    pt_vcpu_lock(v);

    list_for_each_entry ( pt, head, list )
        migrate_timer(&pt->timer, v->processor);

    pt_vcpu_unlock(v);
}

void create_periodic_time(
    struct vcpu *v, struct periodic_time *pt, uint64_t delta,
    uint64_t period, uint8_t irq, time_cb *cb, void *data, bool level)
{
    if ( !pt->source ||
         (irq >= NR_ISAIRQS && pt->source == PTSRC_isa) ||
         (level && period) ||
         (pt->source == PTSRC_ioapic ? irq >= hvm_domain_irq(v->domain)->nr_gsis
                                     : level) )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    destroy_periodic_time(pt);

    write_lock(&v->domain->arch.hvm.pl_time->pt_migrate);

    pt->pending_intr_nr = 0;
    pt->do_not_freeze = 0;
    pt->irq_issued = 0;

    /* Periodic timer must be at least 0.1ms. */
    if ( (period < 100000) && period )
    {
        if ( !test_and_set_bool(pt->warned_timeout_too_short) )
            gdprintk(XENLOG_WARNING, "HVM_PlatformTime: program too "
                     "small period %"PRIu64"\n", period);
        period = 100000;
    }

    pt->period = period;
    pt->vcpu = v;
    pt->last_plt_gtime = hvm_get_guest_time(pt->vcpu);
    pt->irq = irq;
    pt->one_shot = !period;
    pt->level = level;
    pt->scheduled = NOW() + delta;

    if ( !pt->one_shot )
    {
        if ( v->domain->arch.hvm.params[HVM_PARAM_VPT_ALIGN] )
        {
            pt->scheduled = align_timer(pt->scheduled, pt->period);
        }
        else if ( pt->source == PTSRC_lapic )
        {
            /*
             * Offset LAPIC ticks from other timer ticks. Otherwise guests
             * which use LAPIC ticks for process accounting can see long
             * sequences of process ticks incorrectly accounted to interrupt
             * processing (seen with RHEL3 guest).
             */
            pt->scheduled += delta >> 1;
        }
    }

    pt->cb = cb;
    pt->priv = data;

    init_timer(&pt->timer, pt_timer_fn, pt, v->processor);
    set_timer(&pt->timer, pt->scheduled);

    pt_vcpu_lock(v);
    pt->on_list = 1;
    list_add(&pt->list, &v->arch.hvm.tm_list);
    pt_vcpu_unlock(v);

    write_unlock(&v->domain->arch.hvm.pl_time->pt_migrate);
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
    pt->pending_intr_nr = 0;
    pt_unlock(pt);

    /*
     * pt_timer_fn() can run until this kill_timer() returns. We must do this
     * outside pt_lock() otherwise we can deadlock with pt_timer_fn().
     */
    kill_timer(&pt->timer);
}

static void pt_adjust_vcpu(struct periodic_time *pt, struct vcpu *v)
{
    ASSERT(pt->source == PTSRC_isa || pt->source == PTSRC_ioapic);

    if ( pt->vcpu == NULL )
        return;

    write_lock(&v->domain->arch.hvm.pl_time->pt_migrate);

    if ( pt->vcpu == v )
        goto out;

    pt_vcpu_lock(pt->vcpu);
    if ( pt->on_list )
        list_del(&pt->list);
    pt_vcpu_unlock(pt->vcpu);

    pt->vcpu = v;

    pt_vcpu_lock(v);
    if ( pt->on_list )
    {
        list_add(&pt->list, &v->arch.hvm.tm_list);
        migrate_timer(&pt->timer, v->processor);
    }
    pt_vcpu_unlock(v);

 out:
    write_unlock(&v->domain->arch.hvm.pl_time->pt_migrate);
}

void pt_adjust_global_vcpu_target(struct vcpu *v)
{
    struct PITState *vpit;
    struct pl_time *pl_time;
    int i;

    if ( !v || !has_vpit(v->domain) )
        return;

    vpit = &v->domain->arch.vpit;

    spin_lock(&vpit->lock);
    pt_adjust_vcpu(&vpit->pt0, v);
    spin_unlock(&vpit->lock);

    pl_time = v->domain->arch.hvm.pl_time;

    spin_lock(&pl_time->vrtc.lock);
    pt_adjust_vcpu(&pl_time->vrtc.pt, v);
    spin_unlock(&pl_time->vrtc.lock);

    write_lock(&pl_time->vhpet.lock);
    for ( i = 0; i < HPET_TIMER_NUM; i++ )
        pt_adjust_vcpu(&pl_time->vhpet.pt[i], v);
    write_unlock(&pl_time->vhpet.lock);
}


static void pt_resume(struct periodic_time *pt)
{
    if ( pt->vcpu == NULL )
        return;

    pt_lock(pt);
    if ( pt->pending_intr_nr && !pt->on_list )
    {
        pt->on_list = 1;
        list_add(&pt->list, &pt->vcpu->arch.hvm.tm_list);
        vcpu_kick(pt->vcpu);
    }
    pt_unlock(pt);
}

void pt_may_unmask_irq(struct domain *d, struct periodic_time *vlapic_pt)
{
    if ( d )
    {
        if ( has_vpit(d) )
            pt_resume(&d->arch.vpit.pt0);
        if ( has_vrtc(d) )
            pt_resume(&d->arch.hvm.pl_time->vrtc.pt);
        if ( has_vhpet(d) )
        {
            unsigned int i;

            for ( i = 0; i < HPET_TIMER_NUM; i++ )
                pt_resume(&d->arch.hvm.pl_time->vhpet.pt[i]);
        }
    }

    if ( vlapic_pt )
        pt_resume(vlapic_pt);
}
