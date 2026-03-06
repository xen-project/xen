/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/sched.h>
#include <xen/timer.h>

#include <asm/vtimer.h>

static void vtimer_expired(void *data)
{
    struct vtimer *t = data;
    struct vcpu *v = container_of(t, struct vcpu, arch.vtimer);

    vcpu_set_interrupt(v, IRQ_VS_TIMER);
}

int vcpu_vtimer_init(struct vcpu *v)
{
    struct vtimer *t = &v->arch.vtimer;

    init_timer(&t->timer, vtimer_expired, t, v->processor);

    return 0;
}

void vcpu_timer_destroy(struct vcpu *v)
{
    struct vtimer *t = &v->arch.vtimer;

    if ( t->timer.status == TIMER_STATUS_invalid )
        return;

    kill_timer(&v->arch.vtimer.timer);
}

void vtimer_set_timer(struct vtimer *t, const uint64_t ticks)
{
    struct vcpu *v = container_of(t, struct vcpu, arch.vtimer);
    s_time_t expires = ticks_to_ns(ticks - boot_clock_cycles);

    vcpu_unset_interrupt(v, IRQ_VS_TIMER);

    /*
     * According to the RISC-V sbi spec:
     *   If the supervisor wishes to clear the timer interrupt without
     *   scheduling the next timer event, it can either request a timer
     *   interrupt infinitely far into the future (i.e., (uint64_t)-1),
     *   or it can instead mask the timer interrupt by clearing sie.STIE CSR
     *   bit.
     */
    if ( ticks == ((uint64_t)~0) )
    {
        stop_timer(&t->timer);

        return;
    }

    if ( expires < NOW() )
    {
        /*
         * Simplify the logic if the timeout has already expired and just
         * inject the event.
         */
        stop_timer(&t->timer);
        vcpu_set_interrupt(v, IRQ_VS_TIMER);

        return;
    }

    migrate_timer(&t->timer, smp_processor_id());
    set_timer(&t->timer, expires);
}
