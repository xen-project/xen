/******************************************************************************
 * event.h
 *
 * A nice interface for passing asynchronous events to guest OSes.
 * (architecture-dependent part)
 *
 */

#ifndef __ASM_EVENT_H__
#define __ASM_EVENT_H__

#include <xen/shared.h>
#include <asm/hvm/irq.h> /* cpu_has_pending_irq() */

static inline void vcpu_kick(struct vcpu *v)
{
    /*
     * NB1. 'vcpu_flags' and 'processor' must be checked /after/ update of
     * pending flag. These values may fluctuate (after all, we hold no
     * locks) but the key insight is that each change will cause
     * evtchn_upcall_pending to be polled.
     * 
     * NB2. We save VCPUF_running across the unblock to avoid a needless
     * IPI for domains that we IPI'd to unblock.
     */
    int running = test_bit(_VCPUF_running, &v->vcpu_flags);
    vcpu_unblock(v);
    if ( running )
        smp_send_event_check_cpu(v->processor);
}

static inline void vcpu_mark_events_pending(struct vcpu *v)
{
    if ( !test_and_set_bit(0, &vcpu_info(v, evtchn_upcall_pending)) )
        vcpu_kick(v);
}

static inline int local_events_need_delivery(void)
{
    struct vcpu *v = current;
    return ((vcpu_info(v, evtchn_upcall_pending) &&
             !vcpu_info(v, evtchn_upcall_mask)) ||
            (is_hvm_vcpu(v) && cpu_has_pending_irq(v)));
}

static inline int local_event_delivery_is_enabled(void)
{
    return !vcpu_info(current, evtchn_upcall_mask);
}

static inline void local_event_delivery_disable(void)
{
    vcpu_info(current, evtchn_upcall_mask) = 1;
}

static inline void local_event_delivery_enable(void)
{
    vcpu_info(current, evtchn_upcall_mask) = 0;
}

/* No arch specific virq definition now. Default to global. */
static inline int arch_virq_is_global(int virq)
{
    return 1;
}

#endif
