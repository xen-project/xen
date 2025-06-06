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

void vcpu_kick(struct vcpu *v);
void vcpu_mark_events_pending(struct vcpu *v);

static inline int vcpu_event_delivery_is_enabled(struct vcpu *v)
{
    return !vcpu_info(v, evtchn_upcall_mask);
}

int hvm_local_events_need_delivery(struct vcpu *v);
static always_inline bool local_events_need_delivery(void)
{
    struct vcpu *v = current;

    ASSERT(!is_idle_vcpu(v));

    return (is_hvm_vcpu(v) ? hvm_local_events_need_delivery(v) :
            (vcpu_info(v, evtchn_upcall_pending) &&
             !vcpu_info(v, evtchn_upcall_mask)));
}

static inline void local_event_delivery_disable(void)
{
    vcpu_info(current, evtchn_upcall_mask) = 1;
}

static inline void local_event_delivery_enable(void)
{
    vcpu_info(current, evtchn_upcall_mask) = 0;
}

/* Only global arch specific virq definitions. */
static inline enum virq_type arch_get_virq_type(unsigned int virq)
{
    return VIRQ_GLOBAL;
}

#ifdef CONFIG_PV_SHIM
# include <asm/pv/shim.h>
# define arch_evtchn_is_special(chn) \
             (pv_shim && (chn)->port && (chn)->state == ECS_RESERVED)
#endif

#endif
