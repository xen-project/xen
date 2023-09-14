/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_EVENT_H__
#define __ASM_PPC_EVENT_H__

#include <xen/lib.h>

/* TODO: implement */
static inline void vcpu_kick(struct vcpu *v) { BUG_ON("unimplemented"); }
static inline void vcpu_mark_events_pending(struct vcpu *v) { BUG_ON("unimplemented"); }
static inline void vcpu_update_evtchn_irq(struct vcpu *v) { BUG_ON("unimplemented"); }
static inline void vcpu_block_unless_event_pending(struct vcpu *v) { BUG_ON("unimplemented"); }

static inline int vcpu_event_delivery_is_enabled(struct vcpu *v)
{
    BUG_ON("unimplemented");
    return 0;
}

/* No arch specific virq definition now. Default to global. */
static inline bool arch_virq_is_global(unsigned int virq)
{
    return true;
}

static inline int local_events_need_delivery(void)
{
    BUG_ON("unimplemented");
    return 0;
}

static inline void local_event_delivery_enable(void)
{
    BUG_ON("unimplemented");
}

#endif /* __ASM_PPC_EVENT_H__ */
