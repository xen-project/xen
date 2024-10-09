/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__EVENT_H
#define ASM__RISCV__EVENT_H

#include <xen/lib.h>

void vcpu_mark_events_pending(struct vcpu *v);

static inline int vcpu_event_delivery_is_enabled(struct vcpu *v)
{
    BUG_ON("unimplemented");
    return 0;
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

/* No arch specific virq definition now. Default to global. */
static inline bool arch_virq_is_global(unsigned int virq)
{
    return true;
}

#endif /* ASM__RISCV__EVENT_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
