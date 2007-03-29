/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef __ASM_EVENT_H__
#define __ASM_EVENT_H__

#include <asm/current.h>

/* copied from x86 evtchn_notify() */
static inline void evtchn_notify(struct vcpu *v)
{
#ifdef XXX_NO_SMP_YET
    int running = v->is_running;
    vcpu_unblock(v);
    if (running)
        smp_send_event_check_cpu(v->processor);
#else
    vcpu_unblock(v);
#endif
}

static inline int local_event_delivery_is_enabled(void)
{
    return !!(vcpu_regs(current)->msr & MSR_EE);
}

static inline void local_event_delivery_disable(void)
{
    vcpu_regs(current)->msr &= ~MSR_EE;
}

static inline void local_event_delivery_enable(void)
{
    vcpu_regs(current)->msr |= MSR_EE;
}

static inline int local_events_need_delivery(void)
{
    struct vcpu *v = current;
    /* Note: Bitwise operations result in fast code with no branches. */
    return (!!v->vcpu_info->evtchn_upcall_pending &
            local_event_delivery_is_enabled());
}

/* No arch specific virq definition now. Default to global. */
static inline int arch_virq_is_global(int virq)
{
    return 1;
}

static inline void vcpu_kick(struct vcpu *v)
{
    /*
     * NB1. 'pause_flags' and 'processor' must be checked /after/ update of
     * pending flag. These values may fluctuate (after all, we hold no
     * locks) but the key insight is that each change will cause
     * evtchn_upcall_pending to be polled.
     *
     * NB2. We save the running flag across the unblock to avoid a needless
     * IPI for domains that we IPI'd to unblock.
     */
    int running = v->is_running;
    vcpu_unblock(v);
    if (running)
        smp_send_event_check_cpu(v->processor);
}

/* HACK: evtchn_upcall_pending is only a byte, but our atomic instructions
 * only store in 4/8 byte quantities. However, because evtchn_upcall_pending
 * is part of the guest ABI, we can't change its size without breaking
 * backwards compatibility. In this particular case, struct vcpu_info is big
 * enough that we can safely store a full long into it. However, note that bit
 * 0 of evtchn_upcall_pending is bit 56 when cast to a long.
 */
static inline void vcpu_mark_events_pending(struct vcpu *v)
{
    unsigned long *l = (unsigned long *)&v->vcpu_info->evtchn_upcall_pending;
    if (!test_and_set_bit(BITS_PER_LONG - 8, l))
        vcpu_kick(v);
}

#endif
