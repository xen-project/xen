/* SPDX-License-Identifier:  GPL-2.0-only */
/*
 * vm_event.h: stubs for architecture specific vm_event handling routines
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 */

#ifndef __ASM_GENERIC_VM_EVENT_H__
#define __ASM_GENERIC_VM_EVENT_H__

#include <xen/sched.h>
#include <public/vm_event.h>

static inline int vm_event_init_domain(struct domain *d)
{
    /* Nothing to do. */
    return 0;
}

static inline void vm_event_cleanup_domain(struct domain *d)
{
    memset(&d->monitor, 0, sizeof(d->monitor));
}

static inline void vm_event_toggle_singlestep(struct domain *d, struct vcpu *v,
                                              vm_event_response_t *rsp)
{
    /* Nothing to do. */
}

static inline
void vm_event_register_write_resume(struct vcpu *v, vm_event_response_t *rsp)
{
    /* Nothing to do. */
}

static inline
void vm_event_emulate_check(struct vcpu *v, vm_event_response_t *rsp)
{
    /* Nothing to do. */
}

static inline
void vm_event_sync_event(struct vcpu *v, bool value)
{
    /* Nothing to do. */
}

static inline
void vm_event_reset_vmtrace(struct vcpu *v)
{
    /* Nothing to do. */
}

#endif /* __ASM_GENERIC_VM_EVENT_H__ */
