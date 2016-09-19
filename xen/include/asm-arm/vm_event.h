/*
 * vm_event.h: architecture specific vm_event handling routines
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_ARM_VM_EVENT_H__
#define __ASM_ARM_VM_EVENT_H__

#include <xen/sched.h>
#include <xen/vm_event.h>
#include <public/domctl.h>

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
    /* Not supported on ARM. */
}

static inline
void vm_event_register_write_resume(struct vcpu *v, vm_event_response_t *rsp)
{
    /* Not supported on ARM. */
}

static inline
void vm_event_emulate_check(struct vcpu *v, vm_event_response_t *rsp)
{
    /* Not supported on ARM. */
}

#endif /* __ASM_ARM_VM_EVENT_H__ */
