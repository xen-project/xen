/******************************************************************************
 * vm_event.h
 *
 * Common interface for memory event support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __VM_EVENT_H__
#define __VM_EVENT_H__

#include <xen/sched.h>

/* Clean up on domain destruction */
void vm_event_cleanup(struct domain *d);

/* Returns whether a ring has been set up */
bool_t vm_event_check_ring(struct vm_event_domain *ved);

/* Returns 0 on success, -ENOSYS if there is no ring, -EBUSY if there is no
 * available space and the caller is a foreign domain. If the guest itself
 * is the caller, -EBUSY is avoided by sleeping on a wait queue to ensure
 * that the ring does not lose future events.
 *
 * However, the allow_sleep flag can be set to false in cases in which it is ok
 * to lose future events, and thus -EBUSY can be returned to guest vcpus
 * (handle with care!).
 *
 * In general, you must follow a claim_slot() call with either put_request() or
 * cancel_slot(), both of which are guaranteed to
 * succeed.
 */
int __vm_event_claim_slot(struct domain *d, struct vm_event_domain *ved,
                          bool_t allow_sleep);
static inline int vm_event_claim_slot(struct domain *d,
                                      struct vm_event_domain *ved)
{
    return __vm_event_claim_slot(d, ved, 1);
}

static inline int vm_event_claim_slot_nosleep(struct domain *d,
                                              struct vm_event_domain *ved)
{
    return __vm_event_claim_slot(d, ved, 0);
}

void vm_event_cancel_slot(struct domain *d, struct vm_event_domain *ved);

void vm_event_put_request(struct domain *d, struct vm_event_domain *ved,
                          vm_event_request_t *req);

int vm_event_get_response(struct domain *d, struct vm_event_domain *ved,
                          vm_event_response_t *rsp);

void vm_event_resume(struct domain *d, struct vm_event_domain *ved);

int vm_event_domctl(struct domain *d, xen_domctl_vm_event_op_t *vec,
                    XEN_GUEST_HANDLE_PARAM(void) u_domctl);

void vm_event_vcpu_pause(struct vcpu *v);
void vm_event_vcpu_unpause(struct vcpu *v);

#endif /* __VM_EVENT_H__ */


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
