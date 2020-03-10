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
#include <public/vm_event.h>

struct vm_event_domain
{
    spinlock_t lock;
    /* The ring has 64 entries */
    unsigned char foreign_producers;
    unsigned char target_producers;
    /* shared ring page */
    void *ring_page;
    struct page_info *ring_pg_struct;
    /* front-end ring */
    vm_event_front_ring_t front_ring;
    /* event channel port (vcpu0 only) */
    int xen_port;
    /* vm_event bit for vcpu->pause_flags */
    int pause_flag;
    /* list of vcpus waiting for room in the ring */
    struct waitqueue_head wq;
    /* the number of vCPUs blocked */
    unsigned int blocked;
    /* The last vcpu woken up */
    unsigned int last_vcpu_wake_up;
};

/* Clean up on domain destruction */
void vm_event_cleanup(struct domain *d);

/* Returns whether a ring has been set up */
bool vm_event_check_ring(struct vm_event_domain *ved);

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
                          bool allow_sleep);
static inline int vm_event_claim_slot(struct domain *d,
                                      struct vm_event_domain *ved)
{
    return __vm_event_claim_slot(d, ved, true);
}

static inline int vm_event_claim_slot_nosleep(struct domain *d,
                                              struct vm_event_domain *ved)
{
    return __vm_event_claim_slot(d, ved, false);
}

void vm_event_cancel_slot(struct domain *d, struct vm_event_domain *ved);

void vm_event_put_request(struct domain *d, struct vm_event_domain *ved,
                          vm_event_request_t *req);

int vm_event_domctl(struct domain *d, struct xen_domctl_vm_event_op *vec);

void vm_event_vcpu_pause(struct vcpu *v);
void vm_event_vcpu_unpause(struct vcpu *v);

void vm_event_fill_regs(vm_event_request_t *req);
void vm_event_set_registers(struct vcpu *v, vm_event_response_t *rsp);

void vm_event_monitor_next_interrupt(struct vcpu *v);

#endif /* __VM_EVENT_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
