/******************************************************************************
 * mem_event.h
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef __MEM_EVENT_H__
#define __MEM_EVENT_H__

#include <xen/sched.h>

#ifdef HAS_MEM_ACCESS

/* Clean up on domain destruction */
void mem_event_cleanup(struct domain *d);

/* Returns whether a ring has been set up */
bool_t mem_event_check_ring(struct mem_event_domain *med);

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
int __mem_event_claim_slot(struct domain *d, struct mem_event_domain *med,
                            bool_t allow_sleep);
static inline int mem_event_claim_slot(struct domain *d,
                                        struct mem_event_domain *med)
{
    return __mem_event_claim_slot(d, med, 1);
}

static inline int mem_event_claim_slot_nosleep(struct domain *d,
                                        struct mem_event_domain *med)
{
    return __mem_event_claim_slot(d, med, 0);
}

void mem_event_cancel_slot(struct domain *d, struct mem_event_domain *med);

void mem_event_put_request(struct domain *d, struct mem_event_domain *med,
                            mem_event_request_t *req);

int mem_event_get_response(struct domain *d, struct mem_event_domain *med,
                           mem_event_response_t *rsp);

int do_mem_event_op(int op, uint32_t domain, void *arg);
int mem_event_domctl(struct domain *d, xen_domctl_mem_event_op_t *mec,
                     XEN_GUEST_HANDLE_PARAM(void) u_domctl);

void mem_event_vcpu_pause(struct vcpu *v);
void mem_event_vcpu_unpause(struct vcpu *v);

#else

static inline void mem_event_cleanup(struct domain *d) {}

static inline bool_t mem_event_check_ring(struct mem_event_domain *med)
{
    return 0;
}

static inline int mem_event_claim_slot(struct domain *d,
                                        struct mem_event_domain *med)
{
    return -ENOSYS;
}

static inline int mem_event_claim_slot_nosleep(struct domain *d,
                                        struct mem_event_domain *med)
{
    return -ENOSYS;
}

static inline
void mem_event_cancel_slot(struct domain *d, struct mem_event_domain *med)
{}

static inline
void mem_event_put_request(struct domain *d, struct mem_event_domain *med,
                            mem_event_request_t *req)
{}

static inline
int mem_event_get_response(struct domain *d, struct mem_event_domain *med,
                           mem_event_response_t *rsp)
{
    return -ENOSYS;
}

static inline int do_mem_event_op(int op, uint32_t domain, void *arg)
{
    return -ENOSYS;
}

static inline
int mem_event_domctl(struct domain *d, xen_domctl_mem_event_op_t *mec,
                     XEN_GUEST_HANDLE_PARAM(void) u_domctl)
{
    return -ENOSYS;
}

static inline void mem_event_vcpu_pause(struct vcpu *v) {}
static inline void mem_event_vcpu_unpause(struct vcpu *v) {}

#endif /* HAS_MEM_ACCESS */

#endif /* __MEM_EVENT_H__ */


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
