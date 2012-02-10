/******************************************************************************
 * include/asm-x86/mem_event.h
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

/* Returns whether a ring has been set up */
bool_t mem_event_check_ring(struct mem_event_domain *med);

/* Returns 0 on success, -ENOSYS if there is no ring, -EBUSY if there is no
 * available space. For success or -EBUSY, the vCPU may be left blocked
 * temporarily to ensure that the ring does not lose future events.  In
 * general, you must follow a claim_slot() call with either put_request() or
 * cancel_slot(), both of which are guaranteed to succeed. */
int mem_event_claim_slot(struct domain *d, struct mem_event_domain *med);

void mem_event_cancel_slot(struct domain *d, struct mem_event_domain *med);

void mem_event_put_request(struct domain *d, struct mem_event_domain *med,
                            mem_event_request_t *req);

int mem_event_get_response(struct domain *d, struct mem_event_domain *med,
                           mem_event_response_t *rsp);

struct domain *get_mem_event_op_target(uint32_t domain, int *rc);
int do_mem_event_op(int op, uint32_t domain, void *arg);
int mem_event_domctl(struct domain *d, xen_domctl_mem_event_op_t *mec,
                     XEN_GUEST_HANDLE(void) u_domctl);

#endif /* __MEM_EVENT_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
