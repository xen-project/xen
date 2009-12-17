/******************************************************************************
 * include/asm-x86/mem_event.h
 *
 * Common interface for memory event support.
 *
 * Copyright (c) 2009 Citrix (R&D) Ltd. (Patrick Colp)
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


/* Printouts */
#define MEM_EVENT_PRINTK(_f, _a...)                                      \
    debugtrace_printk("mem_event: %s(): " _f, __func__, ##_a)
#define MEM_EVENT_ERROR(_f, _a...)                                       \
    printk("mem_event error: %s(): " _f, __func__, ##_a)
#define MEM_EVENT_DEBUG(flag, _f, _a...)                                 \
    do {                                                                  \
        if (MEM_EVENT_DEBUG_ ## flag)                                    \
            debugtrace_printk("mem_event debug: %s(): " _f, __func__, ##_a); \
    } while (0)


#define mem_event_enabled(_d) (_d)->mem_event.enabled


/* Ring lock */
#define mem_event_ring_lock_init(_d)  spin_lock_init(&(_d)->mem_event.ring_lock)
#define mem_event_ring_lock(_d)       spin_lock(&(_d)->mem_event.ring_lock)
#define mem_event_ring_unlock(_d)     spin_unlock(&(_d)->mem_event.ring_lock)


int mem_event_enable(struct domain *d, mfn_t ring_mfn, mfn_t shared_mfn);
int mem_event_disable(struct domain *d);

int mem_event_check_ring(struct domain *d);
void mem_event_put_request(struct domain *d, mem_event_request_t *req);
void mem_event_get_response(struct domain *d, mem_event_response_t *rsp);
void mem_event_unpause_vcpus(struct domain *d);

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
