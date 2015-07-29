/******************************************************************************
 * tools/xenpaging/xenpaging.h
 *
 * Xen domain paging.
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


#ifndef __XEN_PAGING2_H__
#define __XEN_PAGING2_H__


#include <xc_private.h>
#include <xen/event_channel.h>
#include <xen/vm_event.h>

#define XENPAGING_PAGEIN_QUEUE_SIZE 64

struct vm_event {
    domid_t domain_id;
    xc_evtchn *xce_handle;
    int port;
    vm_event_back_ring_t back_ring;
    uint32_t evtchn_port;
    void *ring_page;
};

struct xenpaging {
    xc_interface *xc_handle;
    struct xs_handle *xs_handle;

    unsigned long *bitmap;

    unsigned long *slot_to_gfn;
    int *gfn_to_slot;

    void *paging_buffer;

    struct vm_event vm_event;
    int fd;
    /* number of pages for which data structures were allocated */
    int max_pages;
    int num_paged_out;
    int target_tot_pages;
    int policy_mru_size;
    int use_poll_timeout;
    int debug;
    int stack_count;
    int *free_slot_stack;
    unsigned long pagein_queue[XENPAGING_PAGEIN_QUEUE_SIZE];
};

extern void create_page_in_thread(struct xenpaging *paging);
extern void page_in_trigger(void);

#endif // __XEN_PAGING_H__


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
