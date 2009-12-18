/******************************************************************************
 * tools/xenpaging/mem_event.h
 *
 * Memory event structures.
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


#ifndef __XEN_MEM_EVENT_H__
#define __XEN_MEM_EVENT_H__


#include "spinlock.h"
#include "xc.h"
#include <xc_private.h>

#include <xen/event_channel.h>
#include <xen/mem_event.h>


#define mem_event_ring_lock_init(_m)  spin_lock_init(&(_m)->ring_lock)
#define mem_event_ring_lock(_m)       spin_lock(&(_m)->ring_lock)
#define mem_event_ring_unlock(_m)     spin_unlock(&(_m)->ring_lock)


typedef struct mem_event {
    domid_t domain_id;
    int xce_handle;
    int port;
    mem_event_back_ring_t back_ring;
    mem_event_shared_page_t *shared_page;
    void *ring_page;
    spinlock_t ring_lock;
} mem_event_t;


#endif // __XEN_MEM_EVENT_H__


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
