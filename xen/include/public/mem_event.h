/******************************************************************************
 * mem_event.h
 *
 * Memory event common structures.
 *
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
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

#ifndef _XEN_PUBLIC_MEM_EVENT_H
#define _XEN_PUBLIC_MEM_EVENT_H

#include "xen.h"
#include "io/ring.h"

/* Memory event type */
#define MEM_EVENT_TYPE_SHARED   0
#define MEM_EVENT_TYPE_PAGING   1
#define MEM_EVENT_TYPE_ACCESS   2

/* Memory event flags */
#define MEM_EVENT_FLAG_VCPU_PAUSED  (1 << 0)
#define MEM_EVENT_FLAG_DROP_PAGE    (1 << 1)

/* Reasons for the memory event request */
#define MEM_EVENT_REASON_UNKNOWN     0    /* typical reason */
#define MEM_EVENT_REASON_VIOLATION   1    /* access violation, GFN is address */
#define MEM_EVENT_REASON_CR0         2    /* CR0 was hit: gfn is CR0 value */
#define MEM_EVENT_REASON_CR3         3    /* CR3 was hit: gfn is CR3 value */
#define MEM_EVENT_REASON_CR4         4    /* CR4 was hit: gfn is CR4 value */
#define MEM_EVENT_REASON_INT3        5    /* int3 was hit: gla/gfn are RIP */

typedef struct mem_event_shared_page {
    uint32_t port;
} mem_event_shared_page_t;

typedef struct mem_event_st {
    uint16_t type;
    uint16_t flags;
    uint32_t vcpu_id;

    uint64_t gfn;
    uint64_t offset;
    uint64_t gla; /* if gla_valid */

    uint32_t p2mt;

    uint16_t access_r:1;
    uint16_t access_w:1;
    uint16_t access_x:1;
    uint16_t gla_valid:1;
    uint16_t available:12;

    uint16_t reason;
} mem_event_request_t, mem_event_response_t;

DEFINE_RING_TYPES(mem_event, mem_event_request_t, mem_event_response_t);

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
