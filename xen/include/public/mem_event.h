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


/* Memory event notification modes */
#define MEM_EVENT_MODE_ASYNC    0
#define MEM_EVENT_MODE_SYNC     (1 << 0)
#define MEM_EVENT_MODE_SYNC_ALL (1 << 1)

/* Memory event flags */
#define MEM_EVENT_FLAG_VCPU_PAUSED  (1 << 0)
#define MEM_EVENT_FLAG_DOM_PAUSED   (1 << 1)
#define MEM_EVENT_FLAG_OUT_OF_MEM   (1 << 2)


typedef struct mem_event_shared_page {
    int port;
} mem_event_shared_page_t;

typedef struct mem_event_st {
    unsigned long gfn;
    unsigned long offset;
    unsigned long p2mt;
    int vcpu_id;
    uint64_t flags;
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
