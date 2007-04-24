/*
 * Copyright (c) 2006-2007, XenSource Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef XEN_EVENT_H
#define XEN_EVENT_H

#include <xen/api/xen_common.h>
#include <xen/api/xen_event_decl.h>
#include <xen/api/xen_event_operation.h>
#include <xen/api/xen_string_set.h>


/*
 * The event class.
 * 
 * Asynchronous event registration and handling.
 */



typedef struct xen_event_record
{
    int64_t id;
    time_t timestamp;
    char *class;
    enum xen_event_operation operation;
    char *ref;
    char *obj_uuid;
} xen_event_record;

/**
 * Allocate a xen_event_record.
 */
extern xen_event_record *
xen_event_record_alloc(void);

/**
 * Free the given xen_event_record, and all referenced values.  The
 * given record must have been allocated by this library.
 */
extern void
xen_event_record_free(xen_event_record *record);


typedef struct xen_event_record_set
{
    size_t size;
    xen_event_record *contents[];
} xen_event_record_set;

/**
 * Allocate a xen_event_record_set of the given size.
 */
extern xen_event_record_set *
xen_event_record_set_alloc(size_t size);

/**
 * Free the given xen_event_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_event_record_set_free(xen_event_record_set *set);


/**
 * Registers this session with the event system.  Specifying the empty
 * list will register for all classes.
 */
extern bool
xen_event_register(xen_session *session, struct xen_string_set *classes);


/**
 * Unregisters this session with the event system.
 */
extern bool
xen_event_unregister(xen_session *session, struct xen_string_set *classes);


/**
 * Blocking call which returns a (possibly empty) batch of events.
 */
extern bool
xen_event_next(xen_session *session, struct xen_event_record_set **result);


#endif
