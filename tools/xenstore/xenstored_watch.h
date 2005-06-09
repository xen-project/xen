/* 
    Watch code for Xen Store Daemon.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef _XENSTORED_WATCH_H
#define _XENSTORED_WATCH_H
#include "xenstored_core.h"

bool do_watch(struct connection *conn, struct buffered_data *in);
bool do_watch_ack(struct connection *conn);
bool do_unwatch(struct connection *conn, const char *node);

/* Is this a watch event message for this connection? */
bool is_watch_event(struct connection *conn, struct buffered_data *out);

/* Look through our watches: if any of them have an event, queue it. */
void queue_next_event(struct connection *conn);

/* Is this connection waiting for a watch acknowledgement? */
bool waiting_for_ack(struct connection *conn);

/* Reset event if we were sending one */
void reset_watch_event(struct connection *conn);

/* Fire all watches. */
void fire_watches(struct transaction *trans, const char *node);

#endif /* _XENSTORED_WATCH_H */
