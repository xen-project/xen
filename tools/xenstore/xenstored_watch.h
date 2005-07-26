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

void do_watch(struct connection *conn, struct buffered_data *in);
void do_watch_ack(struct connection *conn, const char *token);
void do_unwatch(struct connection *conn, struct buffered_data *in);

/* Is this a watch event message for this connection? */
bool is_watch_event(struct connection *conn, struct buffered_data *out);

/* Look through our watches: if any of them have an event, queue it. */
void queue_next_event(struct connection *conn);

/* Fire all watches: recurse means all the children are effected (ie. rm).
 * Returns true if there were any, meaning connection has to wait.
 */
bool fire_watches(struct connection *conn, const char *node, bool recurse);

/* Find shortest timeout: if any, reduce tv (may already be set). */
void shortest_watch_ack_timeout(struct timeval *tv);

/* Check for watches which may have timed out. */
void check_watch_ack_timeout(void);

void dump_watches(struct connection *conn);

#endif /* _XENSTORED_WATCH_H */
