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
    along with this program; If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _XENSTORED_WATCH_H
#define _XENSTORED_WATCH_H

#include "xenstored_core.h"

int do_watch(struct connection *conn, struct buffered_data *in);
int do_unwatch(struct connection *conn, struct buffered_data *in);

/* Fire all watches: !exact means all the children are affected (ie. rm). */
void fire_watches(struct connection *conn, const void *tmp, const char *name,
		  struct node *node, bool exact, struct node_perms *perms);

void conn_delete_all_watches(struct connection *conn);

const char *dump_state_watches(FILE *fp, struct connection *conn,
			       unsigned int conn_id);

void read_state_watch(const void *ctx, const void *state);

#endif /* _XENSTORED_WATCH_H */
