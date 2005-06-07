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

#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include "talloc.h"
#include "list.h"
#include "xenstored_watch.h"
#include "xs_lib.h"
#include "utils.h"
#include "xenstored_test.h"

/* We create this if anyone is interested "node", then we pass it from
 * watch to watch as each connection acks it.
 */
struct watch_event
{
	/* The watch we are firing for (watch->events) */
	struct list_head list;

	/* Watch we are currently attached to. */
	struct watch *watch;

	struct buffered_data *data;
};

struct watch
{
	struct list_head list;
	unsigned int priority;

	/* Current outstanding events applying to this watch. */
	struct list_head events;

	char *node;
	struct connection *conn;
};
static LIST_HEAD(watches);

static void reset_event(struct watch_event *event)
{
	event->data->inhdr = true;
	event->data->used = 0;
}

/* We received a non-ACK response: re-queue any watch we just sent. */
void reset_watch_event(struct connection *conn)
{
	if (waiting_for_ack(conn))
		reset_event(conn->event);
}

/* We're waiting if we have an event and we sent it all. */
bool waiting_for_ack(struct connection *conn)
{
	if (!conn->event)
		return false;

	if (conn->event->data->inhdr)
		return false;
	return conn->event->data->used == conn->event->data->hdr.msg.len;
}

bool is_watch_event(struct connection *conn, struct buffered_data *out)
{
	return (conn->event && out == conn->event->data);
}

/* Look through our watches: if any of them have an event, queue it. */
void queue_next_event(struct connection *conn)
{
	struct watch *watch;

	/* We had a reply queued already?  Send it. */
	if (conn->waiting_reply) {
		conn->out = conn->waiting_reply;
		conn->waiting_reply = NULL;
		return;
	}

	/* If we're waiting for ack, don't queue more. */
	if (waiting_for_ack(conn))
		return;

	/* Find a good event to send. */
	if (!conn->event) {
		list_for_each_entry(watch, &watches, list) {
			if (watch->conn != conn)
				continue;

			conn->event = list_top(&watch->events,
					       struct watch_event, list);
			if (conn->event)
				break;
		}
		if (!conn->event)
			return;
	}

	conn->out = conn->event->data;
}

/* Watch on DIR applies to DIR, DIR/FILE, but not DIRLONG. */
static bool watch_applies(const struct watch *watch, const char *node)
{
	return is_child(node, watch->node);
}

static struct watch *find_watch(const char *node)
{
	struct watch *watch;

	list_for_each_entry(watch, &watches, list) {
		if (watch_applies(watch, node))
			return watch;
	}
	return NULL;
}

static struct watch *find_next_watch(struct watch *watch, const char *node)
{
	list_for_each_entry_continue(watch, &watches, list) {
		if (watch_applies(watch, node))
			return watch;
	}
	return NULL;
}

/* FIXME: we fail to fire on out of memory.  Should drop connections. */
void fire_watches(struct transaction *trans, const char *node)
{
	struct watch *watch;
	struct watch_event *event;

	/* During transactions, don't fire watches. */
	if (trans)
		return;

	watch = find_watch(node);
	if (!watch)
		return;

	/* Create and fill in info about event. */
	event = talloc(talloc_autofree_context(), struct watch_event);
	event->data = new_buffer(event);
	event->data->hdr.msg.type = XS_WATCH_EVENT;
	event->data->hdr.msg.len = strlen(node) + 1;
	event->data->buffer = talloc_strdup(event->data, node);

	/* Tie event to this watch. */
	event->watch = watch;
	list_add(&event->list, &watch->events);

	/* If connection not doing anything, queue this. */
	if (!watch->conn->out)
		queue_next_event(watch->conn);
}

/* We're done with this event: see if anyone else wants it. */
static void move_event_onwards(struct watch_event *event)
{
	list_del(&event->list);
	reset_event(event);

	/* Remove from this watch, and find next watch to put this on. */
	event->watch = find_next_watch(event->watch, event->data->buffer);
	if (!event->watch) {
		talloc_free(event);
		return;
	}

	list_add(&event->list, &event->watch->events);

	/* If connection not doing anything, queue this. */
	if (!event->watch->conn->out)
		queue_next_event(event->watch->conn);
}

static int destroy_watch(void *_watch)
{
	struct watch *watch = _watch;
	struct watch_event *event;

	/* Forget about sending out or waiting for acks for this watch.  */
	if (watch->conn->event && watch->conn->event->watch == watch)
		watch->conn->event = NULL;

	/* If we have pending events, pass them on to others. */
	while ((event = list_top(&watch->events, struct watch_event, list)))
		move_event_onwards(event);

	/* Remove from global list. */
	list_del(&watch->list);
	return 0;
}

/* We keep watches in priority order. */
static void insert_watch(struct watch *watch)
{
	struct watch *i;

	list_for_each_entry(i, &watches, list) {
		if (i->priority <= watch->priority) {
			list_add_tail(&watch->list, &i->list);
			return;
		}
	}

	list_add_tail(&watch->list, &watches);
}

bool do_watch(struct connection *conn, struct buffered_data *in)
{
	struct watch *watch;
	char *vec[2];

	if (get_strings(in, vec, ARRAY_SIZE(vec)) != ARRAY_SIZE(vec))
		return send_error(conn, EINVAL);

	if (!check_node_perms(conn, vec[0], XS_PERM_READ))
		return send_error(conn, errno);

	watch = talloc(conn, struct watch);
	watch->node = talloc_strdup(watch, vec[0]);
	watch->conn = conn;
	watch->priority = strtoul(vec[1], NULL, 0);
	INIT_LIST_HEAD(&watch->events);

	insert_watch(watch);
	talloc_set_destructor(watch, destroy_watch);
	return send_ack(conn, XS_WATCH);
}

bool do_watch_ack(struct connection *conn)
{
	struct watch_event *event;

	if (!waiting_for_ack(conn))
		return send_error(conn, ENOENT);

	/* Remove this watch event. */
	event = conn->event;
	conn->event = NULL;

	move_event_onwards(event);
	return send_ack(conn, XS_WATCH_ACK);
}

bool do_unwatch(struct connection *conn, const char *node)
{
	struct watch *watch;

	list_for_each_entry(watch, &watches, list) {
		if (watch->conn == conn
		    && streq(watch->node, node)) {
			talloc_free(watch);
			return send_ack(conn, XS_UNWATCH);
		}
	}
	return send_error(conn, ENOENT);
}
