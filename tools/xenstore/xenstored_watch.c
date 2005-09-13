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
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include "talloc.h"
#include "list.h"
#include "xenstored_watch.h"
#include "xs_lib.h"
#include "utils.h"
#include "xenstored_test.h"
#include "xenstored_domain.h"

/* FIXME: time out unacked watches. */
struct watch_event
{
	/* The events on this watch. */
	struct list_head list;

	/* Data to send (node\0token\0). */
	unsigned int len;
	char *data;
};

struct watch
{
	/* Watches on this connection */
	struct list_head list;

	/* Current outstanding events applying to this watch. */
	struct list_head events;

	/* Is this relative to connnection's implicit path? */
	const char *relative_path;

	char *token;
	char *node;
};

/* Look through our watches: if any of them have an event, queue it. */
void queue_next_event(struct connection *conn)
{
	struct watch_event *event;
	struct watch *watch;

	/* We had a reply queued already?  Send it: other end will
	 * discard watch. */
	if (conn->waiting_reply) {
		conn->out = conn->waiting_reply;
		conn->waiting_reply = NULL;
		conn->waiting_for_ack = NULL;
		return;
	}

	/* If we're already waiting for ack, don't queue more. */
	if (conn->waiting_for_ack)
		return;

	list_for_each_entry(watch, &conn->watches, list) {
		event = list_top(&watch->events, struct watch_event, list);
		if (event) {
			conn->waiting_for_ack = watch;
			send_reply(conn,XS_WATCH_EVENT,event->data,event->len);
			break;
		}
	}
}

static int destroy_watch_event(void *_event)
{
	struct watch_event *event = _event;

	trace_destroy(event, "watch_event");
	return 0;
}

static void add_event(struct connection *conn,
		      struct watch *watch, const char *node)
{
	struct watch_event *event;

	/* Check read permission: no permission, no watch event.
	 * If it doesn't exist, we need permission to read parent.
	 */
	if (!check_node_perms(conn, node, XS_PERM_READ|XS_PERM_ENOENT_OK) &&
	    !check_event_node(node)) {
		return;
	}

	if (watch->relative_path) {
		node += strlen(watch->relative_path);
		if (*node == '/') /* Could be "" */
			node++;
	}

	event = talloc(watch, struct watch_event);
	event->len = strlen(node) + 1 + strlen(watch->token) + 1;
	event->data = talloc_array(event, char, event->len);
	strcpy(event->data, node);
	strcpy(event->data + strlen(node) + 1, watch->token);
	talloc_set_destructor(event, destroy_watch_event);
	list_add_tail(&event->list, &watch->events);
	trace_create(event, "watch_event");
}

/* FIXME: we fail to fire on out of memory.  Should drop connections. */
void fire_watches(struct connection *conn, const char *node, bool recurse)
{
	struct connection *i;
	struct watch *watch;

	/* During transactions, don't fire watches. */
	if (conn && conn->transaction)
		return;

	/* Create an event for each watch. */
	list_for_each_entry(i, &connections, list) {
		list_for_each_entry(watch, &i->watches, list) {
			if (is_child(node, watch->node))
				add_event(i, watch, node);
			else if (recurse && is_child(watch->node, node))
				add_event(i, watch, watch->node);
			else
				continue;
			/* If connection not doing anything, queue this. */
			if (!i->out)
				queue_next_event(i);
		}
	}
}

static int destroy_watch(void *_watch)
{
	trace_destroy(_watch, "watch");
	return 0;
}

void shortest_watch_ack_timeout(struct timeval *tv)
{
	(void)tv;
#if 0 /* FIXME */
	struct watch *watch;

	list_for_each_entry(watch, &watches, list) {
		struct watch_event *i;
		list_for_each_entry(i, &watch->events, list) {
			if (!timerisset(&i->timeout))
				continue;
			if (!timerisset(tv) || timercmp(&i->timeout, tv, <))
				*tv = i->timeout;
		}
	}
#endif
}	

void check_watch_ack_timeout(void)
{
#if 0
	struct watch *watch;
	struct timeval now;

	gettimeofday(&now, NULL);
	list_for_each_entry(watch, &watches, list) {
		struct watch_event *i, *tmp;
		list_for_each_entry_safe(i, tmp, &watch->events, list) {
			if (!timerisset(&i->timeout))
				continue;
			if (timercmp(&i->timeout, &now, <)) {
				xprintf("Warning: timeout on watch event %s"
					" token %s\n",
					i->node, watch->token);
				trace_watch_timeout(watch->conn, i->node,
						    watch->token);
				timerclear(&i->timeout);
			}
		}
	}
#endif
}

void do_watch(struct connection *conn, struct buffered_data *in)
{
	struct watch *watch;
	char *vec[2];
	bool relative;

	if (get_strings(in, vec, ARRAY_SIZE(vec)) != ARRAY_SIZE(vec)) {
		send_error(conn, EINVAL);
		return;
	}

	if (strstarts(vec[0], "@")) {
		relative = false;
		/* check if valid event */
	} else {
		relative = !strstarts(vec[0], "/");
		vec[0] = canonicalize(conn, vec[0]);
		if (!is_valid_nodename(vec[0])) {
			send_error(conn, errno);
			return;
		}
	}

	watch = talloc(conn, struct watch);
	watch->node = talloc_strdup(watch, vec[0]);
	watch->token = talloc_strdup(watch, vec[1]);
	if (relative)
		watch->relative_path = get_implicit_path(conn);
	else
		watch->relative_path = NULL;

	INIT_LIST_HEAD(&watch->events);

	list_add_tail(&watch->list, &conn->watches);
	trace_create(watch, "watch");
	talloc_set_destructor(watch, destroy_watch);
	send_ack(conn, XS_WATCH);
}

void do_watch_ack(struct connection *conn, const char *token)
{
	struct watch_event *event;

	if (!token) {
		send_error(conn, EINVAL);
		return;
	}

	if (!conn->waiting_for_ack) {
		send_error(conn, ENOENT);
		return;
	}

	if (!streq(conn->waiting_for_ack->token, token)) {
		/* They're confused: this will cause us to send event again */
		conn->waiting_for_ack = NULL;
		send_error(conn, EINVAL);
		return;
	}

	/* Remove event: after ack sent, core will call queue_next_event */
	event = list_top(&conn->waiting_for_ack->events, struct watch_event,
			 list);
	list_del(&event->list);
	talloc_free(event);

	conn->waiting_for_ack = NULL;
	send_ack(conn, XS_WATCH_ACK);
}

void do_unwatch(struct connection *conn, struct buffered_data *in)
{
	struct watch *watch;
	char *node, *vec[2];

	if (get_strings(in, vec, ARRAY_SIZE(vec)) != ARRAY_SIZE(vec)) {
		send_error(conn, EINVAL);
		return;
	}

	/* We don't need to worry if we're waiting for an ack for the
	 * watch we're deleting: conn->waiting_for_ack was reset by
	 * this command in consider_message anyway. */
	node = canonicalize(conn, vec[0]);
	list_for_each_entry(watch, &conn->watches, list) {
		if (streq(watch->node, node) && streq(watch->token, vec[1])) {
			list_del(&watch->list);
			talloc_free(watch);
			send_ack(conn, XS_UNWATCH);
			return;
		}
	}
	send_error(conn, ENOENT);
}

#ifdef TESTING
void dump_watches(struct connection *conn)
{
	struct watch *watch;
	struct watch_event *event;

	if (conn->waiting_for_ack)
		printf("    waiting_for_ack for watch on %s token %s\n",
		       conn->waiting_for_ack->node,
		       conn->waiting_for_ack->token);

	list_for_each_entry(watch, &conn->watches, list) {
		printf("    watch on %s token %s\n",
		       watch->node, watch->token);
		list_for_each_entry(event, &watch->events, list)
			printf("        event: %s\n", event->data);
	}
}
#endif
