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
#include "talloc.h"
#include "list.h"
#include "xenstored_watch.h"
#include "xs_lib.h"
#include "utils.h"
#include "xenstored_test.h"

/* FIXME: time out unacked watches. */

/* We create this if anyone is interested "node", then we pass it from
 * watch to watch as each connection acks it.
 */
struct watch_event
{
	/* The watch we are firing for (watch->events) */
	struct list_head list;

	/* Watch we are currently attached to. */
	struct watch *watch;

	struct timeval timeout;

	/* Name of node which changed. */
	char *node;
};

struct watch
{
	struct list_head list;
	unsigned int priority;

	/* Current outstanding events applying to this watch. */
	struct list_head events;

	char *token;
	char *node;
	struct connection *conn;
};
static LIST_HEAD(watches);

static struct watch_event *get_first_event(struct connection *conn)
{
	struct watch *watch;
	struct watch_event *event;

	/* Find first watch with an event. */
	list_for_each_entry(watch, &watches, list) {
		if (watch->conn != conn)
			continue;

		event = list_top(&watch->events, struct watch_event, list);
		if (event)
			return event;
	}
	return NULL;
}

/* Look through our watches: if any of them have an event, queue it. */
void queue_next_event(struct connection *conn)
{
	struct watch_event *event;
	char *buffer;
	unsigned int len;

	/* We had a reply queued already?  Send it: other end will
	 * discard watch. */
	if (conn->waiting_reply) {
		conn->out = conn->waiting_reply;
		conn->waiting_reply = NULL;
		conn->waiting_for_ack = false;
		return;
	}

	/* If we're already waiting for ack, don't queue more. */
	if (conn->waiting_for_ack)
		return;

	event = get_first_event(conn);
	if (!event)
		return;

	/* If we decide to cancel, we will reset this. */
	conn->waiting_for_ack = true;

	/* Create reply from path and token */
	len = strlen(event->node) + 1 + strlen(event->watch->token) + 1;
	buffer = talloc_array(conn, char, len);
	strcpy(buffer, event->node);
	strcpy(buffer+strlen(event->node)+1, event->watch->token);
	send_reply(conn, XS_WATCH_EVENT, buffer, len);
	talloc_free(buffer);
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
	event->node = talloc_strdup(event, node);

	/* Tie event to this watch. */
	event->watch = watch;
	list_add_tail(&event->list, &watch->events);

	/* Warn if not finished after thirty seconds. */
	gettimeofday(&event->timeout, NULL);
	event->timeout.tv_sec += 30;

	/* If connection not doing anything, queue this. */
	if (!watch->conn->out)
		queue_next_event(watch->conn);
}

/* We're done with this event: see if anyone else wants it. */
static void move_event_onwards(struct watch_event *event)
{
	list_del(&event->list);

	/* Remove from this watch, and find next watch to put this on. */
	event->watch = find_next_watch(event->watch, event->node);
	if (!event->watch) {
		talloc_free(event);
		return;
	}

	list_add_tail(&event->list, &event->watch->events);

	/* If connection not doing anything, queue this. */
	if (!event->watch->conn->out)
		queue_next_event(event->watch->conn);
}

static int destroy_watch(void *_watch)
{
	struct watch *watch = _watch;
	struct watch_event *event;

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

void shortest_watch_ack_timeout(struct timeval *tv)
{
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
}	

void check_watch_ack_timeout(void)
{
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
				timerclear(&i->timeout);
			}
		}
	}
}

bool do_watch(struct connection *conn, struct buffered_data *in)
{
	struct watch *watch;
	char *vec[3];

	if (get_strings(in, vec, ARRAY_SIZE(vec)) != ARRAY_SIZE(vec))
		return send_error(conn, EINVAL);

	vec[0] = canonicalize(conn, vec[0]);
	if (!check_node_perms(conn, vec[0], XS_PERM_READ))
		return send_error(conn, errno);

	watch = talloc(conn, struct watch);
	watch->node = talloc_strdup(watch, vec[0]);
	watch->token = talloc_strdup(watch, vec[1]);
	watch->conn = conn;
	watch->priority = strtoul(vec[2], NULL, 0);
	INIT_LIST_HEAD(&watch->events);

	insert_watch(watch);
	talloc_set_destructor(watch, destroy_watch);
	return send_ack(conn, XS_WATCH);
}

bool do_watch_ack(struct connection *conn, const char *token)
{
	struct watch_event *event;

	if (!conn->waiting_for_ack)
		return send_error(conn, ENOENT);

	event = get_first_event(conn);
	if (!streq(event->watch->token, token))
		return send_error(conn, EINVAL);

	move_event_onwards(event);
	conn->waiting_for_ack = false;
	return send_ack(conn, XS_WATCH_ACK);
}

bool do_unwatch(struct connection *conn, struct buffered_data *in)
{
	struct watch *watch;
	char *node, *vec[2];

	if (get_strings(in, vec, ARRAY_SIZE(vec)) != ARRAY_SIZE(vec))
		return send_error(conn, EINVAL);

	node = canonicalize(conn, vec[0]);
	list_for_each_entry(watch, &watches, list) {
		if (watch->conn != conn)
			continue;

		if (streq(watch->node, node) && streq(watch->token, vec[1])) {
			talloc_free(watch);
			return send_ack(conn, XS_UNWATCH);
		}
	}
	return send_error(conn, ENOENT);
}

#ifdef TESTING
void dump_watches(struct connection *conn)
{
	struct watch *watch;
	struct watch_event *event;

	/* Find first watch with an event. */
	list_for_each_entry(watch, &watches, list) {
		if (watch->conn != conn)
			continue;

		printf("    watch on %s token %s prio %i\n",
		       watch->node, watch->token, watch->priority);
		list_for_each_entry(event, &watch->events, list)
			printf("        event: %s\n", event->node);
	}
}
#endif
