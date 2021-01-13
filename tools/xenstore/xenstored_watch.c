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
#include "xenstore_lib.h"
#include "utils.h"
#include "xenstored_domain.h"

extern int quota_nb_watch_per_domain;

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

static bool check_special_event(const char *name)
{
	assert(name);

	return strstarts(name, "@");
}

/* Is child a subnode of parent, or equal? */
static bool is_child(const char *child, const char *parent)
{
	unsigned int len = strlen(parent);

	/*
	 * / should really be "" for this algorithm to work, but that's a
	 * usability nightmare.
	 */
	if (streq(parent, "/"))
		return true;

	if (strncmp(child, parent, len) != 0)
		return false;

	return child[len] == '/' || child[len] == '\0';
}

static const char *get_watch_path(const struct watch *watch, const char *name)
{
	const char *path = name;

	if (watch->relative_path) {
		path += strlen(watch->relative_path);
		if (*path == '/') /* Could be "" */
			path++;
	}

	return path;
}

/*
 * Send a watch event.
 * Temporary memory allocations are done with ctx.
 */
static void add_event(struct connection *conn,
		      const void *ctx,
		      struct watch *watch,
		      const char *name)
{
	/* Data to send (node\0token\0). */
	unsigned int len;
	char *data;

	name = get_watch_path(watch, name);

	len = strlen(name) + 1 + strlen(watch->token) + 1;
	/* Don't try to send over-long events. */
	if (len > XENSTORE_PAYLOAD_MAX)
		return;

	data = talloc_array(ctx, char, len);
	if (!data)
		return;
	strcpy(data, name);
	strcpy(data + strlen(name) + 1, watch->token);
	send_reply(conn, XS_WATCH_EVENT, data, len);
	talloc_free(data);
}

/*
 * Check permissions of a specific watch to fire:
 * Either the node itself or its parent have to be readable by the connection
 * the watch has been setup for. In case a watch event is created due to
 * changed permissions we need to take the old permissions into account, too.
 */
static bool watch_permitted(struct connection *conn, const void *ctx,
			    const char *name, struct node *node,
			    struct node_perms *perms)
{
	enum xs_perm_type perm;
	struct node *parent;
	char *parent_name;

	if (perms) {
		perm = perm_for_conn(conn, perms);
		if (perm & XS_PERM_READ)
			return true;
	}

	if (!node) {
		node = read_node(conn, ctx, name);
		if (!node)
			return false;
	}

	perm = perm_for_conn(conn, &node->perms);
	if (perm & XS_PERM_READ)
		return true;

	parent = node->parent;
	if (!parent) {
		parent_name = get_parent(ctx, node->name);
		if (!parent_name)
			return false;
		parent = read_node(conn, ctx, parent_name);
		if (!parent)
			return false;
	}

	perm = perm_for_conn(conn, &parent->perms);

	return perm & XS_PERM_READ;
}

/*
 * Check whether any watch events are to be sent.
 * Temporary memory allocations are done with ctx.
 * We need to take the (potential) old permissions of the node into account
 * as a watcher losing permissions to access a node should receive the
 * watch event, too.
 */
void fire_watches(struct connection *conn, const void *ctx, const char *name,
		  struct node *node, bool exact, struct node_perms *perms)
{
	struct connection *i;
	struct watch *watch;

	/* During transactions, don't fire watches. */
	if (conn && conn->transaction)
		return;

	/* Create an event for each watch. */
	list_for_each_entry(i, &connections, list) {
		/* introduce/release domain watches */
		if (check_special_event(name)) {
			if (!check_perms_special(name, i))
				continue;
		} else {
			if (!watch_permitted(i, ctx, name, node, perms))
				continue;
		}

		list_for_each_entry(watch, &i->watches, list) {
			if (exact) {
				if (streq(name, watch->node))
					add_event(i, ctx, watch, name);
			} else {
				if (is_child(name, watch->node))
					add_event(i, ctx, watch, name);
			}
		}
	}
}

static int destroy_watch(void *_watch)
{
	trace_destroy(_watch, "watch");
	return 0;
}

static int check_watch_path(struct connection *conn, const void *ctx,
			    char **path, bool *relative)
{
	/* Check if valid event. */
	if (strstarts(*path, "@")) {
		*relative = false;
		if (strlen(*path) > XENSTORE_REL_PATH_MAX)
			goto inval;
	} else {
		*relative = !strstarts(*path, "/");
		*path = canonicalize(conn, ctx, *path);
		if (!*path)
			return errno;
		if (!is_valid_nodename(*path))
			goto inval;
	}

	return 0;

 inval:
	errno = EINVAL;
	return errno;
}

static struct watch *add_watch(struct connection *conn, char *path, char *token,
			       bool relative)
{
	struct watch *watch;

	watch = talloc(conn, struct watch);
	if (!watch)
		goto nomem;
	watch->node = talloc_strdup(watch, path);
	watch->token = talloc_strdup(watch, token);
	if (!watch->node || !watch->token)
		goto nomem;

	if (relative)
		watch->relative_path = get_implicit_path(conn);
	else
		watch->relative_path = NULL;

	INIT_LIST_HEAD(&watch->events);

	domain_watch_inc(conn);
	list_add_tail(&watch->list, &conn->watches);
	talloc_set_destructor(watch, destroy_watch);

	return watch;

 nomem:
	talloc_free(watch);
	errno = ENOMEM;
	return NULL;
}

int do_watch(struct connection *conn, struct buffered_data *in)
{
	struct watch *watch;
	char *vec[2];
	bool relative;

	if (get_strings(in, vec, ARRAY_SIZE(vec)) != ARRAY_SIZE(vec))
		return EINVAL;

	errno = check_watch_path(conn, in, &(vec[0]), &relative);
	if (errno)
		return errno;

	/* Check for duplicates. */
	list_for_each_entry(watch, &conn->watches, list) {
		if (streq(watch->node, vec[0]) &&
		    streq(watch->token, vec[1]))
			return EEXIST;
	}

	if (domain_watch(conn) > quota_nb_watch_per_domain)
		return E2BIG;

	watch = add_watch(conn, vec[0], vec[1], relative);
	if (!watch)
		return errno;

	trace_create(watch, "watch");
	send_ack(conn, XS_WATCH);

	/* We fire once up front: simplifies clients and restart. */
	add_event(conn, in, watch, watch->node);

	return 0;
}

int do_unwatch(struct connection *conn, struct buffered_data *in)
{
	struct watch *watch;
	char *node, *vec[2];

	if (get_strings(in, vec, ARRAY_SIZE(vec)) != ARRAY_SIZE(vec))
		return EINVAL;

	node = canonicalize(conn, in, vec[0]);
	if (!node)
		return ENOMEM;
	list_for_each_entry(watch, &conn->watches, list) {
		if (streq(watch->node, node) && streq(watch->token, vec[1])) {
			list_del(&watch->list);
			talloc_free(watch);
			domain_watch_dec(conn);
			send_ack(conn, XS_UNWATCH);
			return 0;
		}
	}
	return ENOENT;
}

void conn_delete_all_watches(struct connection *conn)
{
	struct watch *watch;

	while ((watch = list_top(&conn->watches, struct watch, list))) {
		list_del(&watch->list);
		talloc_free(watch);
		domain_watch_dec(conn);
	}
}

const char *dump_state_watches(FILE *fp, struct connection *conn,
			       unsigned int conn_id)
{
	const char *ret = NULL;
	struct watch *watch;
	struct xs_state_watch sw;
	struct xs_state_record_header head;
	const char *path;

	head.type = XS_STATE_TYPE_WATCH;

	list_for_each_entry(watch, &conn->watches, list) {
		head.length = sizeof(sw);

		sw.conn_id = conn_id;
		path = get_watch_path(watch, watch->node);
		sw.path_length = strlen(path) + 1;
		sw.token_length = strlen(watch->token) + 1;
		head.length += sw.path_length + sw.token_length;
		head.length = ROUNDUP(head.length, 3);
		if (fwrite(&head, sizeof(head), 1, fp) != 1)
			return "Dump watch state error";
		if (fwrite(&sw, sizeof(sw), 1, fp) != 1)
			return "Dump watch state error";

		if (fwrite(path, sw.path_length, 1, fp) != 1)
			return "Dump watch path error";
		if (fwrite(watch->token, sw.token_length, 1, fp) != 1)
			return "Dump watch token error";

		ret = dump_state_align(fp);
		if (ret)
			return ret;
	}

	return ret;
}

void read_state_watch(const void *ctx, const void *state)
{
	const struct xs_state_watch *sw = state;
	struct connection *conn;
	char *path, *token;
	bool relative;

	conn = get_connection_by_id(sw->conn_id);
	if (!conn)
		barf("connection not found for read watch");

	path = (char *)sw->data;
	token = path + sw->path_length;

	/* Don't check success, we want the relative information only. */
	check_watch_path(conn, ctx, &path, &relative);
	if (!path)
		barf("allocation error for read watch");

	if (!add_watch(conn, path, token, relative))
		barf("error adding watch");
}

/*
 * Local variables:
 *  mode: C
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
