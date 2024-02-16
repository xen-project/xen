/* 
    Simple prototype Xen Store Daemon providing simple tree-like database.
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

#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <signal.h>
#include <assert.h>
#include <setjmp.h>

#include <xenevtchn.h>
#include <xen-tools/xenstore-common.h>

#include "utils.h"
#include "list.h"
#include "talloc.h"
#include "core.h"
#include "watch.h"
#include "transaction.h"
#include "domain.h"
#include "control.h"
#include "lu.h"

extern xenevtchn_handle *xce_handle; /* in domain.c */
static int xce_pollfd_idx = -1;
struct pollfd *poll_fds;
static unsigned int current_array_size;
static unsigned int nr_fds;
static unsigned int delayed_requests;

int orig_argc;
char **orig_argv;

LIST_HEAD(connections);
int tracefd = -1;
bool keep_orphans = false;
const char *tracefile = NULL;
static struct hashtable *nodes;
unsigned int trace_flags = TRACE_OBJ | TRACE_IO;

static const char *sockmsg_string(enum xsd_sockmsg_type type);

unsigned int timeout_watch_event_msec = 20000;

void trace(const char *fmt, ...)
{
	va_list arglist;
	char *str;
	char sbuf[1024];
	int ret, dummy;

	if (tracefd < 0)
		return;

	/* try to use a static buffer */
	va_start(arglist, fmt);
	ret = vsnprintf(sbuf, 1024, fmt, arglist);
	va_end(arglist);

	if (ret <= 1024) {
		dummy = write(tracefd, sbuf, ret);
		return;
	}

	/* fail back to dynamic allocation */
	va_start(arglist, fmt);
	str = talloc_vasprintf(NULL, fmt, arglist);
	va_end(arglist);
	if (str) {
		dummy = write(tracefd, str, strlen(str));
		talloc_free(str);
	}
}

static void trace_io(const struct connection *conn,
		     const struct buffered_data *data,
		     const char *type)
{
	unsigned int i;
	time_t now;
	struct tm *tm;

	if (tracefd < 0 || !(trace_flags & TRACE_IO))
		return;

	now = time(NULL);
	tm = localtime(&now);

	trace("io: %s %p (d%u) %04d%02d%02d %02d:%02d:%02d %s (",
	      type, conn, conn->id, tm->tm_year + 1900, tm->tm_mon + 1,
	      tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,
	      sockmsg_string(data->hdr.msg.type));
	
	for (i = 0; i < data->hdr.msg.len; i++)
		trace("%c", (data->buffer[i] != '\0') ? data->buffer[i] : ' ');
	trace(")\n");
}

void trace_create(const void *data, const char *type)
{
	if (trace_flags & TRACE_OBJ)
		trace("obj: CREATE %s %p\n", type, data);
}

void trace_destroy(const void *data, const char *type)
{
	if (trace_flags & TRACE_OBJ)
		trace("obj: DESTROY %s %p\n", type, data);
}

/*
 * Return an absolute filename.
 * In case of a relative filename given as input, prepend XENSTORE_LIB_DIR.
 */
const char *absolute_filename(const void *ctx, const char *filename)
{
	if (filename[0] != '/')
		return talloc_asprintf(ctx, XENSTORE_LIB_DIR "/%s", filename);
	return talloc_strdup(ctx, filename);
}

void close_log(void)
{
	if (tracefd >= 0)
		close(tracefd);
	tracefd = -1;
}

void reopen_log(void)
{
	if (tracefile) {
		close_log();

		tracefd = open(tracefile,
			       O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);

		if (tracefd < 0)
			perror("Could not open tracefile");
		else
			trace("\n***\n");
	}
}

uint64_t get_now_msec(void)
{
	struct timespec now_ts;

	if (clock_gettime(CLOCK_MONOTONIC, &now_ts))
		barf_perror("Could not find time (clock_gettime failed)");

	return now_ts.tv_sec * 1000 + now_ts.tv_nsec / 1000000;
}

/*
 * Remove a struct buffered_data from the list of outgoing data.
 * A struct buffered_data related to a request having caused watch events to be
 * sent is kept until all those events have been written out.
 * Each watch event is referencing the related request via pend.req, while the
 * number of watch events caused by a request is kept in pend.ref.event_cnt
 * (those two cases are mutually exclusive, so the two fields can share memory
 * via a union).
 * The struct buffered_data is freed only if no related watch event is
 * referencing it. The related return data can be freed right away.
 */
static void free_buffered_data(struct buffered_data *out,
			       struct connection *conn)
{
	struct buffered_data *req;

	list_del(&out->list);
	out->on_out_list = false;

	/*
	 * Update conn->timeout_msec with the next found timeout value in the
	 * queued pending requests.
	 */
	if (out->timeout_msec) {
		conn->timeout_msec = 0;
		list_for_each_entry(req, &conn->out_list, list) {
			if (req->timeout_msec) {
				conn->timeout_msec = req->timeout_msec;
				break;
			}
		}
	}

	domain_memory_add_nochk(conn, conn->id,
				-out->hdr.msg.len - sizeof(out->hdr));

	if (out->hdr.msg.type == XS_WATCH_EVENT) {
		req = out->pend.req;
		if (req) {
			req->pend.ref.event_cnt--;
			if (!req->pend.ref.event_cnt && !req->on_out_list) {
				if (req->on_ref_list) {
					domain_outstanding_dec(conn,
						req->pend.ref.domid);
					list_del(&req->list);
				}
				talloc_free(req);
			}
		}
	} else if (out->pend.ref.event_cnt) {
		/* Hang out off from conn. */
		talloc_steal(NULL, out);
		if (out->buffer != out->default_buffer)
			talloc_free(out->buffer);
		list_add(&out->list, &conn->ref_list);
		out->on_ref_list = true;
		return;
	} else
		domain_outstanding_dec(conn, conn->id);

	talloc_free(out);
}

static void check_event_timeout(struct connection *conn, uint64_t msecs,
				int *ptimeout)
{
	uint64_t delta;
	struct buffered_data *out, *tmp;

	if (!conn->timeout_msec)
		return;

	delta = conn->timeout_msec - msecs;
	if (conn->timeout_msec <= msecs) {
		delta = 0;
		list_for_each_entry_safe(out, tmp, &conn->out_list, list) {
			/*
			 * Only look at buffers with timeout and no data
			 * already written to the ring.
			 */
			if (out->timeout_msec && out->inhdr && !out->used) {
				if (out->timeout_msec > msecs) {
					conn->timeout_msec = out->timeout_msec;
					delta = conn->timeout_msec - msecs;
					break;
				}

				/*
				 * Free out without updating conn->timeout_msec,
				 * as the update is done in this loop already.
				 */
				out->timeout_msec = 0;
				trace("watch event path %s for domain %u timed out\n",
				      out->buffer, conn->id);
				free_buffered_data(out, conn);
			}
		}
		if (!delta) {
			conn->timeout_msec = 0;
			return;
		}
	}

	if (*ptimeout == -1 || *ptimeout > delta)
		*ptimeout = delta;
}

void conn_free_buffered_data(struct connection *conn)
{
	struct buffered_data *out;

	while ((out = list_top(&conn->out_list, struct buffered_data, list)))
		free_buffered_data(out, conn);

	conn->timeout_msec = 0;
}

static bool write_messages(struct connection *conn)
{
	int ret;
	struct buffered_data *out;
	bool started = false;

	out = list_top(&conn->out_list, struct buffered_data, list);
	if (out == NULL)
		return true;

	if (out->inhdr) {
		started = !out->used;
		ret = conn->funcs->write(conn, out->hdr.raw + out->used,
					 sizeof(out->hdr) - out->used);
		if (ret < 0)
			goto err;

		out->used += ret;
		if (out->used < sizeof(out->hdr))
			goto start;

		out->inhdr = false;
		out->used = 0;

		/* Second write might block if non-zero. */
		if (out->hdr.msg.len && !conn->domain)
			goto start;
	}

	ret = conn->funcs->write(conn, out->buffer + out->used,
				 out->hdr.msg.len - out->used);
	if (ret < 0)
		goto err;

	out->used += ret;
	if (out->used != out->hdr.msg.len)
		goto start;

	trace_io(conn, out, started ? "OUT" : "OUT(END)");

	free_buffered_data(out, conn);

	return true;

 err:
	trace_io(conn, out, "OUT(ERR)");
	return false;

 start:
	if (started)
		trace_io(conn, out, "OUT(START)");
	return true;
}

static int undelay_request(void *_req)
{
	struct delayed_request *req = _req;

	list_del(&req->list);
	delayed_requests--;

	return 0;
}

static void call_delayed(struct delayed_request *req)
{
	if (req->func(req)) {
		undelay_request(req);
		talloc_set_destructor(req, NULL);
	}
}

int delay_request(struct connection *conn, struct buffered_data *in,
		  bool (*func)(struct delayed_request *), void *data,
		  bool no_quota_check)
{
	struct delayed_request *req;

	/*
	 * Only allow one request can be delayed for an unprivileged
	 * connection.
	 */
	if (!no_quota_check && domain_is_unprivileged(conn) &&
	    !list_empty(&conn->delayed))
		return ENOSPC;

	req = talloc(in, struct delayed_request);
	if (!req)
		return ENOMEM;

	/* For the case of connection being closed. */
	talloc_set_destructor(req, undelay_request);

	req->in = in;
	req->func = func;
	req->data = data;

	delayed_requests++;
	list_add(&req->list, &conn->delayed);

	/* Unlink the request from conn if this is the current one */
	if (conn->in == in)
		conn->in = NULL;

	return 0;
}

static int destroy_conn(void *_conn)
{
	struct connection *conn = _conn;
	struct buffered_data *req;

	/* Flush outgoing if possible, but don't block. */
	if (!conn->domain) {
		struct pollfd pfd;
		pfd.fd = conn->fd;
		pfd.events = POLLOUT;

		while (!list_empty(&conn->out_list)
		       && poll(&pfd, 1, 0) == 1)
			if (!write_messages(conn))
				break;
		close(conn->fd);
	}

	conn_free_buffered_data(conn);
	conn_delete_all_watches(conn);
	list_for_each_entry(req, &conn->ref_list, list)
		req->on_ref_list = false;

        if (conn->target)
                talloc_unlink(conn, conn->target);
	list_del(&conn->list);
	trace_destroy(conn, "connection");
	return 0;
}

static bool conn_can_read(struct connection *conn)
{
	if (conn->is_ignored)
		return false;

	if (!conn->funcs->can_read(conn))
		return false;

	/*
	 * For stalled connection, we want to process the pending
	 * command as soon as live-update has aborted.
	 */
	if (conn->is_stalled)
		return !lu_is_pending();

	return true;
}

static bool conn_can_write(struct connection *conn)
{
	return !conn->is_ignored && conn->funcs->can_write(conn);
}

/* This function returns index inside the array if succeed, -1 if fail */
int set_fd(int fd, short events)
{
	int ret;
	if (current_array_size < nr_fds + 1) {
		struct pollfd *new_fds = NULL;
		unsigned long newsize;

		/* Round up to 2^8 boundary, in practice this just
		 * make newsize larger than current_array_size.
		 */
		newsize = ROUNDUP(nr_fds + 1, 8);

		new_fds = realloc(poll_fds, sizeof(struct pollfd)*newsize);
		if (!new_fds)
			goto fail;
		poll_fds = new_fds;

		memset(&poll_fds[0] + current_array_size, 0,
		       sizeof(struct pollfd ) * (newsize-current_array_size));
		current_array_size = newsize;
	}

	poll_fds[nr_fds].fd = fd;
	poll_fds[nr_fds].events = events;
	ret = nr_fds;
	nr_fds++;

	return ret;
fail:
	syslog(LOG_ERR, "realloc failed, ignoring fd %d\n", fd);
	return -1;
}

static void initialize_fds(int *ptimeout)
{
	struct connection *conn;
	uint64_t msecs;

	if (poll_fds)
		memset(poll_fds, 0, sizeof(struct pollfd) * current_array_size);
	nr_fds = 0;

	/* In case of delayed requests pause for max 1 second. */
	*ptimeout = delayed_requests ? 1000 : -1;

	set_special_fds();

	if (xce_handle != NULL)
		xce_pollfd_idx = set_fd(xenevtchn_fd(xce_handle),
					POLLIN|POLLPRI);

	msecs = get_now_msec();
	wrl_log_periodic(msecs);

	list_for_each_entry(conn, &connections, list) {
		if (conn->domain) {
			wrl_check_timeout(conn->domain, msecs, ptimeout);
			check_event_timeout(conn, msecs, ptimeout);
			if (conn_can_read(conn) ||
			    (conn_can_write(conn) &&
			     !list_empty(&conn->out_list)))
				*ptimeout = 0;
		} else {
			short events = POLLIN|POLLPRI;
			if (!list_empty(&conn->out_list))
				events |= POLLOUT;
			conn->pollfd_idx = set_fd(conn->fd, events);
			/*
			 * For stalled connection, we want to process the
			 * pending command as soon as live-update has aborted.
			 */
			if (conn->is_stalled && !lu_is_pending())
				*ptimeout = 0;
		}
	}
}

static size_t calc_node_acc_size(const struct node_hdr *hdr)
{
	return sizeof(*hdr) + hdr->num_perms * sizeof(struct xs_permissions) +
	       hdr->datalen + hdr->childlen;
}

const struct node_hdr *db_fetch(const char *db_name, size_t *size)
{
	const struct node_hdr *hdr;

	hdr = hashtable_search(nodes, db_name);
	if (!hdr) {
		errno = ENOENT;
		return NULL;
	}

	*size = calc_node_acc_size(hdr);

	trace_tdb("read %s size %zu\n", db_name, *size + strlen(db_name));

	return hdr;
}

static const struct xs_permissions *perms_from_node_hdr(
	const struct node_hdr *hdr)
{
	return (const struct xs_permissions *)(hdr + 1);
}

static void get_acc_data(const char *name, struct node_account_data *acc)
{
	size_t size;
	const struct node_hdr *hdr;

	if (acc->memory < 0) {
		hdr = db_fetch(name, &size);
		/* No check for error, as the node might not exist. */
		if (hdr == NULL) {
			acc->memory = 0;
		} else {
			acc->memory = size;
			acc->domid = perms_from_node_hdr(hdr)->id;
		}
	}
}

/*
 * Per-transaction nodes need to be accounted for the transaction owner.
 * Those nodes are stored in the data base with the transaction generation
 * count prepended (e.g. 123/local/domain/...). So testing for the node's
 * key not to start with "/" or "@" is sufficient.
 */
static unsigned int get_acc_domid(struct connection *conn, const char *name,
				  unsigned int domid)
{
	return (!conn || name[0] == '/' || name[0] == '@') ? domid : conn->id;
}

int db_write(struct connection *conn, const char *db_name, void *data,
	     size_t size, struct node_account_data *acc,
	     enum write_node_mode mode, bool no_quota_check)
{
	const struct node_hdr *hdr = data;
	struct node_account_data old_acc = {};
	unsigned int old_domid, new_domid;
	size_t name_len = strlen(db_name);
	const char *name;
	int ret;

	if (!acc)
		old_acc.memory = -1;
	else
		old_acc = *acc;

	get_acc_data(db_name, &old_acc);
	old_domid = get_acc_domid(conn, db_name, old_acc.domid);
	new_domid = get_acc_domid(conn, db_name, perms_from_node_hdr(hdr)->id);

	/*
	 * Don't check for ENOENT, as we want to be able to switch orphaned
	 * nodes to new owners.
	 */
	if (old_acc.memory)
		domain_memory_add_nochk(conn, old_domid,
					-old_acc.memory - name_len);
	ret = domain_memory_add(conn, new_domid, size + name_len,
				no_quota_check);
	if (ret) {
		/* Error path, so no quota check. */
		if (old_acc.memory)
			domain_memory_add_nochk(conn, old_domid,
						old_acc.memory + name_len);
		return ret;
	}

	if (mode == NODE_CREATE) {
		/* db_name could be modified later, so allocate a copy. */
		name = talloc_strdup(data, db_name);
		ret = name ? hashtable_add(nodes, name, data) : ENOMEM;
	} else
		ret = hashtable_replace(nodes, db_name, data);

	if (ret) {
		/* Free data, as it isn't owned by hashtable now. */
		talloc_free(data);
		domain_memory_add_nochk(conn, new_domid, -size - name_len);
		/* Error path, so no quota check. */
		if (old_acc.memory)
			domain_memory_add_nochk(conn, old_domid,
						old_acc.memory + name_len);
		errno = ret;
		return errno;
	}
	trace_tdb("store %s size %zu\n", db_name, size + name_len);

	if (acc) {
		/* Don't use new_domid, as it might be a transaction node. */
		acc->domid = perms_from_node_hdr(hdr)->id;
		acc->memory = size;
	}

	return 0;
}

void db_delete(struct connection *conn, const char *name,
	       struct node_account_data *acc)
{
	struct node_account_data tmp_acc;
	unsigned int domid;

	if (!acc) {
		acc = &tmp_acc;
		acc->memory = -1;
	}

	get_acc_data(name, acc);

	hashtable_remove(nodes, name);
	trace_tdb("delete %s\n", name);

	if (acc->memory) {
		domid = get_acc_domid(conn, name, acc->domid);
		domain_memory_add_nochk(conn, domid,
					-acc->memory - strlen(name));
	}
}

/*
 * If it fails, returns NULL and sets errno.
 * Temporary memory allocations will be done with ctx.
 */
static struct node *read_node_alloc(struct connection *conn, const void *ctx,
				    const char *name,
				    const struct node_hdr **hdr)
{
	size_t size;
	struct node *node;
	const char *db_name;
	int err;

	node = talloc(ctx, struct node);
	if (!node) {
		errno = ENOMEM;
		return NULL;
	}

	node->name = talloc_strdup(node, name);
	if (!node->name) {
		errno = ENOMEM;
		goto error;
	}

	db_name = transaction_prepend(conn, name);
	*hdr = db_fetch(db_name, &size);
	if (*hdr == NULL) {
		node->hdr.generation = NO_GENERATION;
		err = access_node(conn, node, NODE_ACCESS_READ, NULL);
		errno = err ? : ENOENT;
		goto error;
	}

	node->parent = NULL;

	/* Datalen, childlen, number of permissions */
	node->hdr = **hdr;
	node->acc.domid = perms_from_node_hdr(*hdr)->id;
	node->acc.memory = size;

	return node;

 error:
	talloc_free(node);
	return NULL;
}

static bool read_node_helper(struct connection *conn, struct node *node)
{
	/* Data is binary blob (usually ascii, no nul). */
	node->data = node->perms + node->hdr.num_perms;
	/* Children is strings, nul separated. */
	node->children = node->data + node->hdr.datalen;

	if (domain_adjust_node_perms(node))
		return false;

	/* If owner is gone reset currently accounted memory size. */
	if (node->acc.domid != get_node_owner(node))
		node->acc.memory = 0;

	if (access_node(conn, node, NODE_ACCESS_READ, NULL))
		return false;

	return true;
}

struct node *read_node(struct connection *conn, const void *ctx,
		       const char *name)
{
	size_t size;
	const struct node_hdr *hdr;
	struct node *node;

	node = read_node_alloc(conn, ctx, name, &hdr);
	if (!node)
		return NULL;

	/* Copy node data to new memory area, starting with permissions. */
	size = node->acc.memory - sizeof(*hdr);
	node->perms = talloc_memdup(node, perms_from_node_hdr(hdr), size);
	if (node->perms == NULL) {
		errno = ENOMEM;
		goto error;
	}

	if (!read_node_helper(conn, node))
		goto error;

	return node;

 error:
	talloc_free(node);
	return NULL;
}

const struct node *read_node_const(struct connection *conn, const void *ctx,
				   const char *name)
{
	const struct node_hdr *hdr;
	struct node *node;

	node = read_node_alloc(conn, ctx, name, &hdr);
	if (!node)
		return NULL;

	/* Unfortunately node->perms isn't const. */
	node->perms = (void *)perms_from_node_hdr(hdr);

	if (!read_node_helper(conn, node))
		goto error;

	return node;

 error:
	talloc_free(node);
	return NULL;
}

static bool read_node_can_propagate_errno(void)
{
	/*
	 * 2 error cases for read_node() can always be propagated up:
	 * ENOMEM, because this has nothing to do with the node being in the
	 * data base or not, but is caused by a general lack of memory.
	 * ENOSPC, because this is related to hitting quota limits which need
	 * to be respected.
	 */
	return errno == ENOMEM || errno == ENOSPC;
}

int write_node_raw(struct connection *conn, const char *db_name,
		   struct node *node, enum write_node_mode mode,
		   bool no_quota_check)
{
	void *data;
	size_t size;
	void *p;
	struct node_hdr *hdr;

	if (domain_adjust_node_perms(node))
		return errno;

	size = calc_node_acc_size(&node->hdr);

	/* Call domain_max_chk() in any case in order to record max values. */
	if (domain_max_chk(conn, ACC_NODESZ, size) && !no_quota_check) {
		errno = ENOSPC;
		return errno;
	}

	data = talloc_size(node, size);
	if (!data) {
		errno = ENOMEM;
		return errno;
	}

	BUILD_BUG_ON(XENSTORE_PAYLOAD_MAX >= (typeof(hdr->datalen))(-1));

	hdr = data;
	*hdr = node->hdr;

	/* Open code perms_from_node_hdr() for the non-const case. */
	p = hdr + 1;
	memcpy(p, node->perms, node->hdr.num_perms * sizeof(*node->perms));
	p += node->hdr.num_perms * sizeof(*node->perms);
	memcpy(p, node->data, node->hdr.datalen);
	p += node->hdr.datalen;
	memcpy(p, node->children, node->hdr.childlen);

	if (db_write(conn, db_name, data, size, &node->acc, mode,
		     no_quota_check))
		return EIO;

	return 0;
}

/*
 * Write the node. If the node is written, caller can find the DB name used in
 * node->db_name. This can later be used if the change needs to be reverted.
 */
static int write_node(struct connection *conn, struct node *node,
		      enum write_node_mode mode, bool no_quota_check)
{
	int ret;

	if (access_node(conn, node, NODE_ACCESS_WRITE, &node->db_name))
		return errno;

	ret = write_node_raw(conn, node->db_name, node, mode, no_quota_check);
	if (ret && conn && conn->transaction) {
		/*
		 * Reverting access_node() is hard, so just fail the
		 * transaction.
		 */
		fail_transaction(conn->transaction);
	}

	return ret;
}

unsigned int perm_for_conn(struct connection *conn,
			   const struct node_perms *perms)
{
	unsigned int i;
	unsigned int mask = XS_PERM_READ|XS_PERM_WRITE|XS_PERM_OWNER;

	/* Owners and tools get it all... */
	if (!domain_is_unprivileged(conn) || perms->p[0].id == conn->id
                || (conn->target && perms->p[0].id == conn->target->id))
		return (XS_PERM_READ|XS_PERM_WRITE|XS_PERM_OWNER) & mask;

	for (i = 1; i < perms->num; i++)
		if (!(perms->p[i].perms & XS_PERM_IGNORE) &&
		    (perms->p[i].id == conn->id ||
		     (conn->target && perms->p[i].id == conn->target->id)))
			return perms->p[i].perms & mask;

	return perms->p[0].perms & mask;
}

/*
 * Get name of node parent.
 * Temporary memory allocations are done with ctx.
 */
char *get_parent(const void *ctx, const char *node)
{
	char *parent;
	char *slash = strrchr(node + 1, '/');

	parent = slash ? talloc_asprintf(ctx, "%.*s", (int)(slash - node), node)
		       : talloc_strdup(ctx, "/");
	if (!parent)
		errno = ENOMEM;

	return parent;
}

/*
 * What do parents say?
 * Temporary memory allocations are done with ctx.
 */
static int ask_parents(struct connection *conn, const void *ctx,
		       const char *name, unsigned int *perm)
{
	const struct node *node;

	do {
		name = get_parent(ctx, name);
		if (!name)
			return errno;
		node = read_node_const(conn, ctx, name);
		if (node)
			break;
		if (read_node_can_propagate_errno())
			return errno;
	} while (!streq(name, "/"));

	/* No permission at root?  We're in trouble. */
	if (!node) {
		corrupt(conn, "No permissions file at root");
		*perm = XS_PERM_NONE;
		return 0;
	}

	*perm = perm_for_conn_from_node(conn, node);

	return 0;
}

/*
 * We have a weird permissions system.  You can allow someone into a
 * specific node without allowing it in the parents.  If it's going to
 * fail, however, we don't want the errno to indicate any information
 * about the node.
 * Temporary memory allocations are done with ctx.
 */
static int errno_from_parents(struct connection *conn, const void *ctx,
			      const char *node, int errnum, unsigned int perm)
{
	unsigned int parent_perm = XS_PERM_NONE;

	/* We always tell them about memory failures. */
	if (errnum == ENOMEM)
		return errnum;

	if (ask_parents(conn, ctx, node, &parent_perm))
		return errno;
	if (parent_perm & perm)
		return errnum;
	return EACCES;
}

/*
 * If it fails, returns NULL and sets errno.
 * Temporary memory allocations are done with ctx.
 */
static bool get_node_chk_perm(struct connection *conn, const void *ctx,
			      const struct node *node, const char *name,
			      unsigned int perm)
{
	bool success = node;

	/* If we don't have permission, we don't have node. */
	if (node && (perm_for_conn_from_node(conn, node) & perm) != perm) {
		errno = EACCES;
		success = false;
	}
	/* Clean up errno if they weren't supposed to know. */
	if (!success && !read_node_can_propagate_errno())
		errno = errno_from_parents(conn, ctx, name, errno, perm);

	return success;
}

static struct buffered_data *new_buffer(void *ctx)
{
	struct buffered_data *data;

	data = talloc_zero(ctx, struct buffered_data);
	if (data == NULL)
		return NULL;
	
	data->inhdr = true;
	return data;
}

/* Return length of string (including nul) at this offset.
 * If there is no nul, returns 0 for failure.
 */
unsigned int get_string(const struct buffered_data *data, unsigned int offset)
{
	const char *nul;

	if (offset >= data->used)
		return 0;

	nul = memchr(data->buffer + offset, 0, data->used - offset);
	if (!nul)
		return 0;

	return nul - (data->buffer + offset) + 1;
}

/* Break input into vectors, return the number, fill in up to num of them.
 * Always returns the actual number of nuls in the input.  Stores the
 * positions of the starts of the nul-terminated strings in vec.
 * Callers who use this and then rely only on vec[] will
 * ignore any data after the final nul.
 */
unsigned int get_strings(struct buffered_data *data,
			 const char *vec[], unsigned int num)
{
	unsigned int off, i, len;

	off = i = 0;
	while ((len = get_string(data, off)) != 0) {
		if (i < num)
			vec[i] = data->buffer + off;
		i++;
		off += len;
	}
	return i;
}

static void send_error(struct connection *conn, int error)
{
	unsigned int i;

	for (i = 0; error != xsd_errors[i].errnum; i++) {
		if (i == ARRAY_SIZE(xsd_errors) - 1) {
			eprintf("xenstored: error %i untranslatable", error);
			i = 0; /* EINVAL */
			break;
		}
	}

	acc_drop(conn);

	send_reply(conn, XS_ERROR, xsd_errors[i].errstring,
			  strlen(xsd_errors[i].errstring) + 1);
}

void send_reply(struct connection *conn, enum xsd_sockmsg_type type,
		const void *data, unsigned int len)
{
	struct buffered_data *bdata = conn->in;

	assert(type != XS_WATCH_EVENT);

	/* Commit accounting now, as later errors won't undo any changes. */
	acc_commit(conn);

	if ( len > XENSTORE_PAYLOAD_MAX ) {
		send_error(conn, E2BIG);
		return;
	}

	if (!bdata)
		return;
	bdata->inhdr = true;
	bdata->used = 0;
	bdata->timeout_msec = 0;
	bdata->watch_event = false;

	if (len <= DEFAULT_BUFFER_SIZE) {
		bdata->buffer = bdata->default_buffer;
		/* Don't check quota, path might be used for returning error. */
		domain_memory_add_nochk(conn, conn->id,
					len + sizeof(bdata->hdr));
	} else {
		bdata->buffer = talloc_array(bdata, char, len);
		if (!bdata->buffer ||
		    domain_memory_add_chk(conn, conn->id,
					  len + sizeof(bdata->hdr))) {
			send_error(conn, ENOMEM);
			return;
		}
	}

	conn->in = NULL;

	/* Update relevant header fields and fill in the message body. */
	bdata->hdr.msg.type = type;
	bdata->hdr.msg.len = len;
	memcpy(bdata->buffer, data, len);

	/* Queue for later transmission. */
	list_add_tail(&bdata->list, &conn->out_list);
	bdata->on_out_list = true;
	domain_outstanding_inc(conn);
}

/*
 * Send a watch event.
 * As this is not directly related to the current command, errors can't be
 * reported.
 */
void send_event(struct buffered_data *req, struct connection *conn,
		const char *path, const char *token)
{
	struct buffered_data *bdata, *bd;
	unsigned int len;

	len = strlen(path) + 1 + strlen(token) + 1;
	/* Don't try to send over-long events. */
	if (len > XENSTORE_PAYLOAD_MAX)
		return;

	bdata = new_buffer(conn);
	if (!bdata)
		return;

	bdata->buffer = talloc_array(bdata, char, len);
	if (!bdata->buffer) {
		talloc_free(bdata);
		return;
	}
	strcpy(bdata->buffer, path);
	strcpy(bdata->buffer + strlen(path) + 1, token);
	bdata->hdr.msg.type = XS_WATCH_EVENT;
	bdata->hdr.msg.len = len;

	/*
	 * Check whether an identical event is pending already.
	 * Special events are excluded from that check.
	 */
	if (path[0] != '@') {
		list_for_each_entry(bd, &conn->out_list, list) {
			if (bd->watch_event && bd->hdr.msg.len == len &&
			    !memcmp(bdata->buffer, bd->buffer, len)) {
				trace("dropping duplicate watch %s %s for domain %u\n",
				      path, token, conn->id);
				talloc_free(bdata);
				return;
			}
		}
	}

	if (domain_memory_add_chk(conn, conn->id, len + sizeof(bdata->hdr))) {
		talloc_free(bdata);
		return;
	}

	if (timeout_watch_event_msec && domain_is_unprivileged(conn)) {
		bdata->timeout_msec = get_now_msec() + timeout_watch_event_msec;
		if (!conn->timeout_msec)
			conn->timeout_msec = bdata->timeout_msec;
	}

	bdata->watch_event = true;
	bdata->pend.req = req;
	if (req)
		req->pend.ref.event_cnt++;

	/* Queue for later transmission. */
	list_add_tail(&bdata->list, &conn->out_list);
	bdata->on_out_list = true;
}

/* Some routines (write, mkdir, etc) just need a non-error return */
void send_ack(struct connection *conn, enum xsd_sockmsg_type type)
{
	send_reply(conn, type, "OK", sizeof("OK"));
}

static bool valid_chars(const char *node)
{
	/* Nodes can have lots of crap. */
	return (strspn(node, 
		       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		       "abcdefghijklmnopqrstuvwxyz"
		       "0123456789-/_@") == strlen(node));
}

/* We expect one arg in the input: return NULL otherwise.
 * The payload must contain exactly one nul, at the end.
 */
const char *onearg(struct buffered_data *in)
{
	if (!in->used || get_string(in, 0) != in->used)
		return NULL;
	return in->buffer;
}

static char *node_perms_to_strings(const struct node *node, unsigned int *len)
{
	unsigned int i;
	char *strings = NULL;
	char buffer[MAX_STRLEN(unsigned int) + 1];

	for (*len = 0, i = 0; i < node->hdr.num_perms; i++) {
		if (!xenstore_perm_to_string(&node->perms[i], buffer,
					     sizeof(buffer)))
			return NULL;

		strings = talloc_realloc(node, strings, char,
					 *len + strlen(buffer) + 1);
		if (!strings)
			return NULL;
		strcpy(strings + *len, buffer);
		*len += strlen(buffer) + 1;
	}
	return strings;
}

const char *canonicalize(struct connection *conn, const void *ctx,
			 const char *node, bool allow_special)
{
	const char *name;
	int local_off = 0;
	unsigned int domid;

	/*
	 * Invalid if any of:
	 * - no node at all
	 * - illegal character in node
	 * - starts with '@' but no special node allowed
	 */
	errno = EINVAL;
	if (!node ||
	    !valid_chars(node) ||
	    (node[0] == '@' && !allow_special))
		return NULL;

	if (node[0] != '/' && node[0] != '@') {
		name = talloc_asprintf(ctx, "%s/%s", get_implicit_path(conn),
				       node);
		if (!name)
			return NULL;
	} else
		name = node;

	if (sscanf(name, "/local/domain/%5u/%n", &domid, &local_off) != 1)
		local_off = 0;

	/*
	 * Only valid if:
	 * - doesn't end in / (unless it's just "/")
	 * - no double //
	 * - not violating max allowed path length
	 */
	if (!(strends(name, "/") && !streq(name, "/")) &&
	    !strstr(name, "//") &&
	    !domain_max_chk(conn, ACC_PATHLEN, strlen(name) - local_off))
		return name;

	/* Release the memory if 'name' was allocated by us. */
	if (name != node)
		talloc_free(name);

	return NULL;
}

static struct node *get_node(struct connection *conn, const void *ctx,
			     const char *name, const char **canonical_name,
			     unsigned int perm, bool allow_special)
{
	struct node *node;

	*canonical_name = canonicalize(conn, ctx, name, allow_special);
	if (!*canonical_name)
		return NULL;

	node = read_node(conn, ctx, *canonical_name);

	return get_node_chk_perm(conn, ctx, node, *canonical_name, perm)
	       ? node : NULL;
}

static const struct node *get_node_const(struct connection *conn,
					 const void *ctx, const char *name,
					 unsigned int perm, bool allow_special)
{
	const char *tmp_name;
	const struct node *node;

	tmp_name = canonicalize(conn, ctx, name, allow_special);
	if (!tmp_name)
		return NULL;

	node = read_node_const(conn, ctx, tmp_name);

	return get_node_chk_perm(conn, ctx, node, tmp_name, perm) ? node : NULL;
}

static int send_directory(const void *ctx, struct connection *conn,
			  struct buffered_data *in)
{
	const struct node *node;

	node = get_node_const(conn, ctx, onearg(in), XS_PERM_READ, false);
	if (!node)
		return errno;

	send_reply(conn, XS_DIRECTORY, node->children, node->hdr.childlen);

	return 0;
}

static int send_directory_part(const void *ctx, struct connection *conn,
			       struct buffered_data *in)
{
	unsigned int off, len, maxlen, genlen;
	char *child, *data;
	const struct node *node;
	char gen[24];

	if (xenstore_count_strings(in->buffer, in->used) != 2)
		return EINVAL;

	/* First arg is node name. */
	node = get_node_const(conn, ctx, in->buffer, XS_PERM_READ, false);
	if (!node)
		return errno;

	/* Second arg is childlist offset. */
	off = atoi(in->buffer + strlen(in->buffer) + 1);

	genlen = snprintf(gen, sizeof(gen), "%"PRIu64, node->hdr.generation) +
		 1;

	/* Offset behind list: just return a list with an empty string. */
	if (off >= node->hdr.childlen) {
		gen[genlen] = 0;
		send_reply(conn, XS_DIRECTORY_PART, gen, genlen + 1);
		return 0;
	}

	len = 0;
	maxlen = XENSTORE_PAYLOAD_MAX - genlen - 1;
	child = node->children + off;

	while (len + strlen(child) < maxlen) {
		len += strlen(child) + 1;
		child += strlen(child) + 1;
		if (off + len == node->hdr.childlen)
			break;
	}

	data = talloc_array(ctx, char, genlen + len + 1);
	if (!data)
		return ENOMEM;

	memcpy(data, gen, genlen);
	memcpy(data + genlen, node->children + off, len);
	if (off + len == node->hdr.childlen) {
		data[genlen + len] = 0;
		len++;
	}

	send_reply(conn, XS_DIRECTORY_PART, data, genlen + len);

	return 0;
}

static int do_read(const void *ctx, struct connection *conn,
		   struct buffered_data *in)
{
	const struct node *node;

	node = get_node_const(conn, ctx, onearg(in), XS_PERM_READ, false);
	if (!node)
		return errno;

	send_reply(conn, XS_READ, node->data, node->hdr.datalen);

	return 0;
}

/* Must not be / */
static char *basename(const char *name)
{
	return strrchr(name, '/') + 1;
}

static int add_child(const void *ctx, struct node *parent, const char *name)
{
	const char *base;
	unsigned int baselen;
	char *children;

	base = basename(name);
	baselen = strlen(base) + 1;
	children = talloc_array(ctx, char, parent->hdr.childlen + baselen);
	if (!children)
		return ENOMEM;
	memcpy(children, parent->children, parent->hdr.childlen);
	memcpy(children + parent->hdr.childlen, base, baselen);
	parent->children = children;
	parent->hdr.childlen += baselen;

	return 0;
}

static struct node *construct_node(struct connection *conn, const void *ctx,
				   const char *name)
{
	const char **names = NULL;
	unsigned int levels = 0;
	struct node *node = NULL;
	struct node *parent = NULL;
	const char *parentname = talloc_strdup(ctx, name);

	if (!parentname)
		return NULL;

	/* Walk the path up until an existing node is found. */
	while (!parent) {
		names = talloc_realloc(ctx, names, const char *, levels + 1);
		if (!names)
			goto nomem;

		/*
		 * names[0] is the name of the node to construct initially,
		 * names[1] is its parent, and so on.
		 */
		names[levels] = parentname;
		parentname = get_parent(ctx, parentname);
		if (!parentname)
			return NULL;

		/* Try to read parent node until we found an existing one. */
		parent = read_node(conn, ctx, parentname);
		if (!parent && (errno != ENOENT || !strcmp(parentname, "/")))
			return NULL;

		levels++;
	}

	/* Walk the path down again constructing the missing nodes. */
	for (; levels > 0; levels--) {
		/* Add child to parent. */
		if (add_child(ctx, parent, names[levels - 1]))
			goto nomem;

		/* Allocate node */
		node = talloc(ctx, struct node);
		if (!node)
			goto nomem;
		node->name = talloc_steal(node, names[levels - 1]);

		/* Inherit permissions, unpriv domains own what they create. */
		node->hdr.num_perms = parent->hdr.num_perms;
		node->perms = talloc_memdup(node, parent->perms,
					    node->hdr.num_perms *
					    sizeof(*node->perms));
		if (!node->perms)
			goto nomem;
		if (domain_is_unprivileged(conn))
			node->perms[0].id = conn->id;

		/* No children, no data */
		node->children = node->data = NULL;
		node->hdr.childlen = node->hdr.datalen = 0;
		node->acc.memory = 0;
		node->parent = parent;

		parent = node;
	}

	return node;

nomem:
	errno = ENOMEM;
	return NULL;
}

static void destroy_node_rm(struct connection *conn, struct node *node)
{
	if (streq(node->name, "/"))
		corrupt(NULL, "Destroying root node!");

	db_delete(conn, node->db_name, &node->acc);
}

static int destroy_node(struct connection *conn, struct node *node)
{
	destroy_node_rm(conn, node);

	/*
	 * It is not possible to easily revert the changes in a transaction.
	 * So if the failure happens in a transaction, mark it as fail to
	 * prevent any commit.
	 */
	if ( conn->transaction )
		fail_transaction(conn->transaction);

	return 0;
}

static struct node *create_node(struct connection *conn, const void *ctx,
				const char *name,
				void *data, unsigned int datalen)
{
	struct node *node, *i, *j;
	int ret;

	node = construct_node(conn, ctx, name);
	if (!node)
		return NULL;

	if (conn && conn->transaction)
		ta_node_created(conn->transaction);

	node->data = data;
	node->hdr.datalen = datalen;

	/*
	 * We write out the nodes bottom up.
	 * All new created nodes will have i->parent set, while the final
	 * node will be already existing and won't have i->parent set.
	 * New nodes are subject to quota handling.
	 */
	for (i = node; i; i = i->parent) {
		/* i->parent is set for each new node, so check quota. */
		if (i->parent &&
		    domain_nbentry(conn) >= hard_quotas[ACC_NODES].val) {
			ret = ENOSPC;
			goto err;
		}

		ret = write_node(conn, i, i->parent ? NODE_CREATE : NODE_MODIFY,
				 false);
		if (ret)
			goto err;

		/* Account for new node */
		if (i->parent) {
			if (domain_nbentry_inc(conn, get_node_owner(i))) {
				destroy_node_rm(conn, i);
				return NULL;
			}
		}
	}

	return node;

err:
	/*
	 * We failed to update TDB for some of the nodes. Undo any work that
	 * have already been done.
	 */
	for (j = node; j != i; j = j->parent)
		destroy_node(conn, j);

	/* We don't need to keep the nodes around, so free them. */
	i = node;
	while (i) {
		j = i;
		i = i->parent;
		talloc_free(j);
	}

	errno = ret;

	return NULL;
}

/* path, data... */
static int do_write(const void *ctx, struct connection *conn,
		    struct buffered_data *in)
{
	unsigned int offset, datalen;
	struct node *node;
	const char *vec[1] = { NULL }; /* gcc4 + -W + -Werror fucks code. */
	const char *name;

	/* Extra "strings" can be created by binary data. */
	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec))
		return EINVAL;

	offset = strlen(vec[0]) + 1;
	datalen = in->used - offset;

	node = get_node(conn, ctx, vec[0], &name, XS_PERM_WRITE, false);
	if (!node) {
		/* No permissions, invalid input? */
		if (errno != ENOENT)
			return errno;
		node = create_node(conn, ctx, name, in->buffer + offset,
				   datalen);
		if (!node)
			return errno;
	} else {
		node->data = in->buffer + offset;
		node->hdr.datalen = datalen;
		if (write_node(conn, node, NODE_MODIFY, false))
			return errno;
	}

	fire_watches(conn, ctx, name, node, false, NULL);
	send_ack(conn, XS_WRITE);

	return 0;
}

static int do_mkdir(const void *ctx, struct connection *conn,
		    struct buffered_data *in)
{
	struct node *node;
	const char *name;

	node = get_node(conn, ctx, onearg(in), &name, XS_PERM_WRITE, false);

	/* If it already exists, fine. */
	if (!node) {
		/* No permissions? */
		if (errno != ENOENT)
			return errno;
		if (!name)
			return ENOMEM;
		node = create_node(conn, ctx, name, NULL, 0);
		if (!node)
			return errno;
		fire_watches(conn, ctx, name, node, false, NULL);
	}
	send_ack(conn, XS_MKDIR);

	return 0;
}

/* Delete memory using memmove. */
static void memdel(void *mem, unsigned off, unsigned len, unsigned total)
{
	memmove(mem + off, mem + off + len, total - off - len);
}

static int remove_child_entry(struct connection *conn, struct node *node,
			      size_t offset)
{
	size_t childlen = strlen(node->children + offset);

	memdel(node->children, offset, childlen + 1, node->hdr.childlen);
	node->hdr.childlen -= childlen + 1;

	return write_node(conn, node, NODE_MODIFY, true);
}

static int delete_child(struct connection *conn,
			struct node *node, const char *childname)
{
	unsigned int i;

	for (i = 0; i < node->hdr.childlen;
	     i += strlen(node->children + i) + 1) {
		if (streq(node->children + i, childname)) {
			errno = remove_child_entry(conn, node, i) ? EIO : 0;
			return errno;
		}
	}
	corrupt(conn, "Can't find child '%s' in %s", childname, node->name);

	errno = EIO;
	return errno;
}

static int delnode_sub(const void *ctx, struct connection *conn,
		       struct node *node, void *arg)
{
	const char *root = arg;
	bool watch_exact;
	int ret;
	const char *db_name;

	/* Any error here will probably be repeated for all following calls. */
	ret = access_node(conn, node, NODE_ACCESS_DELETE, &db_name);
	if (ret > 0)
		return WALK_TREE_SUCCESS_STOP;

	if (domain_nbentry_dec(conn, get_node_owner(node)))
		return WALK_TREE_ERROR_STOP;

	if (!ret)
		db_delete(conn, db_name, &node->acc);

	/*
	 * Fire the watches now, when we can still see the node permissions.
	 * This fine as we are single threaded and the next possible read will
	 * be handled only after the node has been really removed.
	*/
	watch_exact = strcmp(root, node->name);
	fire_watches(conn, ctx, node->name, node, watch_exact, NULL);

	return WALK_TREE_RM_CHILDENTRY;
}

int rm_node(struct connection *conn, const void *ctx, const char *name)
{
	struct node *parent;
	char *parentname = get_parent(ctx, name);
	struct walk_funcs walkfuncs = { .exit = delnode_sub };
	int ret;

	if (!parentname)
		return errno;

	parent = read_node(conn, ctx, parentname);
	if (!parent)
		return read_node_can_propagate_errno() ? errno : EINVAL;

	ret = walk_node_tree(ctx, conn, name, &walkfuncs, (void *)name);
	if (ret < 0) {
		if (ret == WALK_TREE_ERROR_STOP) {
			/*
			 * This can't be triggered by an unprivileged guest,
			 * so calling corrupt() is fine here.
			 * In fact it is needed in order to fix a potential
			 * accounting inconsistency.
			 */
			corrupt(conn, "error when deleting sub-nodes of %s\n",
				name);
			errno = EIO;
		}
		return errno;
	}

	if (delete_child(conn, parent, basename(name)))
		return errno;

	return 0;
}


static int do_rm(const void *ctx, struct connection *conn,
		 struct buffered_data *in)
{
	struct node *node;
	int ret;
	const char *name;
	char *parentname;

	node = get_node(conn, ctx, onearg(in), &name, XS_PERM_WRITE, false);
	if (!node) {
		/* Didn't exist already?  Fine, if parent exists. */
		if (errno == ENOENT) {
			if (!name)
				return ENOMEM;
			parentname = get_parent(ctx, name);
			if (!parentname)
				return errno;
			node = read_node(conn, ctx, parentname);
			if (node) {
				send_ack(conn, XS_RM);
				return 0;
			}
			/* Restore errno, just in case. */
			if (!read_node_can_propagate_errno())
				errno = ENOENT;
		}
		return errno;
	}

	if (streq(name, "/"))
		return EINVAL;

	ret = rm_node(conn, ctx, name);
	if (ret)
		return ret;

	send_ack(conn, XS_RM);

	return 0;
}


static int do_get_perms(const void *ctx, struct connection *conn,
			struct buffered_data *in)
{
	const struct node *node;
	char *strings;
	unsigned int len;

	node = get_node_const(conn, ctx, onearg(in), XS_PERM_READ, true);
	if (!node)
		return errno;

	strings = node_perms_to_strings(node, &len);
	if (!strings)
		return errno;

	send_reply(conn, XS_GET_PERMS, strings, len);

	return 0;
}

static int do_set_perms(const void *ctx, struct connection *conn,
			struct buffered_data *in)
{
	struct node_perms perms, old_perms;
	const char *name;
	char *permstr;
	struct node *node;

	perms.num = xenstore_count_strings(in->buffer, in->used);
	if (perms.num < 2)
		return EINVAL;

	perms.num--;
	if (domain_max_chk(conn, ACC_NPERM, perms.num))
		return ENOSPC;

	permstr = in->buffer + strlen(in->buffer) + 1;

	perms.p = talloc_array(ctx, struct xs_permissions, perms.num);
	if (!perms.p)
		return ENOMEM;
	if (!xenstore_strings_to_perms(perms.p, perms.num, permstr))
		return errno;

	if (domain_alloc_permrefs(&perms))
		return ENOMEM;
	if (perms.p[0].perms & XS_PERM_IGNORE)
		return ENOENT;

	/* We must own node to do this (tools can do this too). */
	node = get_node(conn, ctx, in->buffer, &name,
			XS_PERM_WRITE | XS_PERM_OWNER, true);
	if (!node)
		return errno;

	/* Unprivileged domains may not change the owner. */
	if (domain_is_unprivileged(conn) &&
	    perms.p[0].id != get_node_owner(node))
		return EPERM;

	node_to_node_perms(node, &old_perms);
	if (domain_nbentry_dec(conn, get_node_owner(node)))
		return ENOMEM;
	node_perms_to_node(&perms, node);
	if (domain_nbentry_inc(conn, get_node_owner(node)))
		return ENOMEM;

	if (write_node(conn, node, NODE_MODIFY, false))
		return errno;

	fire_watches(conn, ctx, name, node, false, &old_perms);
	send_ack(conn, XS_SET_PERMS);

	return 0;
}

static char *child_name(const void *ctx, const char *s1, const char *s2)
{
	if (strcmp(s1, "/"))
		return talloc_asprintf(ctx, "%s/%s", s1, s2);
	return talloc_asprintf(ctx, "/%s", s2);
}

static int rm_from_parent(struct connection *conn, struct node *parent,
			  const char *name)
{
	size_t off;

	if (!parent)
		return WALK_TREE_ERROR_STOP;

	for (off = parent->childoff - 1; off && parent->children[off - 1];
	     off--);
	if (remove_child_entry(conn, parent, off)) {
		log("treewalk: child entry could not be removed from '%s'",
		    parent->name);
		return WALK_TREE_ERROR_STOP;
	}
	parent->childoff = off;

	return WALK_TREE_OK;
}

static int walk_call_func(const void *ctx, struct connection *conn,
			  struct node *node, struct node *parent, void *arg,
			  int (*func)(const void *ctx, struct connection *conn,
				      struct node *node, void *arg))
{
	int ret;

	if (!func)
		return WALK_TREE_OK;

	ret = func(ctx, conn, node, arg);
	if (ret == WALK_TREE_RM_CHILDENTRY && parent)
		ret = rm_from_parent(conn, parent, node->name);

	return ret;
}

int walk_node_tree(const void *ctx, struct connection *conn, const char *root,
		   struct walk_funcs *funcs, void *arg)
{
	int ret = 0;
	void *tmpctx;
	char *name;
	struct node *node = NULL;
	struct node *parent = NULL;

	tmpctx = talloc_new(ctx);
	if (!tmpctx) {
		errno = ENOMEM;
		return WALK_TREE_ERROR_STOP;
	}
	name = talloc_strdup(tmpctx, root);
	if (!name) {
		errno = ENOMEM;
		talloc_free(tmpctx);
		return WALK_TREE_ERROR_STOP;
	}

	/* Continue the walk until an error is returned. */
	while (ret >= 0) {
		/* node == NULL possible only for the initial loop iteration. */
		if (node) {
			/* Go one step up if ret or if last child finished. */
			if (ret || node->childoff >= node->hdr.childlen) {
				parent = node->parent;
				/* Call function AFTER processing a node. */
				ret = walk_call_func(ctx, conn, node, parent,
						     arg, funcs->exit);
				/* Last node, so exit loop. */
				if (!parent)
					break;
				talloc_free(node);
				/* Continue with parent. */
				node = parent;
				continue;
			}
			/* Get next child of current node. */
			name = child_name(tmpctx, node->name,
					  node->children + node->childoff);
			if (!name) {
				ret = WALK_TREE_ERROR_STOP;
				break;
			}
			/* Point to next child. */
			node->childoff += strlen(node->children +
						 node->childoff) + 1;
			/* Descent into children. */
			parent = node;
		}
		/* Read next node (root node or next child). */
		node = read_node(conn, tmpctx, name);
		if (!node) {
			/* Child not found - should not happen! */
			/* ENOENT case can be handled by supplied function. */
			if (errno == ENOENT && funcs->enoent)
				ret = funcs->enoent(ctx, conn, parent, name,
						    arg);
			else
				ret = WALK_TREE_ERROR_STOP;
			if (!parent)
				break;
			if (ret == WALK_TREE_RM_CHILDENTRY)
				ret = rm_from_parent(conn, parent, name);
			if (ret < 0)
				break;
			talloc_free(name);
			node = parent;
			continue;
		}
		talloc_free(name);
		node->parent = parent;
		node->childoff = 0;
		/* Call function BEFORE processing a node. */
		ret = walk_call_func(ctx, conn, node, parent, arg,
				     funcs->enter);
	}

	talloc_free(tmpctx);

	return ret < 0 ? ret : WALK_TREE_OK;
}

static struct {
	const char *str;
	int (*func)(const void *ctx, struct connection *conn,
		    struct buffered_data *in);
	unsigned int flags;
#define XS_FLAG_NOTID		(1U << 0)	/* Ignore transaction id. */
#define XS_FLAG_PRIV		(1U << 1)	/* Privileged domain only. */
} const wire_funcs[XS_TYPE_COUNT] = {
	[XS_CONTROL]           =
	    { "CONTROL",       do_control,      XS_FLAG_PRIV },
	[XS_DIRECTORY]         = { "DIRECTORY",         send_directory },
	[XS_READ]              = { "READ",              do_read },
	[XS_GET_PERMS]         = { "GET_PERMS",         do_get_perms },
	[XS_WATCH]             =
	    { "WATCH",         do_watch,        XS_FLAG_NOTID },
	[XS_UNWATCH]           =
	    { "UNWATCH",       do_unwatch,      XS_FLAG_NOTID },
	[XS_TRANSACTION_START] = { "TRANSACTION_START", do_transaction_start },
	[XS_TRANSACTION_END]   = { "TRANSACTION_END",   do_transaction_end },
	[XS_INTRODUCE]         =
	    { "INTRODUCE",     do_introduce,    XS_FLAG_PRIV },
	[XS_RELEASE]           =
	    { "RELEASE",       do_release,      XS_FLAG_PRIV },
	[XS_GET_DOMAIN_PATH]   = { "GET_DOMAIN_PATH",   do_get_domain_path },
	[XS_WRITE]             = { "WRITE",             do_write },
	[XS_MKDIR]             = { "MKDIR",             do_mkdir },
	[XS_RM]                = { "RM",                do_rm },
	[XS_SET_PERMS]         = { "SET_PERMS",         do_set_perms },
	[XS_WATCH_EVENT]       = { "WATCH_EVENT",       NULL },
	[XS_ERROR]             = { "ERROR",             NULL },
	[XS_IS_DOMAIN_INTRODUCED] =
	    { "IS_DOMAIN_INTRODUCED", do_is_domain_introduced, XS_FLAG_PRIV },
	[XS_RESUME]            =
	    { "RESUME",        do_resume,       XS_FLAG_PRIV },
	[XS_SET_TARGET]        =
	    { "SET_TARGET",    do_set_target,   XS_FLAG_PRIV },
	[XS_RESET_WATCHES]     = { "RESET_WATCHES",     do_reset_watches },
	[XS_DIRECTORY_PART]    = { "DIRECTORY_PART",    send_directory_part },
};

static const char *sockmsg_string(enum xsd_sockmsg_type type)
{
	if ((unsigned int)type < ARRAY_SIZE(wire_funcs) && wire_funcs[type].str)
		return wire_funcs[type].str;

	return "**UNKNOWN**";
}

/* Process "in" for conn: "in" will vanish after this conversation, so
 * we can talloc off it for temporary variables.  May free "conn".
 */
static void process_message(struct connection *conn, struct buffered_data *in)
{
	struct transaction *trans;
	enum xsd_sockmsg_type type = in->hdr.msg.type;
	int ret;
	void *ctx;

	/* At least send_error() and send_reply() expects conn->in == in */
	assert(conn->in == in);
	trace_io(conn, in, "IN");

	if ((unsigned int)type >= XS_TYPE_COUNT || !wire_funcs[type].func) {
		eprintf("Client unknown operation %i", type);
		send_error(conn, ENOSYS);
		return;
	}

	if ((wire_funcs[type].flags & XS_FLAG_PRIV) &&
	    domain_is_unprivileged(conn)) {
		send_error(conn, EACCES);
		return;
	}

	trans = (wire_funcs[type].flags & XS_FLAG_NOTID)
		? NULL : transaction_lookup(conn, in->hdr.msg.tx_id);
	if (IS_ERR(trans)) {
		send_error(conn, -PTR_ERR(trans));
		return;
	}

	ctx = talloc_new(NULL);
	if (!ctx) {
		send_error(conn, ENOMEM);
		return;
	}

	assert(conn->transaction == NULL);
	conn->transaction = trans;

	ret = wire_funcs[type].func(ctx, conn, in);
	talloc_free(ctx);
	if (ret)
		send_error(conn, ret);

	conn->transaction = NULL;
}

static bool process_delayed_message(struct delayed_request *req)
{
	struct connection *conn = req->data;
	struct buffered_data *saved_in = conn->in;

	if (lu_is_pending())
		return false;

	/*
	 * Part of process_message() expects conn->in to contains the
	 * processed response. So save the current conn->in and restore it
	 * afterwards.
	 */
	conn->in = req->in;
	process_message(req->data, req->in);
	conn->in = saved_in;

	return true;
}

static void consider_message(struct connection *conn)
{
	conn->is_stalled = false;
	/*
	 * Currently, Live-Update is not supported if there is active
	 * transactions. In order to reduce the number of retry, delay
	 * any new request to start a transaction if Live-Update is pending
	 * and there are no transactions in-flight.
	 *
	 * If we can't delay the request, then mark the connection as
	 * stalled. This will ignore new requests until Live-Update happened
	 * or it was aborted.
	 */
	if (lu_is_pending() && list_empty(&conn->transaction_list) &&
	    conn->in->hdr.msg.type == XS_TRANSACTION_START) {
		trace("Delaying transaction start for connection %p req_id %u\n",
		      conn, conn->in->hdr.msg.req_id);

		if (delay_request(conn, conn->in, process_delayed_message,
				  conn, false) != 0) {
			trace("Stalling connection %p\n", conn);
			conn->is_stalled = true;
		}
		return;
	}

	process_message(conn, conn->in);

	assert(conn->in == NULL);
}

/*
 * Errors in reading or allocating here means we get out of sync, so we mark
 * the connection as ignored.
 */
static void handle_input(struct connection *conn)
{
	int bytes;
	struct buffered_data *in;
	unsigned int err;

	if (!conn->in) {
		conn->in = new_buffer(conn);
		/* In case of no memory just try it again next time. */
		if (!conn->in)
			return;
	}
	in = conn->in;
	in->pend.ref.domid = conn->id;

	/* Not finished header yet? */
	if (in->inhdr) {
		if (in->used != sizeof(in->hdr)) {
			bytes = conn->funcs->read(conn, in->hdr.raw + in->used,
						  sizeof(in->hdr) - in->used);
			if (bytes < 0) {
				err = XENSTORE_ERROR_RINGIDX;
				goto bad_client;
			}
			in->used += bytes;
			if (in->used != sizeof(in->hdr))
				return;

			/*
			 * The payload size is not only currently restricted by
			 * the protocol but also the internal implementation
			 * (see various BUILD_BUG_ON()).
			 * Any potential change of the maximum payload size
			 * needs to be negotiated between the involved parties.
			 */
			if (in->hdr.msg.len > XENSTORE_PAYLOAD_MAX) {
				syslog(LOG_ERR, "Client tried to feed us %i",
				       in->hdr.msg.len);
				err = XENSTORE_ERROR_PROTO;
				goto bad_client;
			}
		}

		if (in->hdr.msg.len <= DEFAULT_BUFFER_SIZE)
			in->buffer = in->default_buffer;
		else
			in->buffer = talloc_array(in, char, in->hdr.msg.len);
		/* In case of no memory just try it again next time. */
		if (!in->buffer)
			return;
		in->used = 0;
		in->inhdr = false;
	}

	bytes = conn->funcs->read(conn, in->buffer + in->used,
				  in->hdr.msg.len - in->used);
	if (bytes < 0) {
		err = XENSTORE_ERROR_RINGIDX;
		goto bad_client;
	}

	in->used += bytes;
	if (in->used != in->hdr.msg.len)
		return;

	consider_message(conn);
	return;

bad_client:
	ignore_connection(conn, err);
}

static void handle_output(struct connection *conn)
{
	/* Ignore the connection if an error occured */
	if (!write_messages(conn))
		ignore_connection(conn, XENSTORE_ERROR_RINGIDX);
}

struct connection *new_connection(const struct interface_funcs *funcs)
{
	struct connection *new;

	new = talloc_zero(talloc_autofree_context(), struct connection);
	if (!new)
		return NULL;

	new->fd = -1;
	new->pollfd_idx = -1;
	new->funcs = funcs;
	new->is_ignored = false;
	new->is_stalled = false;
	INIT_LIST_HEAD(&new->out_list);
	INIT_LIST_HEAD(&new->acc_list);
	INIT_LIST_HEAD(&new->ref_list);
	INIT_LIST_HEAD(&new->watches);
	INIT_LIST_HEAD(&new->transaction_list);
	INIT_LIST_HEAD(&new->delayed);

	list_add_tail(&new->list, &connections);
	talloc_set_destructor(new, destroy_conn);
	trace_create(new, "connection");
	return new;
}

struct connection *get_connection_by_id(unsigned int conn_id)
{
	struct connection *conn;

	list_for_each_entry(conn, &connections, list)
		if (conn->conn_id == conn_id)
			return conn;

	return NULL;
}

/* We create initial nodes manually. */
static void manual_node(const char *name, const char *child)
{
	struct node *node;
	struct xs_permissions perms = { .id = dom0_domid,
					.perms = XS_PERM_NONE };

	node = talloc_zero(NULL, struct node);
	if (!node)
		barf_perror("Could not allocate initial node %s", name);

	node->name = name;
	node->perms = &perms;
	node->hdr.num_perms = 1;
	node->children = (char *)child;
	if (child)
		node->hdr.childlen = strlen(child) + 1;

	if (write_node(NULL, node, NODE_CREATE, false))
		barf_perror("Could not create initial node %s", name);
	talloc_free(node);
}

static unsigned int hash_from_key_fn(const void *k)
{
	const char *str = k;
	unsigned int hash = 5381;
	char c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + (unsigned int)c;

	return hash;
}

static int keys_equal_fn(const void *key1, const void *key2)
{
	return 0 == strcmp(key1, key2);
}

void setup_structure(bool live_update)
{
	nodes = create_hashtable(NULL, "nodes", hash_from_key_fn, keys_equal_fn,
				 HASHTABLE_FREE_KEY | HASHTABLE_FREE_VALUE);
	if (!nodes)
		barf_perror("Could not create nodes hashtable");

	if (live_update)
		manual_node("/", NULL);
	else {
		manual_node("/", "tool");
		manual_node("/tool", "xenstored");
		manual_node("/tool/xenstored", NULL);
		manual_node("@releaseDomain", NULL);
		manual_node("@introduceDomain", NULL);
		domain_nbentry_fix(dom0_domid, 5, true);
	}
}

int remember_string(struct hashtable *hash, const char *str)
{
	char *k = talloc_strdup(NULL, str);

	if (!k)
		return ENOMEM;
	return hashtable_add(hash, k, (void *)1);
}

/**
 * A node has a children field that names the children of the node, separated
 * by NULs.  We check whether there are entries in there that are duplicated
 * (and if so, delete the second one), and whether there are any that do not
 * have a corresponding child node (and if so, delete them).  Each valid child
 * is then recursively checked.
 *
 * As we go, we record each node in the given reachable hashtable.  These
 * entries will be used later in clean_store.
 */

struct check_store_data {
	struct hashtable *reachable;
	struct hashtable *domains;
};

static int check_store_step(const void *ctx, struct connection *conn,
			    struct node *node, void *arg)
{
	struct check_store_data *data = arg;

	if (hashtable_search(data->reachable, (void *)node->name)) {
		log("check_store: '%s' is duplicated!", node->name);
		return WALK_TREE_RM_CHILDENTRY;
	}

	if (remember_string(data->reachable, node->name))
		return WALK_TREE_ERROR_STOP;

	domain_check_acc_add(node, data->domains);

	return WALK_TREE_OK;
}

static int check_store_enoent(const void *ctx, struct connection *conn,
			      struct node *parent, char *name, void *arg)
{
	log("check_store: node '%s' not found", name);

	return WALK_TREE_RM_CHILDENTRY;
}


/**
 * Helper to clean_store below.
 */
static int clean_store_(const void *key, void *val, void *private)
{
	struct hashtable *reachable = private;
	char *slash;
	char *name = talloc_strdup(NULL, key);

	if (!name) {
		log("clean_store: ENOMEM");
		return 1;
	}

	if (name[0] != '/') {
		slash = strchr(name, '/');
		if (slash)
			*slash = 0;
	}
	if (!hashtable_search(reachable, name)) {
		log("clean_store: '%s' is orphaned!", name);
		db_delete(NULL, name, NULL);
	}

	talloc_free(name);

	return 0;
}


/**
 * Given the list of reachable nodes, iterate over the whole store, and
 * remove any that were not reached.
 */
static void clean_store(struct check_store_data *data)
{
	hashtable_iterate(nodes, clean_store_, data->reachable);
	domain_check_acc(data->domains);
}

int check_store_path(const void *ctx, const char *name, struct check_store_data *data)
{
	struct node *node;

	node = read_node(NULL, ctx, name);
	if (!node) {
		log("check_store: error %d reading special node '%s'", errno,
		    name);
		return errno;
	}

	return check_store_step(ctx, NULL, node, data);
}

void check_store(void)
{
	struct walk_funcs walkfuncs = {
		.enter = check_store_step,
		.enoent = check_store_enoent,
	};
	struct check_store_data data;
	void *ctx;

	/* Don't free values (they are all void *1) */
	data.reachable = create_hashtable(NULL, "checkstore", hash_from_key_fn,
					  keys_equal_fn, HASHTABLE_FREE_KEY);
	if (!data.reachable) {
		log("check_store: ENOMEM");
		return;
	}

	data.domains = domain_check_acc_init();
	if (!data.domains) {
		log("check_store: ENOMEM");
		goto out_hash;
	}

	ctx = talloc_new(NULL);
	log("Checking store ...");
	if (walk_node_tree(ctx, NULL, "/", &walkfuncs, &data)) {
		if (errno == ENOMEM)
			log("check_store: ENOMEM");
	} else if (!check_store_path(ctx, "@introduceDomain", &data) &&
		   !check_store_path(ctx, "@releaseDomain", &data) &&
		   !check_transactions(data.reachable))
		clean_store(&data);
	log("Checking store complete.");

	hashtable_destroy(data.domains);
	talloc_free(ctx);
 out_hash:
	hashtable_destroy(data.reachable);
}


/* Something is horribly wrong: check the store. */
void corrupt(struct connection *conn, const char *fmt, ...)
{
	va_list arglist;
	char *str;
	int saved_errno = errno;

	va_start(arglist, fmt);
	str = talloc_vasprintf(NULL, fmt, arglist);
	va_end(arglist);

	log("corruption detected by connection %i: err %s: %s",
	    conn ? (int)conn->id : -1, strerror(saved_errno),
	    str ?: "ENOMEM");

	talloc_free(str);

	check_store();

	errno = saved_errno;
}

static void usage(void)
{
	fprintf(stderr,
"Usage:\n"
"\n"
"  xenstored <options>\n"
"\n"
"where options may include:\n"
"\n"
"  -F, --pid-file <file>   giving a file for the daemon's pid to be written,\n"
"  -H, --help              to output this message,\n"
"  -N, --no-fork           to request that the daemon does not fork,\n"
"  -T, --trace-file <file> giving the file for logging, and\n"
"      --trace-control=+<switch> activate a specific <switch>\n"
"      --trace-control=-<switch> deactivate a specific <switch>\n"
"  -E, --entry-nb <nb>     limit the number of entries per domain,\n"
"  -S, --entry-size <size> limit the size of entry per domain, and\n"
"  -W, --watch-nb <nb>     limit the number of watches per domain,\n"
"  -t, --transaction <nb>  limit the number of transaction allowed per domain,\n"
"  -A, --perm-nb <nb>      limit the number of permissions per node,\n"
"  -M, --path-max <chars>  limit the allowed Xenstore node path length,\n"
"  -Q, --quota <what>=<nb> set the quota <what> to the value <nb>, allowed\n"
"                          quotas are:\n"
"                          transaction-nodes: number of accessed node per\n"
"                                             transaction\n"
"                          memory: total used memory per domain for nodes,\n"
"                                  transactions, watches and requests, above\n"
"                                  which Xenstore will stop talking to domain\n"
"                          nodes: number nodes owned by a domain\n"
"                          node-permissions: number of access permissions per\n"
"                                            node\n"
"                          node-size: total size of a node (permissions +\n"
"                                     children names + content)\n"
"                          outstanding: number of outstanding requests\n"
"                          path-length: length of a node path\n"
"                          transactions: number of concurrent transactions\n"
"                                        per domain\n"
"                          watches: number of watches per domain"
"  -q, --quota-soft <what>=<nb> set a soft quota <what> to the value <nb>,\n"
"                          causing a warning to be issued via syslog() if the\n"
"                          limit is violated, allowed quotas are:\n"
"                          memory: see above\n"
"  -w, --timeout <what>=<seconds>   set the timeout in seconds for <what>,\n"
"                          allowed timeout candidates are:\n"
"                          watch-event: time a watch-event is kept pending\n"
"  -K, --keep-orphans      don't delete nodes owned by a domain when the\n"
"                          domain is deleted (this is a security risk!)\n");
}


static struct option options[] = {
	{ "entry-nb", 1, NULL, 'E' },
	{ "pid-file", 1, NULL, 'F' },
	{ "event", 1, NULL, 'e' },
	{ "master-domid", 1, NULL, 'm' },
	{ "help", 0, NULL, 'H' },
	{ "no-fork", 0, NULL, 'N' },
	{ "priv-domid", 1, NULL, 'p' },
	{ "entry-size", 1, NULL, 'S' },
	{ "trace-file", 1, NULL, 'T' },
	{ "trace-control", 1, NULL, 1 },
	{ "transaction", 1, NULL, 't' },
	{ "perm-nb", 1, NULL, 'A' },
	{ "path-max", 1, NULL, 'M' },
	{ "quota", 1, NULL, 'Q' },
	{ "quota-soft", 1, NULL, 'q' },
	{ "timeout", 1, NULL, 'w' },
	{ "keep-orphans", 0, NULL, 'K' },
	{ "watch-nb", 1, NULL, 'W' },
#ifndef NO_LIVE_UPDATE
	{ "live-update", 0, NULL, 'U' },
#endif
	{ NULL, 0, NULL, 0 } };

int dom0_domid = 0;
int dom0_event = 0;
int priv_domid = 0;
domid_t stub_domid = DOMID_INVALID;

static unsigned int get_optval_uint(const char *arg)
{
	char *end;
	unsigned long val;

	val = strtoul(arg, &end, 10);
	if (!*arg || *end || val > INT_MAX)
		barf("invalid parameter value \"%s\"\n", arg);

	return val;
}

static bool what_matches(const char *arg, const char *what)
{
	unsigned int what_len;

	if (!what)
		return false;

	what_len = strlen(what);

	return !strncmp(arg, what, what_len) && arg[what_len] == '=';
}

static void set_timeout(const char *arg)
{
	const char *eq = strchr(arg, '=');
	unsigned int val;

	if (!eq)
		barf("quotas must be specified via <what>=<seconds>\n");
	val = get_optval_uint(eq + 1);
	if (what_matches(arg, "watch-event"))
		timeout_watch_event_msec = val * 1000;
	else
		barf("unknown timeout \"%s\"\n", arg);
}

static void set_quota(const char *arg, bool soft)
{
	const char *eq = strchr(arg, '=');
	struct quota *q = soft ? soft_quotas : hard_quotas;
	unsigned int val;
	unsigned int i;

	if (!eq)
		barf("quotas must be specified via <what>=<nb>\n");
	val = get_optval_uint(eq + 1);

	for (i = 0; i < ACC_N; i++) {
		if (what_matches(arg, q[i].name)) {
			q[i].val = val;
			return;
		}
	}

	barf("unknown quota \"%s\"\n", arg);
}

/* Sorted by bit values of TRACE_* flags. Flag is (1u << index). */
const char *const trace_switches[] = {
	"obj", "io", "wrl", "acc", "tdb",
	NULL
};

int set_trace_switch(const char *arg)
{
	bool remove = (arg[0] == '-');
	unsigned int idx;

	switch (arg[0]) {
	case '-':
		remove = true;
		break;
	case '+':
		remove = false;
		break;
	default:
		return EINVAL;
	}

	arg++;

	for (idx = 0; trace_switches[idx]; idx++) {
		if (!strcmp(arg, trace_switches[idx])) {
			if (remove)
				trace_flags &= ~(1u << idx);
			else
				trace_flags |= 1u << idx;
			return 0;
		}
	}

	return EINVAL;
}

int main(int argc, char *argv[])
{
	int opt;
	bool dofork = true;
	bool live_update = false;
	const char *pidfile = NULL;
	int timeout;

	orig_argc = argc;
	orig_argv = argv;

	while ((opt = getopt_long(argc, argv,
				  "E:F:H::KNS:t:A:M:Q:q:T:W:w:U",
				  options, NULL)) != -1) {
		switch (opt) {
		case 'E':
			hard_quotas[ACC_NODES].val = get_optval_uint(optarg);
			break;
		case 'F':
			pidfile = optarg;
			break;
		case 'H':
			usage();
			return 0;
		case 'N':
			dofork = false;
			break;
		case 'S':
			hard_quotas[ACC_NODESZ].val = get_optval_uint(optarg);
			break;
		case 't':
			hard_quotas[ACC_TRANS].val = get_optval_uint(optarg);
			break;
		case 'T':
			tracefile = optarg;
			break;
		case 1:
			if (set_trace_switch(optarg))
				barf("Illegal trace switch \"%s\"\n", optarg);
			break;
		case 'K':
			keep_orphans = true;
			break;
		case 'W':
			hard_quotas[ACC_WATCH].val = get_optval_uint(optarg);
			break;
		case 'A':
			hard_quotas[ACC_NPERM].val = get_optval_uint(optarg);
			break;
		case 'M':
			hard_quotas[ACC_PATHLEN].val = get_optval_uint(optarg);
			hard_quotas[ACC_PATHLEN].val =
				 min((unsigned int)XENSTORE_REL_PATH_MAX,
				     hard_quotas[ACC_PATHLEN].val);
			break;
		case 'Q':
			set_quota(optarg, false);
			break;
		case 'q':
			set_quota(optarg, true);
			break;
		case 'w':
			set_timeout(optarg);
			break;
		case 'e':
			dom0_event = get_optval_uint(optarg);
			break;
		case 'm':
			dom0_domid = get_optval_uint(optarg);
			break;
		case 'p':
			priv_domid = get_optval_uint(optarg);
			break;
#ifndef NO_LIVE_UPDATE
		case 'U':
			live_update = true;
			break;
#endif
		}
	}
	if (optind != argc)
		barf("%s: No arguments desired", argv[0]);

	early_init(live_update, dofork, pidfile);

	talloc_enable_null_tracking();

	domain_early_init();

	/* Listen to hypervisor. */
	if (!live_update) {
		domain_init(-1);
		dom0_init();
	}

	/* redirect to /dev/null now we're ready to accept connections */
	if (dofork && !live_update)
		finish_daemonize();
#ifndef __MINIOS__
	if (dofork)
		xprintf = trace;
#endif

	if (tracefile)
		tracefile = absolute_filename(NULL, tracefile);

#ifndef NO_LIVE_UPDATE
	/* Read state in case of live update. */
	if (live_update)
		lu_read_state();
#endif

	stubdom_init();

	check_store();

	/* Get ready to listen to the tools. */
	initialize_fds(&timeout);

	late_init(live_update);

	/* Main loop. */
	for (;;) {
		struct connection *conn, *next;

		if (poll(poll_fds, nr_fds, timeout) < 0) {
			if (errno == EINTR)
				continue;
			barf_perror("Poll failed");
		}

		handle_special_fds();

		if (xce_pollfd_idx != -1) {
			if (poll_fds[xce_pollfd_idx].revents & ~POLLIN) {
				barf_perror("xce_handle poll failed");
				break;
			} else if (poll_fds[xce_pollfd_idx].revents & POLLIN) {
				handle_event();
				xce_pollfd_idx = -1;
			}
		}

		/*
		 * list_for_each_entry_safe is not suitable here because
		 * handle_input may delete entries besides the current one, but
		 * those may be in the temporary next which would trigger a
		 * use-after-free.  list_for_each_entry_safe is only safe for
		 * deleting the current entry.
		 */
		next = list_entry(connections.next, typeof(*conn), list);
		if (&next->list != &connections)
			talloc_increase_ref_count(next);
		while (&next->list != &connections) {
			conn = next;

			next = list_entry(conn->list.next,
					  typeof(*conn), list);
			if (&next->list != &connections)
				talloc_increase_ref_count(next);

			if (conn_can_read(conn))
				handle_input(conn);
			if (talloc_free(conn) == 0)
				continue;

			talloc_increase_ref_count(conn);

			if (conn_can_write(conn))
				handle_output(conn);
			if (talloc_free(conn) == 0)
				continue;

			conn->pollfd_idx = -1;
		}

		if (delayed_requests) {
			list_for_each_entry(conn, &connections, list) {
				struct delayed_request *req, *tmp;

				list_for_each_entry_safe(req, tmp,
							 &conn->delayed, list)
					call_delayed(req);
			}
		}

		initialize_fds(&timeout);
	}
}

const char *dump_state_global(FILE *fp)
{
	struct xs_state_record_header head;
	struct xs_state_global glb;

	head.type = XS_STATE_TYPE_GLOBAL;
	head.length = sizeof(glb);
	if (fwrite(&head, sizeof(head), 1, fp) != 1)
		return "Dump global state error";
	glb.socket_fd = get_socket_fd();
	glb.evtchn_fd = xenevtchn_fd(xce_handle);
	if (fwrite(&glb, sizeof(glb), 1, fp) != 1)
		return "Dump global state error";

	return NULL;
}

static const char *dump_input_buffered_data(FILE *fp,
					    const struct buffered_data *in,
					    unsigned int *total_len)
{
	unsigned int hlen = in->inhdr ? in->used : sizeof(in->hdr);

	*total_len += hlen;
	if (fp && fwrite(&in->hdr, hlen, 1, fp) != 1)
		return "Dump read data error";
	if (!in->inhdr && in->used) {
		*total_len += in->used;
		if (fp && fwrite(in->buffer, in->used, 1, fp) != 1)
			return "Dump read data error";
	}

	return NULL;
}

/* Called twice: first with fp == NULL to get length, then for writing data. */
const char *dump_state_buffered_data(FILE *fp, const struct connection *c,
				     struct xs_state_connection *sc)
{
	unsigned int len = 0, used;
	struct buffered_data *out;
	bool partial = true;
	struct delayed_request *req;
	const char *ret;

	/* Dump any command that was delayed */
	list_for_each_entry(req, &c->delayed, list) {
		/*
		 * We only want to preserve commands that weren't processed at
		 * all. All the other delayed requests (such as do_lu_start())
		 * must be processed before Live-Update.
		 */
		if (req->func != process_delayed_message)
			continue;

		assert(!req->in->inhdr);
		if ((ret = dump_input_buffered_data(fp, req->in, &len)))
			return ret;
	}

	if (c->in && (ret = dump_input_buffered_data(fp, c->in, &len)))
		return ret;

	if (sc) {
		sc->data_in_len = len;
		sc->data_resp_len = 0;
	}

	len = 0;

	list_for_each_entry(out, &c->out_list, list) {
		used = out->used;
		if (out->inhdr) {
			if (!used)
				partial = false;
			if (fp && fwrite(out->hdr.raw + out->used,
				  sizeof(out->hdr) - out->used, 1, fp) != 1)
				return "Dump buffered data error";
			len += sizeof(out->hdr) - out->used;
			used = 0;
		}
		if (fp && out->hdr.msg.len &&
		    fwrite(out->buffer + used, out->hdr.msg.len - used,
			   1, fp) != 1)
			return "Dump buffered data error";
		len += out->hdr.msg.len - used;
		if (partial && sc)
			sc->data_resp_len = len;
		partial = false;
	}

	/* Add "OK" for live-update command. */
	if (c == lu_get_connection()) {
		unsigned int rc = lu_write_response(fp);

		if (!rc)
			return "Dump buffered data error";

		len += rc;
	}

	if (sc)
		sc->data_out_len = len;

	return NULL;
}

const char *dump_state_node_perms(FILE *fp, const struct xs_permissions *perms,
				  unsigned int n_perms)
{
	unsigned int p;

	for (p = 0; p < n_perms; p++) {
		struct xs_state_node_perm sp;

		switch ((int)perms[p].perms & ~XS_PERM_IGNORE) {
		case XS_PERM_READ:
			sp.access = XS_STATE_NODE_PERM_READ;
			break;
		case XS_PERM_WRITE:
			sp.access = XS_STATE_NODE_PERM_WRITE;
			break;
		case XS_PERM_READ | XS_PERM_WRITE:
			sp.access = XS_STATE_NODE_PERM_BOTH;
			break;
		default:
			sp.access = XS_STATE_NODE_PERM_NONE;
			break;
		}
		sp.flags = (perms[p].perms & XS_PERM_IGNORE)
				     ? XS_STATE_NODE_PERM_IGNORE : 0;
		sp.domid = perms[p].id;

		if (fwrite(&sp, sizeof(sp), 1, fp) != 1)
			return "Dump node permission error";

	}

	return NULL;
}

struct dump_node_data {
	FILE *fp;
	const char *err;
};

static int dump_state_node_err(struct dump_node_data *data, const char *err)
{
	data->err = err;
	return WALK_TREE_ERROR_STOP;
}

static int dump_state_node(const void *ctx, struct connection *conn,
			   const struct node *node, struct dump_node_data *data)
{
	FILE *fp = data->fp;
	unsigned int pathlen;
	struct xs_state_record_header head;
	struct xs_state_node sn;
	const char *ret;

	pathlen = strlen(node->name) + 1;

	head.type = XS_STATE_TYPE_NODE;
	head.length = sizeof(sn);
	sn.conn_id = 0;
	sn.ta_id = 0;
	sn.ta_access = 0;
	sn.perm_n = node->hdr.num_perms;
	sn.path_len = pathlen;
	sn.data_len = node->hdr.datalen;
	head.length += node->hdr.num_perms * sizeof(*sn.perms);
	head.length += pathlen;
	head.length += node->hdr.datalen;
	head.length = ROUNDUP(head.length, 3);

	if (fwrite(&head, sizeof(head), 1, fp) != 1)
		return dump_state_node_err(data, "Dump node head error");
	if (fwrite(&sn, sizeof(sn), 1, fp) != 1)
		return dump_state_node_err(data, "Dump node state error");

	ret = dump_state_node_perms(fp, node->perms, node->hdr.num_perms);
	if (ret)
		return dump_state_node_err(data, ret);

	if (fwrite(node->name, pathlen, 1, fp) != 1)
		return dump_state_node_err(data, "Dump node path error");

	if (node->hdr.datalen &&
	    fwrite(node->data, node->hdr.datalen, 1, fp) != 1)
		return dump_state_node_err(data, "Dump node data error");

	ret = dump_state_align(fp);
	if (ret)
		return dump_state_node_err(data, ret);

	return WALK_TREE_OK;
}

static int dump_state_node_enter(const void *ctx, struct connection *conn,
				 struct node *node, void *arg)
{
	return dump_state_node(ctx, conn, node, arg);
}

static int dump_state_special_node(FILE *fp, const void *ctx,
				   struct dump_node_data *data,
				   const char *name)
{
	const struct node *node;
	int ret;

	node = read_node_const(NULL, ctx, name);
	if (!node)
		return dump_state_node_err(data, "Dump node read node error");

	ret = dump_state_node(ctx, NULL, node, data);
	talloc_free(node);

	return ret;
}

const char *dump_state_nodes(FILE *fp, const void *ctx)
{
	struct dump_node_data data = {
		.fp = fp,
		.err = "Dump node walk error"
	};
	struct walk_funcs walkfuncs = { .enter = dump_state_node_enter };

	if (walk_node_tree(ctx, NULL, "/", &walkfuncs, &data))
		return data.err;

	if (dump_state_special_node(fp, ctx, &data, "@releaseDomain"))
		return data.err;
	if (dump_state_special_node(fp, ctx, &data, "@introduceDomain"))
		return data.err;

	return NULL;
}

void read_state_global(const void *ctx, const void *state)
{
	const struct xs_state_global *glb = state;

	set_socket_fd(glb->socket_fd);

	domain_init(glb->evtchn_fd);
}

static void add_buffered_data(struct buffered_data *bdata,
			      struct connection *conn, const uint8_t *data,
			      unsigned int len)
{
	bdata->hdr.msg.len = len;
	if (len <= DEFAULT_BUFFER_SIZE)
		bdata->buffer = bdata->default_buffer;
	else
		bdata->buffer = talloc_array(bdata, char, len);
	if (!bdata->buffer)
		barf("error restoring buffered data");

	memcpy(bdata->buffer, data, len);
	if (bdata->hdr.msg.type == XS_WATCH_EVENT && timeout_watch_event_msec &&
	    domain_is_unprivileged(conn)) {
		bdata->timeout_msec = get_now_msec() + timeout_watch_event_msec;
		if (!conn->timeout_msec)
			conn->timeout_msec = bdata->timeout_msec;
	}

	/* Queue for later transmission. */
	list_add_tail(&bdata->list, &conn->out_list);
	bdata->on_out_list = true;
	/*
	 * Watch events are never "outstanding", but the request causing them
	 * are instead kept "outstanding" until all watch events caused by that
	 * request have been delivered.
	 */
	if (bdata->hdr.msg.type != XS_WATCH_EVENT)
		domain_outstanding_inc(conn);
	/*
	 * We are restoring the state after Live-Update and the new quota may
	 * be smaller. So ignore it. The limit will be applied for any resource
	 * after the state has been fully restored.
	 */
	domain_memory_add_nochk(conn, conn->id, len + sizeof(bdata->hdr));
}

void read_state_buffered_data(const void *ctx, struct connection *conn,
			      const struct xs_state_connection *sc)
{
	struct buffered_data *bdata;
	const uint8_t *data;
	unsigned int len;
	bool partial = sc->data_resp_len;

	for (data = sc->data; data < sc->data + sc->data_in_len; data += len) {
		bdata = new_buffer(conn);
		if (!bdata)
			barf("error restoring read data");

		/*
		 * We don't know yet if there is more than one message
		 * to process. So the len is the size of the leftover data.
		 */
		len = sc->data_in_len - (data - sc->data);
		if (len < sizeof(bdata->hdr)) {
			bdata->inhdr = true;
			memcpy(&bdata->hdr, data, len);
			bdata->used = len;
		} else {
			bdata->inhdr = false;
			memcpy(&bdata->hdr, data, sizeof(bdata->hdr));
			if (bdata->hdr.msg.len <= DEFAULT_BUFFER_SIZE)
				bdata->buffer = bdata->default_buffer;
			else
				bdata->buffer = talloc_array(bdata, char,
							bdata->hdr.msg.len);
			if (!bdata->buffer)
				barf("Error allocating in buffer");
			bdata->used = min_t(unsigned int,
					    len - sizeof(bdata->hdr),
					    bdata->hdr.msg.len);
			memcpy(bdata->buffer, data + sizeof(bdata->hdr),
			       bdata->used);
			/* Update len to match the size of the message. */
			len = bdata->used + sizeof(bdata->hdr);
		}

		/*
		 * If the message is not complete, then it means this was
		 * the current processed message. All the other messages
		 * will be queued to be handled after restoring.
		 */
		if (bdata->inhdr || bdata->used != bdata->hdr.msg.len) {
			assert(conn->in == NULL);
			conn->in = bdata;
		} else if (delay_request(conn, bdata, process_delayed_message,
					 conn, true))
			barf("Unable to delay the request");
	}

	for (data = sc->data + sc->data_in_len;
	     data < sc->data + sc->data_in_len + sc->data_out_len;
	     data += len) {
		bdata = new_buffer(conn);
		if (!bdata)
			barf("error restoring buffered data");
		if (partial) {
			bdata->inhdr = false;
			/* Make trace look nice. */
			bdata->hdr.msg.type = XS_INVALID;
			len = sc->data_resp_len;
			add_buffered_data(bdata, conn, data, len);
			partial = false;
			continue;
		}

		memcpy(&bdata->hdr, data, sizeof(bdata->hdr));
		data += sizeof(bdata->hdr);
		len = bdata->hdr.msg.len;
		add_buffered_data(bdata, conn, data, len);
	}
}

void read_state_node(const void *ctx, const void *state)
{
	const struct xs_state_node *sn = state;
	struct node *node, *parent;
	char *name, *parentname;
	unsigned int i;
	struct connection conn = { .id = priv_domid };

	name = (char *)(sn->perms + sn->perm_n);
	node = talloc(ctx, struct node);
	if (!node)
		barf("allocation error restoring node");

	node->acc.memory = 0;
	node->name = name;
	node->hdr.generation = ++generation;
	node->hdr.datalen = sn->data_len;
	node->data = name + sn->path_len;
	node->hdr.childlen = 0;
	node->children = NULL;
	node->hdr.num_perms = sn->perm_n;
	node->perms = talloc_array(node, struct xs_permissions,
				   node->hdr.num_perms);
	if (!node->perms)
		barf("allocation error restoring node");
	for (i = 0; i < node->hdr.num_perms; i++) {
		switch (sn->perms[i].access) {
		case 'r':
			node->perms[i].perms = XS_PERM_READ;
			break;
		case 'w':
			node->perms[i].perms = XS_PERM_WRITE;
			break;
		case 'b':
			node->perms[i].perms = XS_PERM_READ | XS_PERM_WRITE;
			break;
		default:
			node->perms[i].perms = XS_PERM_NONE;
			break;
		}
		if (sn->perms[i].flags & XS_STATE_NODE_PERM_IGNORE)
			node->perms[i].perms |= XS_PERM_IGNORE;
		node->perms[i].id = sn->perms[i].domid;
	}

	if (!strstarts(name, "@")) {
		parentname = get_parent(node, name);
		if (!parentname)
			barf("allocation error restoring node");
		parent = read_node(NULL, node, parentname);
		if (!parent)
			barf("read parent error restoring node");

		if (add_child(node, parent, name))
			barf("allocation error restoring node");

		if (write_node_raw(NULL, parentname, parent, NODE_MODIFY, true))
			barf("write parent error restoring node");
	}

	/* The "/" node is already existing, so it can only be modified here. */
	if (write_node_raw(NULL, name, node,
			   strcmp(name, "/") ? NODE_CREATE : NODE_MODIFY, true))
		barf("write node error restoring node");

	if (domain_nbentry_inc(&conn, get_node_owner(node)))
		barf("node accounting error restoring node");

	talloc_free(node);
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
