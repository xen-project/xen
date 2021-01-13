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
#ifndef NO_SOCKETS
#include <sys/socket.h>
#include <sys/un.h>
#endif
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

#include "utils.h"
#include "list.h"
#include "talloc.h"
#include "xenstore_lib.h"
#include "xenstored_core.h"
#include "xenstored_watch.h"
#include "xenstored_transaction.h"
#include "xenstored_domain.h"
#include "xenstored_control.h"
#include "tdb.h"

#ifndef NO_SOCKETS
#if defined(HAVE_SYSTEMD)
#define XEN_SYSTEMD_ENABLED 1
#endif
#endif

#if defined(XEN_SYSTEMD_ENABLED)
#include <systemd/sd-daemon.h>
#endif

extern xenevtchn_handle *xce_handle; /* in xenstored_domain.c */
static int xce_pollfd_idx = -1;
static struct pollfd *fds;
static unsigned int current_array_size;
static unsigned int nr_fds;
static unsigned int delayed_requests;

static int sock = -1;

int orig_argc;
char **orig_argv;

static bool verbose = false;
LIST_HEAD(connections);
int tracefd = -1;
static bool recovery = true;
static int reopen_log_pipe[2];
static int reopen_log_pipe0_pollfd_idx = -1;
char *tracefile = NULL;
TDB_CONTEXT *tdb_ctx = NULL;

static const char *sockmsg_string(enum xsd_sockmsg_type type);

#define log(...)							\
	do {								\
		char *s = talloc_asprintf(NULL, __VA_ARGS__);		\
		if (s) {						\
			trace("%s\n", s);				\
			syslog(LOG_ERR, "%s\n",  s);			\
			talloc_free(s);					\
		} else {						\
			trace("talloc failure during logging\n");	\
			syslog(LOG_ERR, "talloc failure during logging\n"); \
		}							\
	} while (0)


int quota_nb_entry_per_domain = 1000;
int quota_nb_watch_per_domain = 128;
int quota_max_entry_size = 2048; /* 2K */
int quota_max_transaction = 10;
int quota_nb_perms_per_node = 5;
int quota_max_path_len = XENSTORE_REL_PATH_MAX;

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
		     int out)
{
	unsigned int i;
	time_t now;
	struct tm *tm;

#ifdef HAVE_DTRACE
	dtrace_io(conn, data, out);
#endif

	if (tracefd < 0)
		return;

	now = time(NULL);
	tm = localtime(&now);

	trace("%s %p %04d%02d%02d %02d:%02d:%02d %s (",
	      out ? "OUT" : "IN", conn,
	      tm->tm_year + 1900, tm->tm_mon + 1,
	      tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,
	      sockmsg_string(data->hdr.msg.type));
	
	for (i = 0; i < data->hdr.msg.len; i++)
		trace("%c", (data->buffer[i] != '\0') ? data->buffer[i] : ' ');
	trace(")\n");
}

void trace_create(const void *data, const char *type)
{
	trace("CREATE %s %p\n", type, data);
}

void trace_destroy(const void *data, const char *type)
{
	trace("DESTROY %s %p\n", type, data);
}

/**
 * Signal handler for SIGHUP, which requests that the trace log is reopened
 * (in the main loop).  A single byte is written to reopen_log_pipe, to awaken
 * the poll() in the main loop.
 */
static void trigger_reopen_log(int signal __attribute__((unused)))
{
	char c = 'A';
	int dummy;
	dummy = write(reopen_log_pipe[1], &c, 1);
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

static bool write_messages(struct connection *conn)
{
	int ret;
	struct buffered_data *out;

	out = list_top(&conn->out_list, struct buffered_data, list);
	if (out == NULL)
		return true;

	if (out->inhdr) {
		if (verbose)
			xprintf("Writing msg %s (%.*s) out to %p\n",
				sockmsg_string(out->hdr.msg.type),
				out->hdr.msg.len,
				out->buffer, conn);
		ret = conn->write(conn, out->hdr.raw + out->used,
				  sizeof(out->hdr) - out->used);
		if (ret < 0)
			return false;

		out->used += ret;
		if (out->used < sizeof(out->hdr))
			return true;

		out->inhdr = false;
		out->used = 0;

		/* Second write might block if non-zero. */
		if (out->hdr.msg.len && !conn->domain)
			return true;
	}

	ret = conn->write(conn, out->buffer + out->used,
			  out->hdr.msg.len - out->used);
	if (ret < 0)
		return false;

	out->used += ret;
	if (out->used != out->hdr.msg.len)
		return true;

	trace_io(conn, out, 1);

	list_del(&out->list);
	talloc_free(out);

	return true;
}

static int undelay_request(void *_req)
{
	struct delayed_request *req = _req;

	list_del(&req->list);
	delayed_requests--;

	return 0;
}

static void call_delayed(struct connection *conn, struct delayed_request *req)
{
	assert(conn->in == NULL);
	conn->in = req->in;

	if (req->func(req)) {
		undelay_request(req);
		talloc_set_destructor(req, NULL);
	}

	conn->in = NULL;
}

int delay_request(struct connection *conn, struct buffered_data *in,
		  bool (*func)(struct delayed_request *), void *data)
{
	struct delayed_request *req;

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

	conn->in = NULL;

	return 0;
}

static int destroy_conn(void *_conn)
{
	struct connection *conn = _conn;

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
        if (conn->target)
                talloc_unlink(conn, conn->target);
	list_del(&conn->list);
	trace_destroy(conn, "connection");
	return 0;
}

/* This function returns index inside the array if succeed, -1 if fail */
static int set_fd(int fd, short events)
{
	int ret;
	if (current_array_size < nr_fds + 1) {
		struct pollfd *new_fds = NULL;
		unsigned long newsize;

		/* Round up to 2^8 boundary, in practice this just
		 * make newsize larger than current_array_size.
		 */
		newsize = ROUNDUP(nr_fds + 1, 8);

		new_fds = realloc(fds, sizeof(struct pollfd)*newsize);
		if (!new_fds)
			goto fail;
		fds = new_fds;

		memset(&fds[0] + current_array_size, 0,
		       sizeof(struct pollfd ) * (newsize-current_array_size));
		current_array_size = newsize;
	}

	fds[nr_fds].fd = fd;
	fds[nr_fds].events = events;
	ret = nr_fds;
	nr_fds++;

	return ret;
fail:
	syslog(LOG_ERR, "realloc failed, ignoring fd %d\n", fd);
	return -1;
}

static void initialize_fds(int *p_sock_pollfd_idx, int *ptimeout)
{
	struct connection *conn;
	struct wrl_timestampt now;

	if (fds)
		memset(fds, 0, sizeof(struct pollfd) * current_array_size);
	nr_fds = 0;

	/* In case of delayed requests pause for max 1 second. */
	*ptimeout = delayed_requests ? 1000 : -1;

	if (sock != -1)
		*p_sock_pollfd_idx = set_fd(sock, POLLIN|POLLPRI);
	if (reopen_log_pipe[0] != -1)
		reopen_log_pipe0_pollfd_idx =
			set_fd(reopen_log_pipe[0], POLLIN|POLLPRI);

	if (xce_handle != NULL)
		xce_pollfd_idx = set_fd(xenevtchn_fd(xce_handle),
					POLLIN|POLLPRI);

	wrl_gettime_now(&now);
	wrl_log_periodic(now);

	list_for_each_entry(conn, &connections, list) {
		if (conn->domain) {
			wrl_check_timeout(conn->domain, now, ptimeout);
			if (domain_can_read(conn) ||
			    (domain_can_write(conn) &&
			     !list_empty(&conn->out_list)))
				*ptimeout = 0;
		} else {
			short events = POLLIN|POLLPRI;
			if (!list_empty(&conn->out_list))
				events |= POLLOUT;
			conn->pollfd_idx = set_fd(conn->fd, events);
		}
	}
}

void set_tdb_key(const char *name, TDB_DATA *key)
{
	/*
	 * Dropping const is fine here, as the key will never be modified
	 * by TDB.
	 */
	key->dptr = (char *)name;
	key->dsize = strlen(name);
}

/*
 * If it fails, returns NULL and sets errno.
 * Temporary memory allocations will be done with ctx.
 */
struct node *read_node(struct connection *conn, const void *ctx,
		       const char *name)
{
	TDB_DATA key, data;
	struct xs_tdb_record_hdr *hdr;
	struct node *node;

	node = talloc(ctx, struct node);
	if (!node) {
		errno = ENOMEM;
		return NULL;
	}
	node->name = talloc_strdup(node, name);
	if (!node->name) {
		talloc_free(node);
		errno = ENOMEM;
		return NULL;
	}

	if (transaction_prepend(conn, name, &key))
		return NULL;

	data = tdb_fetch(tdb_ctx, key);

	if (data.dptr == NULL) {
		if (tdb_error(tdb_ctx) == TDB_ERR_NOEXIST) {
			node->generation = NO_GENERATION;
			access_node(conn, node, NODE_ACCESS_READ, NULL);
			errno = ENOENT;
		} else {
			log("TDB error on read: %s", tdb_errorstr(tdb_ctx));
			errno = EIO;
		}
		talloc_free(node);
		return NULL;
	}

	node->parent = NULL;
	talloc_steal(node, data.dptr);

	/* Datalen, childlen, number of permissions */
	hdr = (void *)data.dptr;
	node->generation = hdr->generation;
	node->perms.num = hdr->num_perms;
	node->datalen = hdr->datalen;
	node->childlen = hdr->childlen;

	/* Permissions are struct xs_permissions. */
	node->perms.p = hdr->perms;
	if (domain_adjust_node_perms(node)) {
		talloc_free(node);
		return NULL;
	}

	/* Data is binary blob (usually ascii, no nul). */
	node->data = node->perms.p + hdr->num_perms;
	/* Children is strings, nul separated. */
	node->children = node->data + node->datalen;

	access_node(conn, node, NODE_ACCESS_READ, NULL);

	return node;
}

int write_node_raw(struct connection *conn, TDB_DATA *key, struct node *node,
		   bool no_quota_check)
{
	TDB_DATA data;
	void *p;
	struct xs_tdb_record_hdr *hdr;

	if (domain_adjust_node_perms(node))
		return errno;

	data.dsize = sizeof(*hdr)
		+ node->perms.num * sizeof(node->perms.p[0])
		+ node->datalen + node->childlen;

	if (!no_quota_check && domain_is_unprivileged(conn) &&
	    data.dsize >= quota_max_entry_size) {
		errno = ENOSPC;
		return errno;
	}

	data.dptr = talloc_size(node, data.dsize);
	hdr = (void *)data.dptr;
	hdr->generation = node->generation;
	hdr->num_perms = node->perms.num;
	hdr->datalen = node->datalen;
	hdr->childlen = node->childlen;

	memcpy(hdr->perms, node->perms.p,
	       node->perms.num * sizeof(*node->perms.p));
	p = hdr->perms + node->perms.num;
	memcpy(p, node->data, node->datalen);
	p += node->datalen;
	memcpy(p, node->children, node->childlen);

	/* TDB should set errno, but doesn't even set ecode AFAICT. */
	if (tdb_store(tdb_ctx, *key, data, TDB_REPLACE) != 0) {
		corrupt(conn, "Write of %s failed", key->dptr);
		errno = EIO;
		return errno;
	}
	return 0;
}

static int write_node(struct connection *conn, struct node *node,
		      bool no_quota_check)
{
	TDB_DATA key;

	if (access_node(conn, node, NODE_ACCESS_WRITE, &key))
		return errno;

	return write_node_raw(conn, &key, node, no_quota_check);
}

enum xs_perm_type perm_for_conn(struct connection *conn,
				const struct node_perms *perms)
{
	unsigned int i;
	enum xs_perm_type mask = XS_PERM_READ|XS_PERM_WRITE|XS_PERM_OWNER;

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
		       const char *name, enum xs_perm_type *perm)
{
	struct node *node;

	do {
		name = get_parent(ctx, name);
		if (!name)
			return errno;
		node = read_node(conn, ctx, name);
		if (node)
			break;
		if (errno == ENOMEM)
			return errno;
	} while (!streq(name, "/"));

	/* No permission at root?  We're in trouble. */
	if (!node) {
		corrupt(conn, "No permissions file at root");
		*perm = XS_PERM_NONE;
		return 0;
	}

	*perm = perm_for_conn(conn, &node->perms);
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
			      const char *node, int errnum,
			      enum xs_perm_type perm)
{
	enum xs_perm_type parent_perm = XS_PERM_NONE;

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
static struct node *get_node(struct connection *conn,
			     const void *ctx,
			     const char *name,
			     enum xs_perm_type perm)
{
	struct node *node;

	if (!name || !is_valid_nodename(name)) {
		errno = EINVAL;
		return NULL;
	}
	node = read_node(conn, ctx, name);
	/* If we don't have permission, we don't have node. */
	if (node) {
		if ((perm_for_conn(conn, &node->perms) & perm) != perm) {
			errno = EACCES;
			node = NULL;
		}
	}
	/* Clean up errno if they weren't supposed to know. */
	if (!node && errno != ENOMEM)
		errno = errno_from_parents(conn, ctx, name, errno, perm);
	return node;
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
			 char *vec[], unsigned int num)
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
	send_reply(conn, XS_ERROR, xsd_errors[i].errstring,
			  strlen(xsd_errors[i].errstring) + 1);
}

void send_reply(struct connection *conn, enum xsd_sockmsg_type type,
		const void *data, unsigned int len)
{
	struct buffered_data *bdata;

	if ( len > XENSTORE_PAYLOAD_MAX ) {
		send_error(conn, E2BIG);
		return;
	}

	/* Replies reuse the request buffer, events need a new one. */
	if (type != XS_WATCH_EVENT) {
		bdata = conn->in;
		/* Drop asynchronous responses, e.g. errors for watch events. */
		if (!bdata)
			return;
		bdata->inhdr = true;
		bdata->used = 0;
		conn->in = NULL;
	} else {
		/* Message is a child of the connection for auto-cleanup. */
		bdata = new_buffer(conn);

		/*
		 * Allocation failure here is unfortunate: we have no way to
		 * tell anybody about it.
		 */
		if (!bdata)
			return;
	}
	if (len <= DEFAULT_BUFFER_SIZE)
		bdata->buffer = bdata->default_buffer;
	else
		bdata->buffer = talloc_array(bdata, char, len);
	if (!bdata->buffer) {
		if (type == XS_WATCH_EVENT) {
			/* Same as above: no way to tell someone. */
			talloc_free(bdata);
			return;
		}
		/* re-establish request buffer for sending ENOMEM. */
		conn->in = bdata;
		send_error(conn, ENOMEM);
		return;
	}

	/* Update relevant header fields and fill in the message body. */
	bdata->hdr.msg.type = type;
	bdata->hdr.msg.len = len;
	memcpy(bdata->buffer, data, len);

	/* Queue for later transmission. */
	list_add_tail(&bdata->list, &conn->out_list);

	return;
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

bool is_valid_nodename(const char *node)
{
	int local_off = 0;
	unsigned int domid;

	/* Must start in /. */
	if (!strstarts(node, "/"))
		return false;

	/* Cannot end in / (unless it's just "/"). */
	if (strends(node, "/") && !streq(node, "/"))
		return false;

	/* No double //. */
	if (strstr(node, "//"))
		return false;

	if (sscanf(node, "/local/domain/%5u/%n", &domid, &local_off) != 1)
		local_off = 0;

	if (strlen(node) > local_off + quota_max_path_len)
		return false;

	return valid_chars(node);
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

static char *perms_to_strings(const void *ctx, const struct node_perms *perms,
			      unsigned int *len)
{
	unsigned int i;
	char *strings = NULL;
	char buffer[MAX_STRLEN(unsigned int) + 1];

	for (*len = 0, i = 0; i < perms->num; i++) {
		if (!xs_perm_to_string(&perms->p[i], buffer, sizeof(buffer)))
			return NULL;

		strings = talloc_realloc(ctx, strings, char,
					 *len + strlen(buffer) + 1);
		if (!strings)
			return NULL;
		strcpy(strings + *len, buffer);
		*len += strlen(buffer) + 1;
	}
	return strings;
}

char *canonicalize(struct connection *conn, const void *ctx, const char *node)
{
	const char *prefix;

	if (!node || (node[0] == '/') || (node[0] == '@'))
		return (char *)node;
	prefix = get_implicit_path(conn);
	if (prefix)
		return talloc_asprintf(ctx, "%s/%s", prefix, node);
	return (char *)node;
}

static struct node *get_node_canonicalized(struct connection *conn,
					   const void *ctx,
					   const char *name,
					   char **canonical_name,
					   enum xs_perm_type perm)
{
	char *tmp_name;

	if (!canonical_name)
		canonical_name = &tmp_name;
	*canonical_name = canonicalize(conn, ctx, name);
	if (!*canonical_name)
		return NULL;
	return get_node(conn, ctx, *canonical_name, perm);
}

static int send_directory(struct connection *conn, struct buffered_data *in)
{
	struct node *node;

	node = get_node_canonicalized(conn, in, onearg(in), NULL, XS_PERM_READ);
	if (!node)
		return errno;

	send_reply(conn, XS_DIRECTORY, node->children, node->childlen);

	return 0;
}

static int send_directory_part(struct connection *conn,
			       struct buffered_data *in)
{
	unsigned int off, len, maxlen, genlen;
	char *child, *data;
	struct node *node;
	char gen[24];

	if (xs_count_strings(in->buffer, in->used) != 2)
		return EINVAL;

	/* First arg is node name. */
	node = get_node_canonicalized(conn, in, in->buffer, NULL, XS_PERM_READ);
	if (!node)
		return errno;

	/* Second arg is childlist offset. */
	off = atoi(in->buffer + strlen(in->buffer) + 1);

	genlen = snprintf(gen, sizeof(gen), "%"PRIu64, node->generation) + 1;

	/* Offset behind list: just return a list with an empty string. */
	if (off >= node->childlen) {
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
		if (off + len == node->childlen)
			break;
	}

	data = talloc_array(in, char, genlen + len + 1);
	if (!data)
		return ENOMEM;

	memcpy(data, gen, genlen);
	memcpy(data + genlen, node->children + off, len);
	if (off + len == node->childlen) {
		data[genlen + len] = 0;
		len++;
	}

	send_reply(conn, XS_DIRECTORY_PART, data, genlen + len);

	return 0;
}

static int do_read(struct connection *conn, struct buffered_data *in)
{
	struct node *node;

	node = get_node_canonicalized(conn, in, onearg(in), NULL, XS_PERM_READ);
	if (!node)
		return errno;

	send_reply(conn, XS_READ, node->data, node->datalen);

	return 0;
}

static void delete_node_single(struct connection *conn, struct node *node)
{
	TDB_DATA key;

	if (access_node(conn, node, NODE_ACCESS_DELETE, &key))
		return;

	if (tdb_delete(tdb_ctx, key) != 0) {
		corrupt(conn, "Could not delete '%s'", node->name);
		return;
	}

	domain_entry_dec(conn, node);
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
	children = talloc_array(ctx, char, parent->childlen + baselen);
	if (!children)
		return ENOMEM;
	memcpy(children, parent->children, parent->childlen);
	memcpy(children + parent->childlen, base, baselen);
	parent->children = children;
	parent->childlen += baselen;

	return 0;
}

static struct node *construct_node(struct connection *conn, const void *ctx,
				   const char *name)
{
	struct node *parent, *node;
	char *parentname = get_parent(ctx, name);

	if (!parentname)
		return NULL;

	/* If parent doesn't exist, create it. */
	parent = read_node(conn, parentname, parentname);
	if (!parent)
		parent = construct_node(conn, ctx, parentname);
	if (!parent)
		return NULL;

	/* Add child to parent. */
	if (add_child(ctx, parent, name))
		goto nomem;

	/* Allocate node */
	node = talloc(ctx, struct node);
	if (!node)
		goto nomem;
	node->name = talloc_strdup(node, name);
	if (!node->name)
		goto nomem;

	/* Inherit permissions, except unprivileged domains own what they create */
	node->perms.num = parent->perms.num;
	node->perms.p = talloc_memdup(node, parent->perms.p,
				      node->perms.num * sizeof(*node->perms.p));
	if (!node->perms.p)
		goto nomem;
	if (domain_is_unprivileged(conn))
		node->perms.p[0].id = conn->id;

	/* No children, no data */
	node->children = node->data = NULL;
	node->childlen = node->datalen = 0;
	node->parent = parent;
	return node;

nomem:
	errno = ENOMEM;
	return NULL;
}

static int destroy_node(void *_node)
{
	struct node *node = _node;
	TDB_DATA key;

	if (streq(node->name, "/"))
		corrupt(NULL, "Destroying root node!");

	set_tdb_key(node->name, &key);
	tdb_delete(tdb_ctx, key);

	domain_entry_dec(talloc_parent(node), node);

	return 0;
}

static struct node *create_node(struct connection *conn, const void *ctx,
				const char *name,
				void *data, unsigned int datalen)
{
	struct node *node, *i;

	node = construct_node(conn, ctx, name);
	if (!node)
		return NULL;

	node->data = data;
	node->datalen = datalen;

	/*
	 * We write out the nodes bottom up.
	 * All new created nodes will have i->parent set, while the final
	 * node will be already existing and won't have i->parent set.
	 * New nodes are subject to quota handling.
	 * Initially set a destructor for all new nodes removing them from
	 * TDB again and undoing quota accounting for the case of an error
	 * during the write loop.
	 */
	for (i = node; i; i = i->parent) {
		/* i->parent is set for each new node, so check quota. */
		if (i->parent &&
		    domain_entry(conn) >= quota_nb_entry_per_domain) {
			errno = ENOSPC;
			return NULL;
		}
		if (write_node(conn, i, false))
			return NULL;

		/* Account for new node, set destructor for error case. */
		if (i->parent) {
			domain_entry_inc(conn, i);
			talloc_set_destructor(i, destroy_node);
		}
	}

	/* OK, now remove destructors so they stay around */
	for (i = node; i->parent; i = i->parent)
		talloc_set_destructor(i, NULL);
	return node;
}

/* path, data... */
static int do_write(struct connection *conn, struct buffered_data *in)
{
	unsigned int offset, datalen;
	struct node *node;
	char *vec[1] = { NULL }; /* gcc4 + -W + -Werror fucks code. */
	char *name;

	/* Extra "strings" can be created by binary data. */
	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec))
		return EINVAL;

	offset = strlen(vec[0]) + 1;
	datalen = in->used - offset;

	node = get_node_canonicalized(conn, in, vec[0], &name, XS_PERM_WRITE);
	if (!node) {
		/* No permissions, invalid input? */
		if (errno != ENOENT)
			return errno;
		node = create_node(conn, in, name, in->buffer + offset,
				   datalen);
		if (!node)
			return errno;
	} else {
		node->data = in->buffer + offset;
		node->datalen = datalen;
		if (write_node(conn, node, false))
			return errno;
	}

	fire_watches(conn, in, name, node, false, NULL);
	send_ack(conn, XS_WRITE);

	return 0;
}

static int do_mkdir(struct connection *conn, struct buffered_data *in)
{
	struct node *node;
	char *name;

	node = get_node_canonicalized(conn, in, onearg(in), &name,
				      XS_PERM_WRITE);

	/* If it already exists, fine. */
	if (!node) {
		/* No permissions? */
		if (errno != ENOENT)
			return errno;
		node = create_node(conn, in, name, NULL, 0);
		if (!node)
			return errno;
		fire_watches(conn, in, name, node, false, NULL);
	}
	send_ack(conn, XS_MKDIR);

	return 0;
}

/* Delete memory using memmove. */
static void memdel(void *mem, unsigned off, unsigned len, unsigned total)
{
	memmove(mem + off, mem + off + len, total - off - len);
}

static void remove_child_entry(struct connection *conn, struct node *node,
			       size_t offset)
{
	size_t childlen = strlen(node->children + offset);

	memdel(node->children, offset, childlen + 1, node->childlen);
	node->childlen -= childlen + 1;
	if (write_node(conn, node, true))
		corrupt(conn, "Can't update parent node '%s'", node->name);
}

static void delete_child(struct connection *conn,
			 struct node *node, const char *childname)
{
	unsigned int i;

	for (i = 0; i < node->childlen; i += strlen(node->children+i) + 1) {
		if (streq(node->children+i, childname)) {
			remove_child_entry(conn, node, i);
			return;
		}
	}
	corrupt(conn, "Can't find child '%s' in %s", childname, node->name);
}

static int delete_node(struct connection *conn, const void *ctx,
		       struct node *parent, struct node *node)
{
	char *name;

	/* Delete children. */
	while (node->childlen) {
		struct node *child;

		name = talloc_asprintf(node, "%s/%s", node->name,
				       node->children);
		child = name ? read_node(conn, node, name) : NULL;
		if (child) {
			if (delete_node(conn, ctx, node, child))
				return errno;
		} else {
			trace("delete_node: Error deleting child '%s/%s'!\n",
			      node->name, node->children);
			/* Quit deleting. */
			errno = ENOMEM;
			return errno;
		}
		talloc_free(name);
	}

	fire_watches(conn, ctx, node->name, node, true, NULL);
	delete_node_single(conn, node);
	delete_child(conn, parent, basename(node->name));
	talloc_free(node);

	return 0;
}

static int _rm(struct connection *conn, const void *ctx, struct node *node,
	       const char *name)
{
	/*
	 * Deleting node by node, so the result is always consistent even in
	 * case of a failure.
	 */
	struct node *parent;
	char *parentname = get_parent(ctx, name);

	if (!parentname)
		return errno;

	parent = read_node(conn, ctx, parentname);
	if (!parent)
		return (errno == ENOMEM) ? ENOMEM : EINVAL;
	node->parent = parent;

	/*
	 * Fire the watches now, when we can still see the node permissions.
	 * This fine as we are single threaded and the next possible read will
	 * be handled only after the node has been really removed.
	 */
	fire_watches(conn, ctx, name, node, false, NULL);
	return delete_node(conn, ctx, parent, node);
}


static int do_rm(struct connection *conn, struct buffered_data *in)
{
	struct node *node;
	int ret;
	char *name;
	char *parentname;

	node = get_node_canonicalized(conn, in, onearg(in), &name,
				      XS_PERM_WRITE);
	if (!node) {
		/* Didn't exist already?  Fine, if parent exists. */
		if (errno == ENOENT) {
			parentname = get_parent(in, name);
			if (!parentname)
				return errno;
			node = read_node(conn, in, parentname);
			if (node) {
				send_ack(conn, XS_RM);
				return 0;
			}
			/* Restore errno, just in case. */
			if (errno != ENOMEM)
				errno = ENOENT;
		}
		return errno;
	}

	if (streq(name, "/"))
		return EINVAL;

	ret = _rm(conn, in, node, name);
	if (ret)
		return ret;

	send_ack(conn, XS_RM);

	return 0;
}


static int do_get_perms(struct connection *conn, struct buffered_data *in)
{
	struct node *node;
	char *strings;
	unsigned int len;

	node = get_node_canonicalized(conn, in, onearg(in), NULL, XS_PERM_READ);
	if (!node)
		return errno;

	strings = perms_to_strings(node, &node->perms, &len);
	if (!strings)
		return errno;

	send_reply(conn, XS_GET_PERMS, strings, len);

	return 0;
}

static int do_set_perms(struct connection *conn, struct buffered_data *in)
{
	struct node_perms perms, old_perms;
	char *name, *permstr;
	struct node *node;

	perms.num = xs_count_strings(in->buffer, in->used);
	if (perms.num < 2)
		return EINVAL;

	perms.num--;
	if (domain_is_unprivileged(conn) &&
	    perms.num > quota_nb_perms_per_node)
		return ENOSPC;

	permstr = in->buffer + strlen(in->buffer) + 1;

	perms.p = talloc_array(in, struct xs_permissions, perms.num);
	if (!perms.p)
		return ENOMEM;
	if (!xs_strings_to_perms(perms.p, perms.num, permstr))
		return errno;

	/* First arg is node name. */
	if (strstarts(in->buffer, "@")) {
		if (set_perms_special(conn, in->buffer, &perms))
			return errno;
		send_ack(conn, XS_SET_PERMS);
		return 0;
	}

	/* We must own node to do this (tools can do this too). */
	node = get_node_canonicalized(conn, in, in->buffer, &name,
				      XS_PERM_WRITE | XS_PERM_OWNER);
	if (!node)
		return errno;

	/* Unprivileged domains may not change the owner. */
	if (domain_is_unprivileged(conn) &&
	    perms.p[0].id != node->perms.p[0].id)
		return EPERM;

	old_perms = node->perms;
	domain_entry_dec(conn, node);
	node->perms = perms;
	domain_entry_inc(conn, node);

	if (write_node(conn, node, false))
		return errno;

	fire_watches(conn, in, name, node, false, &old_perms);
	send_ack(conn, XS_SET_PERMS);

	return 0;
}

static struct {
	const char *str;
	int (*func)(struct connection *conn, struct buffered_data *in);
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

/*
 * Keep the connection alive but stop processing any new request or sending
 * reponse. This is to allow sending @releaseDomain watch event at the correct
 * moment and/or to allow the connection to restart (not yet implemented).
 *
 * All watches, transactions, buffers will be freed.
 */
static void ignore_connection(struct connection *conn)
{
	struct buffered_data *out, *tmp;

	trace("CONN %p ignored\n", conn);

	conn->is_ignored = true;
	conn_delete_all_watches(conn);
	conn_delete_all_transactions(conn);

	list_for_each_entry_safe(out, tmp, &conn->out_list, list) {
		list_del(&out->list);
		talloc_free(out);
	}

	talloc_free(conn->in);
	conn->in = NULL;
}

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

	assert(conn->transaction == NULL);
	conn->transaction = trans;

	ret = wire_funcs[type].func(conn, in);
	if (ret)
		send_error(conn, ret);

	conn->transaction = NULL;
}

static void consider_message(struct connection *conn)
{
	if (verbose)
		xprintf("Got message %s len %i from %p\n",
			sockmsg_string(conn->in->hdr.msg.type),
			conn->in->hdr.msg.len, conn);

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

	if (!conn->in) {
		conn->in = new_buffer(conn);
		/* In case of no memory just try it again next time. */
		if (!conn->in)
			return;
	}
	in = conn->in;

	/* Not finished header yet? */
	if (in->inhdr) {
		if (in->used != sizeof(in->hdr)) {
			bytes = conn->read(conn, in->hdr.raw + in->used,
					   sizeof(in->hdr) - in->used);
			if (bytes < 0)
				goto bad_client;
			in->used += bytes;
			if (in->used != sizeof(in->hdr))
				return;

			if (in->hdr.msg.len > XENSTORE_PAYLOAD_MAX) {
				syslog(LOG_ERR, "Client tried to feed us %i",
				       in->hdr.msg.len);
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

	bytes = conn->read(conn, in->buffer + in->used,
			   in->hdr.msg.len - in->used);
	if (bytes < 0)
		goto bad_client;

	in->used += bytes;
	if (in->used != in->hdr.msg.len)
		return;

	trace_io(conn, in, 0);
	consider_message(conn);
	return;

bad_client:
	ignore_connection(conn);
}

static void handle_output(struct connection *conn)
{
	/* Ignore the connection if an error occured */
	if (!write_messages(conn))
		ignore_connection(conn);
}

struct connection *new_connection(connwritefn_t *write, connreadfn_t *read)
{
	struct connection *new;

	new = talloc_zero(talloc_autofree_context(), struct connection);
	if (!new)
		return NULL;

	new->fd = -1;
	new->pollfd_idx = -1;
	new->write = write;
	new->read = read;
	new->is_ignored = false;
	new->transaction_started = 0;
	INIT_LIST_HEAD(&new->out_list);
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

#ifdef NO_SOCKETS
static void accept_connection(int sock)
{
}

int writefd(struct connection *conn, const void *data, unsigned int len)
{
	errno = EBADF;
	return -1;
}

int readfd(struct connection *conn, void *data, unsigned int len)
{
	errno = EBADF;
	return -1;
}
#else
int writefd(struct connection *conn, const void *data, unsigned int len)
{
	int rc;

	while ((rc = write(conn->fd, data, len)) < 0) {
		if (errno == EAGAIN) {
			rc = 0;
			break;
		}
		if (errno != EINTR)
			break;
	}

	return rc;
}

int readfd(struct connection *conn, void *data, unsigned int len)
{
	int rc;

	while ((rc = read(conn->fd, data, len)) < 0) {
		if (errno == EAGAIN) {
			rc = 0;
			break;
		}
		if (errno != EINTR)
			break;
	}

	/* Reading zero length means we're done with this connection. */
	if ((rc == 0) && (len != 0)) {
		errno = EBADF;
		rc = -1;
	}

	return rc;
}

static void accept_connection(int sock)
{
	int fd;
	struct connection *conn;

	fd = accept(sock, NULL, NULL);
	if (fd < 0)
		return;

	conn = new_connection(writefd, readfd);
	if (conn)
		conn->fd = fd;
	else
		close(fd);
}
#endif

static int tdb_flags;

/* We create initial nodes manually. */
static void manual_node(const char *name, const char *child)
{
	struct node *node;
	struct xs_permissions perms = { .id = 0, .perms = XS_PERM_NONE };

	node = talloc_zero(NULL, struct node);
	if (!node)
		barf_perror("Could not allocate initial node %s", name);

	node->name = name;
	node->perms.p = &perms;
	node->perms.num = 1;
	node->children = (char *)child;
	if (child)
		node->childlen = strlen(child) + 1;

	if (write_node(NULL, node, false))
		barf_perror("Could not create initial node %s", name);
	talloc_free(node);
}

static void tdb_logger(TDB_CONTEXT *tdb, int level, const char * fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	s = talloc_vasprintf(NULL, fmt, ap);
	va_end(ap);

	if (s) {
		trace("TDB: %s\n", s);
		syslog(LOG_ERR, "TDB: %s",  s);
		if (verbose)
			xprintf("TDB: %s", s);
		talloc_free(s);
	} else {
		trace("talloc failure during logging\n");
		syslog(LOG_ERR, "talloc failure during logging\n");
	}
}

static void setup_structure(bool live_update)
{
	char *tdbname;

	tdbname = talloc_strdup(talloc_autofree_context(), xs_daemon_tdb());
	if (!tdbname)
		barf_perror("Could not create tdbname");

	if (!(tdb_flags & TDB_INTERNAL))
		unlink(tdbname);

	tdb_ctx = tdb_open_ex(tdbname, 7919, tdb_flags,
			      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
			      0640, &tdb_logger, NULL);
	if (!tdb_ctx)
		barf_perror("Could not create tdb file %s", tdbname);

	if (live_update)
		manual_node("/", NULL);
	else {
		manual_node("/", "tool");
		manual_node("/tool", "xenstored");
		manual_node("/tool/xenstored", NULL);
	}

	check_store();
}

static unsigned int hash_from_key_fn(void *k)
{
	char *str = k;
	unsigned int hash = 5381;
	char c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + (unsigned int)c;

	return hash;
}


static int keys_equal_fn(void *key1, void *key2)
{
	return 0 == strcmp((char *)key1, (char *)key2);
}


static char *child_name(const char *s1, const char *s2)
{
	if (strcmp(s1, "/")) {
		return talloc_asprintf(NULL, "%s/%s", s1, s2);
	}
	else {
		return talloc_asprintf(NULL, "/%s", s2);
	}
}


int remember_string(struct hashtable *hash, const char *str)
{
	char *k = malloc(strlen(str) + 1);

	if (!k)
		return 0;
	strcpy(k, str);
	return hashtable_insert(hash, k, (void *)1);
}


/**
 * A node has a children field that names the children of the node, separated
 * by NULs.  We check whether there are entries in there that are duplicated
 * (and if so, delete the second one), and whether there are any that do not
 * have a corresponding child node (and if so, delete them).  Each valid child
 * is then recursively checked.
 *
 * No deleting is performed if the recovery flag is cleared (i.e. -R was
 * passed on the command line).
 *
 * As we go, we record each node in the given reachable hashtable.  These
 * entries will be used later in clean_store.
 */
static int check_store_(const char *name, struct hashtable *reachable)
{
	struct node *node = read_node(NULL, name, name);
	int ret = 0;

	if (node) {
		size_t i = 0;

		struct hashtable * children =
			create_hashtable(16, hash_from_key_fn, keys_equal_fn);

		if (!remember_string(reachable, name)) {
			hashtable_destroy(children, 0);
			log("check_store: ENOMEM");
			return ENOMEM;
		}

		while (i < node->childlen && !ret) {
			struct node *childnode;
			size_t childlen = strlen(node->children + i);
			char * childname = child_name(node->name,
						      node->children + i);

			if (!childname) {
				log("check_store: ENOMEM");
				ret = ENOMEM;
				break;
			}
			childnode = read_node(NULL, childname, childname);
			
			if (childnode) {
				if (hashtable_search(children, childname)) {
					log("check_store: '%s' is duplicated!",
					    childname);

					if (recovery) {
						remove_child_entry(NULL, node,
								   i);
						i -= childlen + 1;
					}
				}
				else {
					if (!remember_string(children,
							     childname)) {
						log("check_store: ENOMEM");
						talloc_free(childnode);
						talloc_free(childname);
						ret = ENOMEM;
						break;
					}
					ret = check_store_(childname,
							   reachable);
				}
			} else if (errno != ENOMEM) {
				log("check_store: No child '%s' found!\n",
				    childname);

				if (recovery) {
					remove_child_entry(NULL, node, i);
					i -= childlen + 1;
				}
			} else {
				log("check_store: ENOMEM");
				ret = ENOMEM;
			}

			talloc_free(childnode);
			talloc_free(childname);
			i += childlen + 1;
		}

		hashtable_destroy(children, 0 /* Don't free values (they are
						 all (void *)1) */);
		talloc_free(node);
	} else if (errno != ENOMEM) {
		/* Impossible, because no database should ever be without the
		   root, and otherwise, we've just checked in our caller
		   (which made a recursive call to get here). */
		   
		log("check_store: No child '%s' found: impossible!", name);
	} else {
		log("check_store: ENOMEM");
		ret = ENOMEM;
	}

	return ret;
}


/**
 * Helper to clean_store below.
 */
static int clean_store_(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA val,
			void *private)
{
	struct hashtable *reachable = private;
	char *slash;
	char * name = talloc_strndup(NULL, key.dptr, key.dsize);

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
		if (recovery) {
			tdb_delete(tdb, key);
		}
	}

	talloc_free(name);

	return 0;
}


/**
 * Given the list of reachable nodes, iterate over the whole store, and
 * remove any that were not reached.
 */
static void clean_store(struct hashtable *reachable)
{
	tdb_traverse(tdb_ctx, &clean_store_, reachable);
}


void check_store(void)
{
	char * root = talloc_strdup(NULL, "/");
	struct hashtable * reachable =
		create_hashtable(16, hash_from_key_fn, keys_equal_fn);
 
	if (!reachable) {
		log("check_store: ENOMEM");
		return;
	}

	log("Checking store ...");
	if (!check_store_(root, reachable) &&
	    !check_transactions(reachable))
		clean_store(reachable);
	log("Checking store complete.");

	hashtable_destroy(reachable, 0 /* Don't free values (they are all
					  (void *)1) */);
	talloc_free(root);
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
	    conn ? (int)conn->id : -1, strerror(saved_errno), str);

	check_store();
}

#ifndef NO_SOCKETS
static void destroy_fds(void)
{
	if (sock >= 0)
		close(sock);
}

static void init_sockets(void)
{
	struct sockaddr_un addr;
	const char *soc_str = xs_daemon_socket();

	/* Create sockets for them to listen to. */
	atexit(destroy_fds);
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		barf_perror("Could not create socket");

	/* FIXME: Be more sophisticated, don't mug running daemon. */
	unlink(soc_str);

	addr.sun_family = AF_UNIX;

	if(strlen(soc_str) >= sizeof(addr.sun_path))
		barf_perror("socket string '%s' too long", soc_str);
	strcpy(addr.sun_path, soc_str);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		barf_perror("Could not bind socket to %s", soc_str);

	if (chmod(soc_str, 0600) != 0)
		barf_perror("Could not chmod sockets");

	if (listen(sock, 1) != 0)
		barf_perror("Could not listen on sockets");
}
#endif

static void usage(void)
{
	fprintf(stderr,
"Usage:\n"
"\n"
"  xenstored <options>\n"
"\n"
"where options may include:\n"
"\n"
"  -D, --no-domain-init    to state that xenstored should not initialise dom0,\n"
"  -F, --pid-file <file>   giving a file for the daemon's pid to be written,\n"
"  -H, --help              to output this message,\n"
"  -N, --no-fork           to request that the daemon does not fork,\n"
"  -P, --output-pid        to request that the pid of the daemon is output,\n"
"  -T, --trace-file <file> giving the file for logging, and\n"
"  -E, --entry-nb <nb>     limit the number of entries per domain,\n"
"  -S, --entry-size <size> limit the size of entry per domain, and\n"
"  -W, --watch-nb <nb>     limit the number of watches per domain,\n"
"  -t, --transaction <nb>  limit the number of transaction allowed per domain,\n"
"  -A, --perm-nb <nb>      limit the number of permissions per node,\n"
"  -M, --path-max <chars>  limit the allowed Xenstore node path length,\n"
"  -R, --no-recovery       to request that no recovery should be attempted when\n"
"                          the store is corrupted (debug only),\n"
"  -I, --internal-db       store database in memory, not on disk\n"
"  -V, --verbose           to request verbose execution.\n");
}


static struct option options[] = {
	{ "no-domain-init", 0, NULL, 'D' },
	{ "entry-nb", 1, NULL, 'E' },
	{ "pid-file", 1, NULL, 'F' },
	{ "event", 1, NULL, 'e' },
	{ "master-domid", 1, NULL, 'm' },
	{ "help", 0, NULL, 'H' },
	{ "no-fork", 0, NULL, 'N' },
	{ "priv-domid", 1, NULL, 'p' },
	{ "output-pid", 0, NULL, 'P' },
	{ "entry-size", 1, NULL, 'S' },
	{ "trace-file", 1, NULL, 'T' },
	{ "transaction", 1, NULL, 't' },
	{ "perm-nb", 1, NULL, 'A' },
	{ "path-max", 1, NULL, 'M' },
	{ "no-recovery", 0, NULL, 'R' },
	{ "internal-db", 0, NULL, 'I' },
	{ "verbose", 0, NULL, 'V' },
	{ "watch-nb", 1, NULL, 'W' },
	{ "live-update", 0, NULL, 'U' },
	{ NULL, 0, NULL, 0 } };

extern void dump_conn(struct connection *conn); 
int dom0_domid = 0;
int dom0_event = 0;
int priv_domid = 0;

int main(int argc, char *argv[])
{
	int opt;
	int sock_pollfd_idx = -1;
	bool dofork = true;
	bool outputpid = false;
	bool no_domain_init = false;
	bool live_update = false;
	const char *pidfile = NULL;
	int timeout;

	orig_argc = argc;
	orig_argv = argv;

	while ((opt = getopt_long(argc, argv, "DE:F:HNPS:t:A:M:T:RVW:U", options,
				  NULL)) != -1) {
		switch (opt) {
		case 'D':
			no_domain_init = true;
			break;
		case 'E':
			quota_nb_entry_per_domain = strtol(optarg, NULL, 10);
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
		case 'P':
			outputpid = true;
			break;
		case 'R':
			recovery = false;
			break;
		case 'S':
			quota_max_entry_size = strtol(optarg, NULL, 10);
			break;
		case 't':
			quota_max_transaction = strtol(optarg, NULL, 10);
			break;
		case 'T':
			tracefile = optarg;
			break;
		case 'I':
			tdb_flags = TDB_INTERNAL|TDB_NOLOCK;
			break;
		case 'V':
			verbose = true;
			break;
		case 'W':
			quota_nb_watch_per_domain = strtol(optarg, NULL, 10);
			break;
		case 'A':
			quota_nb_perms_per_node = strtol(optarg, NULL, 10);
			break;
			quota_max_path_len = strtol(optarg, NULL, 10);
			quota_max_path_len = min(XENSTORE_REL_PATH_MAX,
						 quota_max_path_len);
			break;
		case 'e':
			dom0_event = strtol(optarg, NULL, 10);
			break;
		case 'm':
			dom0_domid = strtol(optarg, NULL, 10);
			break;
		case 'p':
			priv_domid = strtol(optarg, NULL, 10);
			break;
		case 'U':
			live_update = true;
			break;
		}
	}
	if (optind != argc)
		barf("%s: No arguments desired", argv[0]);

	reopen_log();

	/* make sure xenstored directories exist */
	/* Errors ignored here, will be reported when we open files */
	mkdir(xs_daemon_rundir(), 0755);
	mkdir(xs_daemon_rootdir(), 0755);

	if (dofork) {
		openlog("xenstored", 0, LOG_DAEMON);
		if (!live_update)
			daemonize();
	}
	if (pidfile)
		write_pidfile(pidfile);

	/* Talloc leak reports go to stderr, which is closed if we fork. */
	if (!dofork)
		talloc_enable_leak_report_full();

	/* Don't kill us with SIGPIPE. */
	signal(SIGPIPE, SIG_IGN);

	talloc_enable_null_tracking();

#ifndef NO_SOCKETS
	if (!live_update)
		init_sockets();
#endif

	init_pipe(reopen_log_pipe);

	/* Setup the database */
	setup_structure(live_update);

	/* Listen to hypervisor. */
	if (!no_domain_init && !live_update) {
		domain_init(-1);
		dom0_init();
	}

	if (outputpid) {
		printf("%ld\n", (long)getpid());
		fflush(stdout);
	}

	/* redirect to /dev/null now we're ready to accept connections */
	if (dofork && !live_update)
		finish_daemonize();
#ifndef __MINIOS__
	if (dofork)
		xprintf = trace;
#endif

	signal(SIGHUP, trigger_reopen_log);
	if (tracefile)
		tracefile = talloc_strdup(NULL, tracefile);

	/* Read state in case of live update. */
	if (live_update)
		lu_read_state();

	/* Get ready to listen to the tools. */
	initialize_fds(&sock_pollfd_idx, &timeout);

	/* Tell the kernel we're up and running. */
	xenbus_notify_running();

#if defined(XEN_SYSTEMD_ENABLED)
	if (!live_update) {
		sd_notify(1, "READY=1");
		fprintf(stderr, SD_NOTICE "xenstored is ready\n");
	}
#endif

	/* Main loop. */
	for (;;) {
		struct connection *conn, *next;

		if (poll(fds, nr_fds, timeout) < 0) {
			if (errno == EINTR)
				continue;
			barf_perror("Poll failed");
		}

		if (reopen_log_pipe0_pollfd_idx != -1) {
			if (fds[reopen_log_pipe0_pollfd_idx].revents
			    & ~POLLIN) {
				close(reopen_log_pipe[0]);
				close(reopen_log_pipe[1]);
				init_pipe(reopen_log_pipe);
			} else if (fds[reopen_log_pipe0_pollfd_idx].revents
				   & POLLIN) {
				char c;
				if (read(reopen_log_pipe[0], &c, 1) != 1)
					barf_perror("read failed");
				reopen_log();
			}
			reopen_log_pipe0_pollfd_idx = -1;
		}

		if (sock_pollfd_idx != -1) {
			if (fds[sock_pollfd_idx].revents & ~POLLIN) {
				barf_perror("sock poll failed");
				break;
			} else if (fds[sock_pollfd_idx].revents & POLLIN) {
				accept_connection(sock);
				sock_pollfd_idx = -1;
			}
		}

		if (xce_pollfd_idx != -1) {
			if (fds[xce_pollfd_idx].revents & ~POLLIN) {
				barf_perror("xce_handle poll failed");
				break;
			} else if (fds[xce_pollfd_idx].revents & POLLIN) {
				handle_event();
				xce_pollfd_idx = -1;
			}
		}

		next = list_entry(connections.next, typeof(*conn), list);
		if (&next->list != &connections)
			talloc_increase_ref_count(next);
		while (&next->list != &connections) {
			conn = next;

			next = list_entry(conn->list.next,
					  typeof(*conn), list);
			if (&next->list != &connections)
				talloc_increase_ref_count(next);

			if (conn->domain) {
				if (domain_can_read(conn))
					handle_input(conn);
				if (talloc_free(conn) == 0)
					continue;

				talloc_increase_ref_count(conn);
				if (domain_can_write(conn) &&
				    !list_empty(&conn->out_list))
					handle_output(conn);
				if (talloc_free(conn) == 0)
					continue;
			} else {
				if (conn->pollfd_idx != -1) {
					if (fds[conn->pollfd_idx].revents
					    & ~(POLLIN|POLLOUT))
						talloc_free(conn);
					else if ((fds[conn->pollfd_idx].revents
						  & POLLIN) &&
						 !conn->is_ignored)
						handle_input(conn);
				}
				if (talloc_free(conn) == 0)
					continue;

				talloc_increase_ref_count(conn);

				if (conn->pollfd_idx != -1) {
					if (fds[conn->pollfd_idx].revents
					    & ~(POLLIN|POLLOUT))
						talloc_free(conn);
					else if ((fds[conn->pollfd_idx].revents
						  & POLLOUT) &&
						 !conn->is_ignored)
						handle_output(conn);
				}
				if (talloc_free(conn) == 0)
					continue;

				conn->pollfd_idx = -1;
			}
		}

		if (delayed_requests) {
			list_for_each_entry(conn, &connections, list) {
				struct delayed_request *req, *tmp;

				list_for_each_entry_safe(req, tmp,
							 &conn->delayed, list)
					call_delayed(conn, req);
			}
		}

		initialize_fds(&sock_pollfd_idx, &timeout);
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
	glb.socket_fd = sock;
	glb.evtchn_fd = xenevtchn_fd(xce_handle);
	if (fwrite(&glb, sizeof(glb), 1, fp) != 1)
		return "Dump global state error";

	return NULL;
}

/* Called twice: first with fp == NULL to get length, then for writing data. */
const char *dump_state_buffered_data(FILE *fp, const struct connection *c,
				     const struct connection *conn,
				     struct xs_state_connection *sc)
{
	unsigned int len = 0, used;
	struct buffered_data *out, *in = c->in;
	bool partial = true;

	if (in && c != conn) {
		len = in->inhdr ? in->used : sizeof(in->hdr);
		if (fp && fwrite(&in->hdr, len, 1, fp) != 1)
			return "Dump read data error";
		if (!in->inhdr && in->used) {
			len += in->used;
			if (fp && fwrite(in->buffer, in->used, 1, fp) != 1)
				return "Dump read data error";
		}
	}

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
	if (c == conn) {
		struct xsd_sockmsg msg = conn->in->hdr.msg;

		msg.len = sizeof("OK");
		if (fp && fwrite(&msg, sizeof(msg), 1, fp) != 1)
			return "Dump buffered data error";
		len += sizeof(msg);
		if (fp && fwrite("OK", msg.len, 1, fp) != 1)

			return "Dump buffered data error";
		len += msg.len;
	}

	if (sc)
		sc->data_out_len = len;

	return NULL;
}

const char *dump_state_node_perms(FILE *fp, struct xs_state_node *sn,
				  const struct xs_permissions *perms,
				  unsigned int n_perms)
{
	unsigned int p;

	for (p = 0; p < n_perms; p++) {
		switch ((int)perms[p].perms & ~XS_PERM_IGNORE) {
		case XS_PERM_READ:
			sn->perms[p].access = XS_STATE_NODE_PERM_READ;
			break;
		case XS_PERM_WRITE:
			sn->perms[p].access = XS_STATE_NODE_PERM_WRITE;
			break;
		case XS_PERM_READ | XS_PERM_WRITE:
			sn->perms[p].access = XS_STATE_NODE_PERM_BOTH;
			break;
		default:
			sn->perms[p].access = XS_STATE_NODE_PERM_NONE;
			break;
		}
		sn->perms[p].flags = (perms[p].perms & XS_PERM_IGNORE)
				     ? XS_STATE_NODE_PERM_IGNORE : 0;
		sn->perms[p].domid = perms[p].id;
	}

	if (fwrite(sn->perms, sizeof(*sn->perms), n_perms, fp) != n_perms)
		return "Dump node permissions error";

	return NULL;
}

static const char *dump_state_node_tree(FILE *fp, char *path)
{
	unsigned int pathlen, childlen, p = 0;
	struct xs_state_record_header head;
	struct xs_state_node sn;
	TDB_DATA key, data;
	const struct xs_tdb_record_hdr *hdr;
	const char *child;
	const char *ret;

	pathlen = strlen(path) + 1;

	set_tdb_key(path, &key);
	data = tdb_fetch(tdb_ctx, key);
	if (data.dptr == NULL)
		return "Error reading node";

	/* Clean up in case of failure. */
	talloc_steal(path, data.dptr);

	hdr = (void *)data.dptr;

	head.type = XS_STATE_TYPE_NODE;
	head.length = sizeof(sn);
	sn.conn_id = 0;
	sn.ta_id = 0;
	sn.ta_access = 0;
	sn.perm_n = hdr->num_perms;
	sn.path_len = pathlen;
	sn.data_len = hdr->datalen;
	head.length += hdr->num_perms * sizeof(*sn.perms);
	head.length += pathlen;
	head.length += hdr->datalen;
	head.length = ROUNDUP(head.length, 3);

	if (fwrite(&head, sizeof(head), 1, fp) != 1)
		return "Dump node state error";
	if (fwrite(&sn, sizeof(sn), 1, fp) != 1)
		return "Dump node state error";

	ret = dump_state_node_perms(fp, &sn, hdr->perms, hdr->num_perms);
	if (ret)
		return ret;

	if (fwrite(path, pathlen, 1, fp) != 1)
		return "Dump node path error";
	if (hdr->datalen &&
	    fwrite(hdr->perms + hdr->num_perms, hdr->datalen, 1, fp) != 1)
		return "Dump node data error";

	ret = dump_state_align(fp);
	if (ret)
		return ret;

	child = (char *)(hdr->perms + hdr->num_perms) + hdr->datalen;

	/*
	 * Use path for constructing children paths.
	 * As we don't write out nodes without having written their parent
	 * already we will never clobber a part of the path we'll need later.
	 */
	pathlen--;
	if (path[pathlen - 1] != '/') {
		path[pathlen] = '/';
		pathlen++;
	}
	while (p < hdr->childlen) {
		childlen = strlen(child) + 1;
		if (pathlen + childlen > XENSTORE_ABS_PATH_MAX)
			return "Dump node path length error";
		strcpy(path + pathlen, child);
		ret = dump_state_node_tree(fp, path);
		if (ret)
			return ret;
		p += childlen;
		child += childlen;
	}

	talloc_free(data.dptr);

	return NULL;
}

const char *dump_state_nodes(FILE *fp, const void *ctx)
{
	char *path;

	path = talloc_size(ctx, XENSTORE_ABS_PATH_MAX);
	if (!path)
		return "Path buffer allocation error";

	strcpy(path, "/");

	return dump_state_node_tree(fp, path);
}

void read_state_global(const void *ctx, const void *state)
{
	const struct xs_state_global *glb = state;

	sock = glb->socket_fd;

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

	/* Queue for later transmission. */
	list_add_tail(&bdata->list, &conn->out_list);
}

void read_state_buffered_data(const void *ctx, struct connection *conn,
			      const struct xs_state_connection *sc)
{
	struct buffered_data *bdata;
	const uint8_t *data;
	unsigned int len;
	bool partial = sc->data_resp_len;

	if (sc->data_in_len) {
		bdata = new_buffer(conn);
		if (!bdata)
			barf("error restoring read data");
		if (sc->data_in_len < sizeof(bdata->hdr)) {
			bdata->inhdr = true;
			memcpy(&bdata->hdr, sc->data, sc->data_in_len);
			bdata->used = sc->data_in_len;
		} else {
			bdata->inhdr = false;
			memcpy(&bdata->hdr, sc->data, sizeof(bdata->hdr));
			if (bdata->hdr.msg.len <= DEFAULT_BUFFER_SIZE)
				bdata->buffer = bdata->default_buffer;
			else
				bdata->buffer = talloc_array(bdata, char,
							bdata->hdr.msg.len);
			if (!bdata->buffer)
				barf("Error allocating in buffer");
			bdata->used = sc->data_in_len - sizeof(bdata->hdr);
			memcpy(bdata->buffer, sc->data + sizeof(bdata->hdr),
			       bdata->used);
		}

		conn->in = bdata;
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
	TDB_DATA key;
	char *name, *parentname;
	unsigned int i;
	struct connection conn = { .id = priv_domid };

	name = (char *)(sn->perms + sn->perm_n);
	node = talloc(ctx, struct node);
	if (!node)
		barf("allocation error restoring node");

	node->name = name;
	node->generation = ++generation;
	node->datalen = sn->data_len;
	node->data = name + sn->path_len;
	node->childlen = 0;
	node->children = NULL;
	node->perms.num = sn->perm_n;
	node->perms.p = talloc_array(node, struct xs_permissions,
				     node->perms.num);
	if (!node->perms.p)
		barf("allocation error restoring node");
	for (i = 0; i < node->perms.num; i++) {
		switch (sn->perms[i].access) {
		case 'r':
			node->perms.p[i].perms = XS_PERM_READ;
			break;
		case 'w':
			node->perms.p[i].perms = XS_PERM_WRITE;
			break;
		case 'b':
			node->perms.p[i].perms = XS_PERM_READ | XS_PERM_WRITE;
			break;
		default:
			node->perms.p[i].perms = XS_PERM_NONE;
			break;
		}
		if (sn->perms[i].flags & XS_STATE_NODE_PERM_IGNORE)
			node->perms.p[i].perms |= XS_PERM_IGNORE;
		node->perms.p[i].id = sn->perms[i].domid;
	}

	if (strstarts(name, "@")) {
		set_perms_special(&conn, name, &node->perms);
		talloc_free(node);
		return;
	}

	parentname = get_parent(node, name);
	if (!parentname)
		barf("allocation error restoring node");
	parent = read_node(NULL, node, parentname);
	if (!parent)
		barf("read parent error restoring node");

	if (add_child(node, parent, name))
		barf("allocation error restoring node");

	set_tdb_key(parentname, &key);
	if (write_node_raw(NULL, &key, parent, true))
		barf("write parent error restoring node");

	set_tdb_key(name, &key);
	if (write_node_raw(NULL, &key, node, true))
		barf("write node error restoring node");
	domain_entry_inc(&conn, node);

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
