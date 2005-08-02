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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
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

//#define DEBUG
#include "utils.h"
#include "list.h"
#include "talloc.h"
#include "xs_lib.h"
#include "xenstored.h"
#include "xenstored_core.h"
#include "xenstored_watch.h"
#include "xenstored_transaction.h"
#include "xenstored_domain.h"

static bool verbose;
LIST_HEAD(connections);
static int tracefd = -1;

#ifdef TESTING
static bool failtest = false;

/* We override talloc's malloc. */
void *test_malloc(size_t size)
{
	/* 1 in 20 means only about 50% of connections establish. */
	if (failtest && (random() % 32) == 0)
		return NULL;
	return malloc(size);
}

static void stop_failtest(int signum __attribute__((unused)))
{
	failtest = false;
}

/* Need these before we #define away write_all/mkdir in testing.h */
bool test_write_all(int fd, void *contents, unsigned int len);
bool test_write_all(int fd, void *contents, unsigned int len)
{
	if (failtest && (random() % 8) == 0) {
		if (len)
			len = random() % len;
		write(fd, contents, len);
		errno = ENOSPC;
		return false;
	}
	return xs_write_all(fd, contents, len);
}

int test_mkdir(const char *dir, int perms);
int test_mkdir(const char *dir, int perms)
{
	if (failtest && (random() % 8) == 0) {
		errno = ENOSPC;
		return -1;
	}
	return mkdir(dir, perms);
}
#endif /* TESTING */

#include "xenstored_test.h"

/* FIXME: Ideally, this should never be called.  Some can be eliminated. */
/* Something is horribly wrong: shutdown immediately. */
void __attribute__((noreturn)) corrupt(struct connection *conn,
				       const char *fmt, ...)
{
	va_list arglist;
	char *str;
	int saved_errno = errno;

	va_start(arglist, fmt);
	str = talloc_vasprintf(NULL, fmt, arglist);
	va_end(arglist);

	trace("xenstored corruption: connection id %i: err %s: %s",
		conn ? (int)conn->id : -1, strerror(saved_errno), str);
	eprintf("xenstored corruption: connection id %i: err %s: %s",
		conn ? (int)conn->id : -1, strerror(saved_errno), str);
#ifdef TESTING
	/* Allow them to attach debugger. */
	sleep(30);
#endif
	syslog(LOG_DAEMON,
	       "xenstored corruption: connection id %i: err %s: %s",
	       conn ? (int)conn->id : -1, strerror(saved_errno), str);
	_exit(2);
}

static char *sockmsg_string(enum xsd_sockmsg_type type)
{
	switch (type) {
	case XS_DEBUG: return "DEBUG";
	case XS_SHUTDOWN: return "SHUTDOWN";
	case XS_DIRECTORY: return "DIRECTORY";
	case XS_READ: return "READ";
	case XS_GET_PERMS: return "GET_PERMS";
	case XS_WATCH: return "WATCH";
	case XS_WATCH_ACK: return "WATCH_ACK";
	case XS_UNWATCH: return "UNWATCH";
	case XS_TRANSACTION_START: return "TRANSACTION_START";
	case XS_TRANSACTION_END: return "TRANSACTION_END";
	case XS_INTRODUCE: return "INTRODUCE";
	case XS_RELEASE: return "RELEASE";
	case XS_GETDOMAINPATH: return "GETDOMAINPATH";
	case XS_WRITE: return "WRITE";
	case XS_MKDIR: return "MKDIR";
	case XS_RM: return "RM";
	case XS_SET_PERMS: return "SET_PERMS";
	case XS_WATCH_EVENT: return "WATCH_EVENT";
	case XS_ERROR: return "ERROR";
	default:
		return "**UNKNOWN**";
	}
}

static void trace_io(const struct connection *conn,
		     const char *prefix,
		     const struct buffered_data *data)
{
	char string[64];
	unsigned int i;

	if (tracefd < 0)
		return;

	write(tracefd, prefix, strlen(prefix));
	sprintf(string, " %p ", conn);
	write(tracefd, string, strlen(string));
	write(tracefd, sockmsg_string(data->hdr.msg.type),
	      strlen(sockmsg_string(data->hdr.msg.type)));
	write(tracefd, " (", 2);
	for (i = 0; i < data->hdr.msg.len; i++) {
		if (data->buffer[i] == '\0')
			write(tracefd, " ", 1);
		else
			write(tracefd, data->buffer + i, 1);
	}
	write(tracefd, ")\n", 2);
}

void trace_create(const void *data, const char *type)
{
	char string[64];
	if (tracefd < 0)
		return;

	write(tracefd, "CREATE ", strlen("CREATE "));
	write(tracefd, type, strlen(type));
	sprintf(string, " %p\n", data);
	write(tracefd, string, strlen(string));
}

void trace_destroy(const void *data, const char *type)
{
	char string[64];
	if (tracefd < 0)
		return;

	write(tracefd, "DESTROY ", strlen("DESTROY "));
	write(tracefd, type, strlen(type));
	sprintf(string, " %p\n", data);
	write(tracefd, string, strlen(string));
}

void trace_watch_timeout(const struct connection *conn, const char *node, const char *token)
{
	char string[64];
	if (tracefd < 0)
		return;
	write(tracefd, "WATCH_TIMEOUT ", strlen("WATCH_TIMEOUT "));
	sprintf(string, " %p ", conn);
	write(tracefd, string, strlen(string));
	write(tracefd, " (", 2);
	write(tracefd, node, strlen(node));
	write(tracefd, " ", 1);
	write(tracefd, token, strlen(token));
	write(tracefd, ")\n", 2);
}

static void trace_blocked(const struct connection *conn,
			  const struct buffered_data *data)
{
	char string[64];

	if (tracefd < 0)
		return;

	write(tracefd, "BLOCKED", strlen("BLOCKED"));
	sprintf(string, " %p (", conn);
	write(tracefd, string, strlen(string));
	write(tracefd, sockmsg_string(data->hdr.msg.type),
	      strlen(sockmsg_string(data->hdr.msg.type)));
	write(tracefd, ")\n", 2);
}

void trace(const char *fmt, ...)
{
	va_list arglist;
	char *str;

	if (tracefd < 0)
		return;

	va_start(arglist, fmt);
	str = talloc_vasprintf(NULL, fmt, arglist);
	va_end(arglist);
	write(tracefd, str, strlen(str));
	talloc_free(str);
}

static bool write_message(struct connection *conn)
{
	int ret;
	struct buffered_data *out = conn->out;

	if (out->inhdr) {
		if (verbose)
			xprintf("Writing msg %s (%s) out to %p\n",
				sockmsg_string(out->hdr.msg.type),
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

	trace_io(conn, "OUT", out);
	conn->out = NULL;
	talloc_free(out);

	queue_next_event(conn);
	return true;
}

static int destroy_conn(void *_conn)
{
	struct connection *conn = _conn;

	/* Flush outgoing if possible, but don't block. */
	if (!conn->domain) {
		fd_set set;
		struct timeval none;

		FD_ZERO(&set);
		FD_SET(conn->fd, &set);
		none.tv_sec = none.tv_usec = 0;

		while (conn->out
		       && select(conn->fd+1, NULL, &set, NULL, &none) == 1)
			if (!write_message(conn))
				break;
		close(conn->fd);
	}
	list_del(&conn->list);
	trace_destroy(conn, "connection");
	return 0;
}

static int initialize_set(fd_set *inset, fd_set *outset, int sock, int ro_sock,
			  int event_fd)
{
	struct connection *i;
	int max;

	FD_ZERO(inset);
	FD_ZERO(outset);
	FD_SET(sock, inset);
	max = sock;
	FD_SET(ro_sock, inset);
	if (ro_sock > max)
		max = ro_sock;
	FD_SET(event_fd, inset);
	if (event_fd > max)
		max = event_fd;
	list_for_each_entry(i, &connections, list) {
		if (i->domain)
			continue;
		if (i->state == OK)
			FD_SET(i->fd, inset);
		if (i->out)
			FD_SET(i->fd, outset);
		if (i->fd > max)
			max = i->fd;
	}
	return max;
}

/* Read everything from a talloc_open'ed fd. */
void *read_all(int *fd, unsigned int *size)
{
	unsigned int max = 4;
	int ret;
	void *buffer = talloc_size(fd, max);

	*size = 0;
	while ((ret = read(*fd, buffer + *size, max - *size)) > 0) {
		*size += ret;
		if (*size == max)
			buffer = talloc_realloc_size(fd, buffer, max *= 2);
	}
	if (ret < 0)
		return NULL;
	return buffer;
}

static int destroy_fd(void *_fd)
{
	int *fd = _fd;
	close(*fd);
	return 0;
}

/* Return a pointer to an fd, self-closing and attached to this pathname. */
int *talloc_open(const char *pathname, int flags, int mode)
{
	int *fd;

	fd = talloc(pathname, int);
	*fd = open(pathname, flags, mode);
	if (*fd < 0) {
		int saved_errno = errno;
		talloc_free(fd);
		errno = saved_errno;
		return NULL;
	}
	talloc_set_destructor(fd, destroy_fd);
	return fd;
}

/* Is child a subnode of parent, or equal? */
bool is_child(const char *child, const char *parent)
{
	unsigned int len = strlen(parent);

	/* / should really be "" for this algorithm to work, but that's a
	 * usability nightmare. */
	if (streq(parent, "/"))
		return true;

	if (strncmp(child, parent, len) != 0)
		return false;

	return child[len] == '/' || child[len] == '\0';
}

/* Answer never ends in /. */
char *node_dir_outside_transaction(const char *node)
{
	if (streq(node, "/"))
		return talloc_strdup(node, xs_daemon_store());
	return talloc_asprintf(node, "%s%s", xs_daemon_store(), node);
}

static char *node_dir(struct transaction *trans, const char *node)
{
	if (!trans || !within_transaction(trans, node))
		return node_dir_outside_transaction(node);
	return node_dir_inside_transaction(trans, node);
}

static char *node_datafile(struct transaction *trans, const char *node)
{
	return talloc_asprintf(node, "%s/.data", node_dir(trans, node));
}

static char *node_permfile(struct transaction *trans, const char *node)
{
	return talloc_asprintf(node, "%s/.perms", node_dir(trans, node));
}

struct buffered_data *new_buffer(void *ctx)
{
	struct buffered_data *data;

	data = talloc(ctx, struct buffered_data);
	data->inhdr = true;
	data->used = 0;
	data->buffer = NULL;

	return data;
}

/* Return length of string (including nul) at this offset. */
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

/* Break input into vectors, return the number, fill in up to num of them. */
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

void send_reply(struct connection *conn, enum xsd_sockmsg_type type,
		const void *data, unsigned int len)
{
	struct buffered_data *bdata;

	/* When data gets freed, we want list entry is destroyed (so
	 * list entry is a child). */
	bdata = new_buffer(conn);
	bdata->buffer = talloc_array(bdata, char, len);

	bdata->hdr.msg.type = type;
	bdata->hdr.msg.len = len;
	memcpy(bdata->buffer, data, len);

	/* There might be an event going out now.  Queue behind it. */
	if (conn->out) {
		assert(conn->out->hdr.msg.type == XS_WATCH_EVENT);
		assert(!conn->waiting_reply);
		conn->waiting_reply = bdata;
	} else
		conn->out = bdata;
}

/* Some routines (write, mkdir, etc) just need a non-error return */
void send_ack(struct connection *conn, enum xsd_sockmsg_type type)
{
	send_reply(conn, type, "OK", sizeof("OK"));
}

void send_error(struct connection *conn, int error)
{
	unsigned int i;

	for (i = 0; error != xsd_errors[i].errnum; i++) {
		if (i == ARRAY_SIZE(xsd_errors) - 1) {
			eprintf("xenstored: error %i untranslatable", error);
			i = 0; 	/* EINVAL */
			break;
		}
	}
	send_reply(conn, XS_ERROR, xsd_errors[i].errstring,
			  strlen(xsd_errors[i].errstring) + 1);
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
	/* Must start in /. */
	if (!strstarts(node, "/"))
		return false;

	/* Cannot end in / (unless it's just "/"). */
	if (strends(node, "/") && !streq(node, "/"))
		return false;

	/* No double //. */
	if (strstr(node, "//"))
		return false;

	return valid_chars(node);
}

/* We expect one arg in the input: return NULL otherwise. */
static const char *onearg(struct buffered_data *in)
{
	if (get_string(in, 0) != in->used)
		return NULL;
	return in->buffer;
}

/* If it fails, returns NULL and sets errno. */
static struct xs_permissions *get_perms(struct transaction *transaction,
					const char *node, unsigned int *num)
{
	unsigned int size;
	char *strings;
	struct xs_permissions *ret;
	int *fd;

	fd = talloc_open(node_permfile(transaction, node), O_RDONLY, 0);
	if (!fd)
		return NULL;
	strings = read_all(fd, &size);
	if (!strings)
		return NULL;

	*num = xs_count_strings(strings, size);
	ret = talloc_array(node, struct xs_permissions, *num);
	if (!xs_strings_to_perms(ret, *num, strings))
		corrupt(NULL, "Permissions corrupt for %s", node);

	return ret;
}

static char *perms_to_strings(const char *node,
			      struct xs_permissions *perms, unsigned int num,
			      unsigned int *len)
{
	unsigned int i;
	char *strings = NULL;
	char buffer[MAX_STRLEN(domid_t) + 1];

	for (*len = 0, i = 0; i < num; i++) {
		if (!xs_perm_to_string(&perms[i], buffer))
			return NULL;

		strings = talloc_realloc(node, strings, char,
					 *len + strlen(buffer) + 1);
		strcpy(strings + *len, buffer);
		*len += strlen(buffer) + 1;
	}
	return strings;
}

/* Destroy this, and its children, and its children's children. */
int destroy_path(void *path)
{
	DIR *dir;
	struct dirent *dirent;

	dir = opendir(path);
	if (!dir) {
		if (unlink(path) == 0 || errno == ENOENT)
			return 0;
		corrupt(NULL, "Destroying path %s", path);
	}

	while ((dirent = readdir(dir)) != NULL) {
		char fullpath[strlen(path) + 1 + strlen(dirent->d_name) + 1];
		sprintf(fullpath, "%s/%s", (char *)path, dirent->d_name);
		if (!streq(dirent->d_name,".") && !streq(dirent->d_name,".."))
			destroy_path(fullpath);
	}
	closedir(dir);
	if (rmdir(path) != 0)
		corrupt(NULL, "Destroying directory %s", path);
	return 0;
}

/* Create a self-destructing temporary file */
static char *tempfile(const char *path, void *contents, unsigned int len)
{
	int *fd;
	char *tmppath = talloc_asprintf(path, "%s.tmp", path);

	fd = talloc_open(tmppath, O_WRONLY|O_CREAT|O_EXCL, 0640);
	if (!fd)
		return NULL;
	talloc_set_destructor(tmppath, destroy_path);
	if (!xs_write_all(*fd, contents, len))
		return NULL;

	return tmppath;
}

static int destroy_opendir(void *_dir)
{
	DIR **dir = _dir;
	closedir(*dir);
	return 0;
}

/* Return a pointer to a DIR*, self-closing and attached to this pathname. */
DIR **talloc_opendir(const char *pathname)
{
	DIR **dir;

	dir = talloc(pathname, DIR *);
	*dir = opendir(pathname);
	if (!*dir) {
		int saved_errno = errno;
		talloc_free(dir);
		errno = saved_errno;
		return NULL;
	}
	talloc_set_destructor(dir, destroy_opendir);
	return dir;
}

/* We assume rename() doesn't fail on moves in same dir. */
static void commit_tempfile(const char *path)
{
	char realname[strlen(path) + 1];
	unsigned int len = strrchr(path, '.') - path;

	memcpy(realname, path, len);
	realname[len] = '\0';
	if (rename(path, realname) != 0)
		corrupt(NULL, "Committing %s", realname);
	talloc_set_destructor(path, NULL);
}

static bool set_perms(struct transaction *transaction,
		      const char *node,
		      struct xs_permissions *perms, unsigned int num)
{
	unsigned int len;
	char *permpath, *strings;

	strings = perms_to_strings(node, perms, num, &len);
	if (!strings)
		return false;

	/* Create then move. */
	permpath = tempfile(node_permfile(transaction, node), strings, len);
	if (!permpath)
		return false;

	commit_tempfile(permpath);
	return true;
}

static char *get_parent(const char *node)
{
	char *slash = strrchr(node + 1, '/');
	if (!slash)
		return talloc_strdup(node, "/");
	return talloc_asprintf(node, "%.*s", slash - node, node);
}

static enum xs_perm_type perm_for_id(domid_t id,
				     struct xs_permissions *perms,
				     unsigned int num)
{
	unsigned int i;

	/* Owners and tools get it all... */
	if (!id || perms[0].id == id)
		return XS_PERM_READ|XS_PERM_WRITE|XS_PERM_OWNER;

	for (i = 1; i < num; i++)
		if (perms[i].id == id)
			return perms[i].perms;

	return perms[0].perms;
}

/* What do parents say? */
static enum xs_perm_type ask_parents(struct connection *conn,
				     const char *node)
{
	struct xs_permissions *perms;
	unsigned int num;

	do {
		node = get_parent(node);
		perms = get_perms(conn->transaction, node, &num);
		if (perms)
			break;
	} while (!streq(node, "/"));

	/* No permission at root?  We're in trouble. */
	if (!perms)
		corrupt(conn, "No permissions file at root");

	return perm_for_id(conn->id, perms, num);
}

/* We have a weird permissions system.  You can allow someone into a
 * specific node without allowing it in the parents.  If it's going to
 * fail, however, we don't want the errno to indicate any information
 * about the node. */
static int errno_from_parents(struct connection *conn, const char *node,
			      int errnum)
{
	/* We always tell them about memory failures. */
	if (errnum == ENOMEM)
		return errnum;

	if (ask_parents(conn, node) & XS_PERM_READ)
		return errnum;
	return EACCES;
}

char *canonicalize(struct connection *conn, const char *node)
{
	const char *prefix;

	if (!node || strstarts(node, "/"))
		return (char *)node;
	prefix = get_implicit_path(conn);
	if (prefix)
		return talloc_asprintf(node, "%s/%s", prefix, node);
	return (char *)node;
}

bool check_node_perms(struct connection *conn, const char *node,
		      enum xs_perm_type perm)
{
	struct xs_permissions *perms;
	unsigned int num;

	if (!node || !is_valid_nodename(node)) {
		errno = EINVAL;
		return false;
	}

	if (!conn->can_write && (perm & XS_PERM_WRITE)) {
		errno = EROFS;
		return false;
	}

	perms = get_perms(conn->transaction, node, &num);

	if (perms) {
		if (perm_for_id(conn->id, perms, num) & perm)
			return true;
		errno = EACCES;
		return false;
	}

	/* If it's OK not to exist, we consult parents. */
	if (errno == ENOENT && (perm & XS_PERM_ENOENT_OK)) {
		if (ask_parents(conn, node) & perm)
			return true;
		/* Parents say they should not know. */
		errno = EACCES;
		return false;
	}

	/* They might not have permission to even *see* this node, in
	 * which case we return EACCES even if it's ENOENT or EIO. */
	errno = errno_from_parents(conn, node, errno);
	return false;
}

static void send_directory(struct connection *conn, const char *node)
{
	char *path, *reply = talloc_strdup(node, "");
	unsigned int reply_len = 0;
	DIR **dir;
	struct dirent *dirent;

	node = canonicalize(conn, node);
	if (!check_node_perms(conn, node, XS_PERM_READ)) {
		send_error(conn, errno);
		return;
	}

	path = node_dir(conn->transaction, node);
	dir = talloc_opendir(path);
	if (!dir) {
		send_error(conn, errno);
		return;
	}

	while ((dirent = readdir(*dir)) != NULL) {
		int len = strlen(dirent->d_name) + 1;

		if (!valid_chars(dirent->d_name))
			continue;

		reply = talloc_realloc(path, reply, char, reply_len + len);
		strcpy(reply + reply_len, dirent->d_name);
		reply_len += len;
	}

	send_reply(conn, XS_DIRECTORY, reply, reply_len);
}

static void do_read(struct connection *conn, const char *node)
{
	char *value;
	unsigned int size;
	int *fd;

	node = canonicalize(conn, node);
	if (!check_node_perms(conn, node, XS_PERM_READ)) {
		send_error(conn, errno);
		return;
	}

	fd = talloc_open(node_datafile(conn->transaction, node), O_RDONLY, 0);
	if (!fd) {
		/* Data file doesn't exist?  We call that a directory */
		if (errno == ENOENT)
			errno = EISDIR;
		send_error(conn, errno);
		return;
	}

	value = read_all(fd, &size);
	if (!value)
		send_error(conn, errno);
	else
		send_reply(conn, XS_READ, value, size);
}

/* Create a new directory.  Optionally put data in it (if data != NULL) */
static bool new_directory(struct connection *conn,
			  const char *node, void *data, unsigned int datalen)
{
	struct xs_permissions *perms;
	char *permstr;
	unsigned int num, len;
	int *fd;
	char *dir = node_dir(conn->transaction, node);

	if (mkdir(dir, 0750) != 0)
		return false;

	/* Set destructor so we clean up if neccesary. */
	talloc_set_destructor(dir, destroy_path);

	perms = get_perms(conn->transaction, get_parent(node), &num);
	/* Domains own what they create. */
	if (conn->id)
		perms->id = conn->id;

	permstr = perms_to_strings(dir, perms, num, &len);
	fd = talloc_open(node_permfile(conn->transaction, node),
			 O_WRONLY|O_CREAT|O_EXCL, 0640);
	if (!fd || !xs_write_all(*fd, permstr, len))
		return false;

	if (data) {
		char *datapath = node_datafile(conn->transaction, node);

		fd = talloc_open(datapath, O_WRONLY|O_CREAT|O_EXCL, 0640);
		if (!fd || !xs_write_all(*fd, data, datalen))
			return false;
	}

	/* Finished! */
	talloc_set_destructor(dir, NULL);
	return true;
}

/* path, flags, data... */
static void do_write(struct connection *conn, struct buffered_data *in)
{
	unsigned int offset, datalen;
	char *vec[2];
	char *node, *tmppath;
	enum xs_perm_type mode;
	struct stat st;

	/* Extra "strings" can be created by binary data. */
	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec)) {
		send_error(conn, EINVAL);
		return;
	}

	node = canonicalize(conn, vec[0]);
	if (/*suppress error on write outside transaction*/ 0 &&
	    !within_transaction(conn->transaction, node)) {
		send_error(conn, EROFS);
		return;
	}

	if (transaction_block(conn, node))
		return;

	offset = strlen(vec[0]) + strlen(vec[1]) + 2;
	datalen = in->used - offset;

	if (streq(vec[1], XS_WRITE_NONE))
		mode = XS_PERM_WRITE;
	else if (streq(vec[1], XS_WRITE_CREATE))
		mode = XS_PERM_WRITE|XS_PERM_ENOENT_OK;
	else if (streq(vec[1], XS_WRITE_CREATE_EXCL))
		mode = XS_PERM_WRITE|XS_PERM_ENOENT_OK;
	else {
		send_error(conn, EINVAL);
		return;
	}

	if (!check_node_perms(conn, node, mode)) {
		send_error(conn, errno);
		return;
	}

	if (lstat(node_dir(conn->transaction, node), &st) != 0) {
		/* Does not exist... */
		if (errno != ENOENT) {
			send_error(conn, errno);
			return;
		}

		/* Not going to create it? */
		if (streq(vec[1], XS_WRITE_NONE)) {
			send_error(conn, ENOENT);
			return;
		}

		if (!new_directory(conn, node, in->buffer + offset, datalen)) {
			send_error(conn, errno);
			return;
		}
	} else {
		/* Exists... */
		if (streq(vec[1], XS_WRITE_CREATE_EXCL)) {
			send_error(conn, EEXIST);
			return;
		}

		tmppath = tempfile(node_datafile(conn->transaction, node),
				   in->buffer + offset, datalen);
		if (!tmppath) {
			send_error(conn, errno);
			return;
		}

		commit_tempfile(tmppath);
	}

	add_change_node(conn->transaction, node, false);
	fire_watches(conn, node, false);
	send_ack(conn, XS_WRITE);
}

static void do_mkdir(struct connection *conn, const char *node)
{
	node = canonicalize(conn, node);
	if (!check_node_perms(conn, node, XS_PERM_WRITE|XS_PERM_ENOENT_OK)) {
		send_error(conn, errno);
		return;
	}

	if (!within_transaction(conn->transaction, node)) {
		send_error(conn, EROFS);
		return;
	}

	if (transaction_block(conn, node))
		return;

	if (!new_directory(conn, node, NULL, 0)) {
		send_error(conn, errno);
		return;
	}

	add_change_node(conn->transaction, node, false);
	fire_watches(conn, node, false);
	send_ack(conn, XS_MKDIR);
}

static void do_rm(struct connection *conn, const char *node)
{
	char *tmppath, *path;

	node = canonicalize(conn, node);
	if (!check_node_perms(conn, node, XS_PERM_WRITE)) {
		send_error(conn, errno);
		return;
	}

	if (!within_transaction(conn->transaction, node)) {
		send_error(conn, EROFS);
		return;
	}

	if (transaction_block(conn, node))
		return;

	if (streq(node, "/")) {
		send_error(conn, EINVAL);
		return;
	}

	/* We move the directory to temporary name, destructor cleans up. */
	path = node_dir(conn->transaction, node);
	tmppath = talloc_asprintf(node, "%s.tmp", path);
	talloc_set_destructor(tmppath, destroy_path);

	if (rename(path, tmppath) != 0) {
		send_error(conn, errno);
		return;
	}

	add_change_node(conn->transaction, node, true);
	fire_watches(conn, node, true);
	send_ack(conn, XS_RM);
}

static void do_get_perms(struct connection *conn, const char *node)
{
	struct xs_permissions *perms;
	char *strings;
	unsigned int len, num;

	node = canonicalize(conn, node);
	if (!check_node_perms(conn, node, XS_PERM_READ)) {
		send_error(conn, errno);
		return;
	}

	perms = get_perms(conn->transaction, node, &num);
	if (!perms) {
		send_error(conn, errno);
		return;
	}

	strings = perms_to_strings(node, perms, num, &len);
	if (!strings)
		send_error(conn, errno);
	else
		send_reply(conn, XS_GET_PERMS, strings, len);
}

static void do_set_perms(struct connection *conn, struct buffered_data *in)
{
	unsigned int num;
	char *node;
	struct xs_permissions *perms;

	num = xs_count_strings(in->buffer, in->used);
	if (num < 2) {
		send_error(conn, EINVAL);
		return;
	}

	/* First arg is node name. */
	node = canonicalize(conn, in->buffer);
	in->buffer += strlen(in->buffer) + 1;
	num--;

	if (!within_transaction(conn->transaction, node)) {
		send_error(conn, EROFS);
		return;
	}

	if (transaction_block(conn, node))
		return;

	/* We must own node to do this (tools can do this too). */
	if (!check_node_perms(conn, node, XS_PERM_WRITE|XS_PERM_OWNER)) {
		send_error(conn, errno);
		return;
	}

	perms = talloc_array(node, struct xs_permissions, num);
	if (!xs_strings_to_perms(perms, num, in->buffer)) {
		send_error(conn, errno);
		return;
	}

	if (!set_perms(conn->transaction, node, perms, num)) {
		send_error(conn, errno);
		return;
	}

	add_change_node(conn->transaction, node, false);
	fire_watches(conn, node, false);
	send_ack(conn, XS_SET_PERMS);
}

/* Process "in" for conn: "in" will vanish after this conversation, so
 * we can talloc off it for temporary variables.  May free "conn".
 */
static void process_message(struct connection *conn, struct buffered_data *in)
{
	switch (in->hdr.msg.type) {
	case XS_DIRECTORY:
		send_directory(conn, onearg(in));
		break;

	case XS_READ:
		do_read(conn, onearg(in));
		break;

	case XS_WRITE:
		do_write(conn, in);
		break;

	case XS_MKDIR:
		do_mkdir(conn, onearg(in));
		break;

	case XS_RM:
		do_rm(conn, onearg(in));
		break;

	case XS_GET_PERMS:
		do_get_perms(conn, onearg(in));
		break;

	case XS_SET_PERMS:
		do_set_perms(conn, in);
		break;

	case XS_SHUTDOWN:
		/* FIXME: Implement gentle shutdown too. */
		/* Only tools can do this. */
		if (conn->id != 0) {
			send_error(conn, EACCES);
			break;
		}
		if (!conn->can_write) {
			send_error(conn, EROFS);
			break;
		}
		send_ack(conn, XS_SHUTDOWN);
		/* Everything hangs off auto-free context, freed at exit. */
		exit(0);

	case XS_DEBUG:
		if (streq(in->buffer, "print"))
			xprintf("debug: %s", in->buffer + get_string(in, 0));
#ifdef TESTING
		/* For testing, we allow them to set id. */
		if (streq(in->buffer, "setid")) {
			conn->id = atoi(in->buffer + get_string(in, 0));
			send_ack(conn, XS_DEBUG);
		} else if (streq(in->buffer, "failtest")) {
			if (get_string(in, 0) < in->used)
				srandom(atoi(in->buffer + get_string(in, 0)));
			send_ack(conn, XS_DEBUG);
			failtest = true;
		}
#endif /* TESTING */
		break;

	case XS_WATCH:
		do_watch(conn, in);
		break;

	case XS_WATCH_ACK:
		do_watch_ack(conn, onearg(in));
		break;

	case XS_UNWATCH:
		do_unwatch(conn, in);
		break;

	case XS_TRANSACTION_START:
		do_transaction_start(conn, onearg(in));
		break;

	case XS_TRANSACTION_END:
		do_transaction_end(conn, onearg(in));
		break;

	case XS_INTRODUCE:
		do_introduce(conn, in);
		break;

	case XS_RELEASE:
		do_release(conn, onearg(in));
		break;

	case XS_GETDOMAINPATH:
		do_get_domain_path(conn, onearg(in));
		break;

	case XS_WATCH_EVENT:
	default:
		eprintf("Client unknown operation %i", in->hdr.msg.type);
		send_error(conn, ENOSYS);
	}
}

static int out_of_mem(void *data)
{
	longjmp(*(jmp_buf *)data, 1);
}

static void consider_message(struct connection *conn)
{
	struct buffered_data *in = NULL;
	enum xsd_sockmsg_type type = conn->in->hdr.msg.type;
	jmp_buf talloc_fail;

	assert(conn->state == OK);

	/* For simplicity, we kill the connection on OOM. */
	talloc_set_fail_handler(out_of_mem, &talloc_fail);
	if (setjmp(talloc_fail)) {
		talloc_free(conn);
		goto end;
	}

	if (verbose)
		xprintf("Got message %s len %i from %p\n",
			sockmsg_string(type), conn->in->hdr.msg.len, conn);

	/* We might get a command while waiting for an ack: this means
	 * the other end discarded it: we will re-transmit. */
	if (type != XS_WATCH_ACK)
		conn->waiting_for_ack = NULL;

	/* Careful: process_message may free connection.  We detach
	 * "in" beforehand and allocate the new buffer to avoid
	 * touching conn after process_message.
	 */
	in = talloc_steal(talloc_autofree_context(), conn->in);
	conn->in = new_buffer(conn);
	process_message(conn, in);

	if (conn->state == BLOCKED) {
		/* Blocked by transaction: queue for re-xmit. */
		talloc_free(conn->in);
		conn->in = in;
		in = NULL;
		trace_blocked(conn, conn->in);
	}

end:
	talloc_free(in);
	talloc_set_fail_handler(NULL, NULL);
	if (talloc_total_blocks(NULL)
	    != talloc_total_blocks(talloc_autofree_context()) + 1)
		talloc_report_full(NULL, stderr);
}

/* Errors in reading or allocating here mean we get out of sync, so we
 * drop the whole client connection. */
void handle_input(struct connection *conn)
{
	int bytes;
	struct buffered_data *in;

	assert(conn->state == OK);
	in = conn->in;

	/* Not finished header yet? */
	if (in->inhdr) {
		bytes = conn->read(conn, in->hdr.raw + in->used,
				   sizeof(in->hdr) - in->used);
		if (bytes <= 0)
			goto bad_client;
		in->used += bytes;
		if (in->used != sizeof(in->hdr))
			return;

		if (in->hdr.msg.len > PATH_MAX) {
			syslog(LOG_DAEMON, "Client tried to feed us %i",
			       in->hdr.msg.len);
			goto bad_client;
		}

		in->buffer = talloc_array(in, char, in->hdr.msg.len);
		if (!in->buffer)
			goto bad_client;
		in->used = 0;
		in->inhdr = false;
		return;
	}

	bytes = conn->read(conn, in->buffer + in->used,
			   in->hdr.msg.len - in->used);
	if (bytes < 0)
		goto bad_client;

	in->used += bytes;
	if (in->used != in->hdr.msg.len)
		return;

	trace_io(conn, "IN ", in);
	consider_message(conn);
	return;

bad_client:
	/* Kill it. */
	talloc_free(conn);
}

void handle_output(struct connection *conn)
{
	if (!write_message(conn))
		talloc_free(conn);
}

/* If a transaction has ended, see if we can unblock any connections. */
static void unblock_connections(void)
{
	struct connection *i, *tmp;

	list_for_each_entry_safe(i, tmp, &connections, list) {
		switch (i->state) {
		case BLOCKED:
			if (!transaction_covering_node(i->blocked_by)) {
				talloc_free(i->blocked_by);
				i->blocked_by = NULL;
				i->state = OK;
				consider_message(i);
			}
			break;
		case OK:
			break;
		}
	}

	/* To balance bias, move first entry to end. */
	if (!list_empty(&connections)) {
		i = list_top(&connections, struct connection, list);
		list_del(&i->list);
		list_add_tail(&i->list, &connections);
	}
}

struct connection *new_connection(connwritefn_t *write, connreadfn_t *read)
{
	struct connection *new;
	jmp_buf talloc_fail;

	new = talloc(talloc_autofree_context(), struct connection);
	if (!new)
		return NULL;

	new->state = OK;
	new->blocked_by = NULL;
	new->out = new->waiting_reply = NULL;
	new->fd = -1;
	new->id = 0;
	new->domain = NULL;
	new->transaction = NULL;
	new->write = write;
	new->read = read;
	new->can_write = true;
	INIT_LIST_HEAD(&new->watches);

	talloc_set_fail_handler(out_of_mem, &talloc_fail);
	if (setjmp(talloc_fail)) {
		talloc_free(new);
		return NULL;
	}
	new->in = new_buffer(new);
	talloc_set_fail_handler(NULL, NULL);

	list_add_tail(&new->list, &connections);
	talloc_set_destructor(new, destroy_conn);
	trace_create(new, "connection");
	return new;
}

static int writefd(struct connection *conn, const void *data, unsigned int len)
{
	return write(conn->fd, data, len);
}

static int readfd(struct connection *conn, void *data, unsigned int len)
{
	return read(conn->fd, data, len);
}

static void accept_connection(int sock, bool canwrite)
{
	int fd;
	struct connection *conn;

	fd = accept(sock, NULL, NULL);
	if (fd < 0)
		return;

	conn = new_connection(writefd, readfd);
	if (conn) {
		conn->fd = fd;
		conn->can_write = canwrite;
	} else
		close(fd);
}

/* Calc timespan from now to absolute time. */
static void time_relative_to_now(struct timeval *tv)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	if (timercmp(&now, tv, >))
		timerclear(tv);
	else {
		tv->tv_sec -= now.tv_sec;
		if (now.tv_usec > tv->tv_usec) {
			tv->tv_sec--;
			tv->tv_usec += 1000000;
		}
		tv->tv_usec -= now.tv_usec;
	}
}

#ifdef TESTING
/* Useful for running under debugger. */
void dump_connection(void)
{
	struct connection *i;

	list_for_each_entry(i, &connections, list) {
		printf("Connection %p:\n", i);
		printf("    state = %s\n",
		       i->state == OK ? "OK"
		       : i->state == BLOCKED ? "BLOCKED"
		       : "INVALID");
		if (i->id)
			printf("    id = %i\n", i->id);
		if (i->blocked_by)
			printf("    blocked on = %s\n", i->blocked_by);
		if (!i->in->inhdr || i->in->used)
			printf("    got %i bytes of %s\n",
			       i->in->used, i->in->inhdr ? "header" : "data");
		if (i->out)
			printf("    sending message %s (%s) out\n",
			       sockmsg_string(i->out->hdr.msg.type),
			       i->out->buffer);
		if (i->waiting_reply)
			printf("    ... and behind is queued %s (%s)\n",
			       sockmsg_string(i->waiting_reply->hdr.msg.type),
			       i->waiting_reply->buffer);
#if 0
		if (i->transaction)
			dump_transaction(i);
		if (i->domain)
			dump_domain(i);
#endif
		dump_watches(i);
	}
}
#endif

static void setup_structure(void)
{
	struct xs_permissions perms = { .id = 0, .perms = XS_PERM_READ };
	char *root, *dir, *permfile;

	/* Create root directory, with permissions. */
	if (mkdir(xs_daemon_store(), 0750) != 0) {
		if (errno != EEXIST)
			barf_perror("Could not create root %s",
				    xs_daemon_store());
		return;
	}
	root = talloc_strdup(talloc_autofree_context(), "/");
	if (!set_perms(NULL, root, &perms, 1))
		barf_perror("Could not create permissions in root");

	/* Create tool directory, with xenstored subdir. */
	dir = talloc_asprintf(root, "%s/%s", xs_daemon_store(), "tool");
	if (mkdir(dir, 0750) != 0)
		barf_perror("Making dir %s", dir);
	
	permfile = talloc_strdup(root, "/tool");
	if (!set_perms(NULL, permfile, &perms, 1))
		barf_perror("Could not create permissions on %s", permfile);

	dir = talloc_asprintf(root, "%s/%s", dir, "xenstored");
	if (mkdir(dir, 0750) != 0)
		barf_perror("Making dir %s", dir);
	
	permfile = talloc_strdup(root, "/tool/xenstored");
	if (!set_perms(NULL, permfile, &perms, 1))
		barf_perror("Could not create permissions on %s", permfile);
	talloc_free(root);
	if (mkdir(xs_daemon_transactions(), 0750) != 0)
		barf_perror("Could not create transaction dir %s",
			    xs_daemon_transactions());
}

static struct option options[] = { { "no-fork", 0, NULL, 'N' },
				   { "verbose", 0, NULL, 'V' },
				   { "output-pid", 0, NULL, 'P' },
				   { "trace-file", 1, NULL, 'T' },
				   { NULL, 0, NULL, 0 } };

int main(int argc, char *argv[])
{
	int opt, *sock, *ro_sock, event_fd, max, tmpout;
	struct sockaddr_un addr;
	fd_set inset, outset;
	bool dofork = true;
	bool outputpid = false;

	while ((opt = getopt_long(argc, argv, "DVT:", options, NULL)) != -1) {
		switch (opt) {
		case 'N':
			dofork = false;
			break;
		case 'V':
			verbose = true;
			break;
		case 'P':
			outputpid = true;
			break;
		case 'T':
			tracefd = open(optarg, O_WRONLY|O_CREAT|O_APPEND, 0600);
			if (tracefd < 0)
				barf_perror("Could not open tracefile %s",
					    optarg);
                        write(tracefd, "\n***\n", strlen("\n***\n"));
			break;
		}
	}
	if (optind != argc)
		barf("%s: No arguments desired", argv[0]);

	talloc_enable_leak_report_full();

	/* Create sockets for them to listen to. */
	sock = talloc(talloc_autofree_context(), int);
	*sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (*sock < 0)
		barf_perror("Could not create socket");
	ro_sock = talloc(talloc_autofree_context(), int);
	*ro_sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (*ro_sock < 0)
		barf_perror("Could not create socket");
	talloc_set_destructor(sock, destroy_fd);
	talloc_set_destructor(ro_sock, destroy_fd);

	/* Don't kill us with SIGPIPE. */
	signal(SIGPIPE, SIG_IGN);

	/* FIXME: Be more sophisticated, don't mug running daemon. */
	unlink(xs_daemon_socket());
	unlink(xs_daemon_socket_ro());

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, xs_daemon_socket());
	if (bind(*sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		barf_perror("Could not bind socket to %s", xs_daemon_socket());
	strcpy(addr.sun_path, xs_daemon_socket_ro());
	if (bind(*ro_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		barf_perror("Could not bind socket to %s",
			    xs_daemon_socket_ro());
	if (chmod(xs_daemon_socket(), 0600) != 0
	    || chmod(xs_daemon_socket_ro(), 0660) != 0)
		barf_perror("Could not chmod sockets");

	if (listen(*sock, 1) != 0
	    || listen(*ro_sock, 1) != 0)
		barf_perror("Could not listen on sockets");

	/* If we're the first, create .perms file for root. */
	setup_structure();

	/* Listen to hypervisor. */
	event_fd = domain_init();

	/* Restore existing connections. */
	restore_existing_connections();

	/* Debugging: daemonize() closes standard fds, so dup here. */
	tmpout = dup(STDOUT_FILENO);
	if (dofork) {
		openlog("xenstored", 0, LOG_DAEMON);
		daemonize();
	}

	if (outputpid) {
		char buffer[20];
		sprintf(buffer, "%i\n", getpid());
		write(tmpout, buffer, strlen(buffer));
	}
	close(tmpout);

#ifdef TESTING
	signal(SIGUSR1, stop_failtest);
#endif

	/* Get ready to listen to the tools. */
	max = initialize_set(&inset, &outset, *sock, *ro_sock, event_fd);

	/* Main loop. */
	for (;;) {
		struct connection *i;
		struct timeval *tvp = NULL, tv;

		timerclear(&tv);
		shortest_transaction_timeout(&tv);
		shortest_watch_ack_timeout(&tv);
		if (timerisset(&tv)) {
			time_relative_to_now(&tv);
			tvp = &tv;
		}

		if (select(max+1, &inset, &outset, NULL, tvp) < 0) {
			if (errno == EINTR)
				continue;
			barf_perror("Select failed");
		}

		if (FD_ISSET(*sock, &inset))
			accept_connection(*sock, true);

		if (FD_ISSET(*ro_sock, &inset))
			accept_connection(*ro_sock, false);

		if (FD_ISSET(event_fd, &inset))
			handle_event(event_fd);

		list_for_each_entry(i, &connections, list) {
			if (i->domain)
				continue;

			/* Operations can delete themselves or others
			 * (xs_release): list is not safe after input,
			 * so break. */
			if (FD_ISSET(i->fd, &inset)) {
				handle_input(i);
				break;
			}
			if (FD_ISSET(i->fd, &outset)) {
				handle_output(i);
				break;
			}
		}

		/* Flush output for domain connections,  */
		list_for_each_entry(i, &connections, list)
			if (i->domain && i->out)
				handle_output(i);

		if (tvp) {
			check_transaction_timeout();
			check_watch_ack_timeout();
		}

		/* If transactions ended, we might be able to do more work. */
		unblock_connections();

		max = initialize_set(&inset, &outset, *sock,*ro_sock,event_fd);
	}
}
