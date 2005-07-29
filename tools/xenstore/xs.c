/* 
    Xen Store Daemon interface providing simple tree-like database.
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
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include "xs.h"
#include "xenstored.h"
#include "xs_lib.h"
#include "utils.h"

struct xs_handle
{
	int fd;
};

/* Get the socket from the store daemon handle.
 */
int xs_fileno(struct xs_handle *h)
{
	return h->fd;
}

static struct xs_handle *get_socket(const char *connect_to)
{
	struct sockaddr_un addr;
	int sock, saved_errno;
	struct xs_handle *h = NULL;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return NULL;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, connect_to);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		h = malloc(sizeof(*h));
		if (h) {
			h->fd = sock;
			return h;
		}
	}

	saved_errno = errno;
	close(sock);
	free(h);
	errno = saved_errno;
	return NULL;
}

struct xs_handle *xs_daemon_open(void)
{
	return get_socket(xs_daemon_socket());
}

struct xs_handle *xs_daemon_open_readonly(void)
{
	return get_socket(xs_daemon_socket_ro());
}

void xs_daemon_close(struct xs_handle *h)
{
	if (h->fd >= 0)
		close(h->fd);
	free(h);
}

static bool read_all(int fd, void *data, unsigned int len)
{
	while (len) {
		int done;

		done = read(fd, data, len);
		if (done < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		if (done == 0) {
			/* It closed fd on us?  EBADF is appropriate. */
			errno = EBADF;
			return false;
		}
		data += done;
		len -= done;
	}

	return true;
}

#ifdef XSTEST
#define read_all read_all_choice
#define xs_write_all write_all_choice
#endif

static int get_error(const char *errorstring)
{
	unsigned int i;

	for (i = 0; !streq(errorstring, xsd_errors[i].errstring); i++)
		if (i == ARRAY_SIZE(xsd_errors) - 1)
			return EINVAL;
	return xsd_errors[i].errnum;
}

/* Adds extra nul terminator, because we generally (always?) hold strings. */
static void *read_reply(int fd, enum xsd_sockmsg_type *type, unsigned int *len)
{
	struct xsd_sockmsg msg;
	void *ret;
	int saved_errno;

	if (!read_all(fd, &msg, sizeof(msg)))
		return NULL;

	ret = malloc(msg.len + 1);
	if (!ret)
		return NULL;

	if (!read_all(fd, ret, msg.len)) {
		saved_errno = errno;
		free(ret);
		errno = saved_errno;
		return NULL;
	}

	*type = msg.type;
	if (len)
		*len = msg.len;
	((char *)ret)[msg.len] = '\0';
	return ret;
}

/* Send message to xs, get malloc'ed reply.  NULL and set errno on error. */
static void *xs_talkv(struct xs_handle *h, enum xsd_sockmsg_type type,
		      const struct iovec *iovec, unsigned int num_vecs,
		      unsigned int *len)
{
	struct xsd_sockmsg msg;
	void *ret = NULL;
	int saved_errno;
	unsigned int i;
	struct sigaction ignorepipe, oldact;

	msg.type = type;
	msg.len = 0;
	for (i = 0; i < num_vecs; i++)
		msg.len += iovec[i].iov_len;

	ignorepipe.sa_handler = SIG_IGN;
	sigemptyset(&ignorepipe.sa_mask);
	ignorepipe.sa_flags = 0;
	sigaction(SIGPIPE, &ignorepipe, &oldact);

	if (!xs_write_all(h->fd, &msg, sizeof(msg)))
		goto fail;

	for (i = 0; i < num_vecs; i++)
		if (!xs_write_all(h->fd, iovec[i].iov_base, iovec[i].iov_len))
			goto fail;

	/* Watches can have fired before reply comes: daemon detects
	 * and re-transmits, so we can ignore this. */
	do {
		free(ret);
		ret = read_reply(h->fd, &msg.type, len);
		if (!ret)
			goto fail;
	} while (msg.type == XS_WATCH_EVENT);

	sigaction(SIGPIPE, &oldact, NULL);
	if (msg.type == XS_ERROR) {
		saved_errno = get_error(ret);
		free(ret);
		errno = saved_errno;
		return NULL;
	}

	assert(msg.type == type);
	return ret;

fail:
	/* We're in a bad state, so close fd. */
	saved_errno = errno;
	sigaction(SIGPIPE, &oldact, NULL);
	close(h->fd);
	h->fd = -1;
	errno = saved_errno;
	return NULL;
}

/* free(), but don't change errno. */
static void free_no_errno(void *p)
{
	int saved_errno = errno;
	free(p);
	errno = saved_errno;
}

/* Simplified version of xs_talkv: single message. */
static void *xs_single(struct xs_handle *h, enum xsd_sockmsg_type type,
		       const char *string, unsigned int *len)
{
	struct iovec iovec;

	iovec.iov_base = (void *)string;
	iovec.iov_len = strlen(string) + 1;
	return xs_talkv(h, type, &iovec, 1, len);
}

static bool xs_bool(char *reply)
{
	if (!reply)
		return false;
	free(reply);
	return true;
}

char **xs_directory(struct xs_handle *h, const char *path, unsigned int *num)
{
	char *strings, *p, **ret;
	unsigned int len;

	strings = xs_single(h, XS_DIRECTORY, path, &len);
	if (!strings)
		return NULL;

	/* Count the strings. */
	*num = xs_count_strings(strings, len);

	/* Transfer to one big alloc for easy freeing. */
	ret = malloc(*num * sizeof(char *) + len);
	if (!ret) {
		free_no_errno(strings);
		return NULL;
	}
	memcpy(&ret[*num], strings, len);
	free_no_errno(strings);

	strings = (char *)&ret[*num];
	for (p = strings, *num = 0; p < strings + len; p += strlen(p) + 1)
		ret[(*num)++] = p;
	return ret;
}

/* Get the value of a single file, nul terminated.
 * Returns a malloced value: call free() on it after use.
 * len indicates length in bytes, not including the nul.
 */
void *xs_read(struct xs_handle *h, const char *path, unsigned int *len)
{
	return xs_single(h, XS_READ, path, len);
}

/* Write the value of a single file.
 * Returns false on failure.  createflags can be 0, O_CREAT, or O_CREAT|O_EXCL.
 */
bool xs_write(struct xs_handle *h, const char *path,
	      const void *data, unsigned int len, int createflags)
{
	const char *flags;
	struct iovec iovec[3];

	/* Format: Flags (as string), path, data. */
	if (createflags == 0)
		flags = XS_WRITE_NONE;
	else if (createflags == O_CREAT)
		flags = XS_WRITE_CREATE;
	else if (createflags == (O_CREAT|O_EXCL))
		flags = XS_WRITE_CREATE_EXCL;
	else {
		errno = EINVAL;
		return false;
	}

	iovec[0].iov_base = (void *)path;
	iovec[0].iov_len = strlen(path) + 1;
	iovec[1].iov_base = (void *)flags;
	iovec[1].iov_len = strlen(flags) + 1;
	iovec[2].iov_base = (void *)data;
	iovec[2].iov_len = len;

	return xs_bool(xs_talkv(h, XS_WRITE, iovec, ARRAY_SIZE(iovec), NULL));
}

/* Create a new directory.
 * Returns false on failure.
 */
bool xs_mkdir(struct xs_handle *h, const char *path)
{
	return xs_bool(xs_single(h, XS_MKDIR, path, NULL));
}

/* Destroy a file or directory (directories must be empty).
 * Returns false on failure.
 */
bool xs_rm(struct xs_handle *h, const char *path)
{
	return xs_bool(xs_single(h, XS_RM, path, NULL));
}

/* Get permissions of node (first element is owner).
 * Returns malloced array, or NULL: call free() after use.
 */
struct xs_permissions *xs_get_permissions(struct xs_handle *h,
					  const char *path, unsigned int *num)
{
	char *strings;
	unsigned int len;
	struct xs_permissions *ret;

	strings = xs_single(h, XS_GET_PERMS, path, &len);
	if (!strings)
		return NULL;

	/* Count the strings: each one perms then domid. */
	*num = xs_count_strings(strings, len);

	/* Transfer to one big alloc for easy freeing. */
	ret = malloc(*num * sizeof(struct xs_permissions));
	if (!ret) {
		free_no_errno(strings);
		return NULL;
	}

	if (!xs_strings_to_perms(ret, *num, strings)) {
		free_no_errno(ret);
		ret = NULL;
	}

	free(strings);
	return ret;
}

/* Set permissions of node (must be owner).
 * Returns false on failure.
 */
bool xs_set_permissions(struct xs_handle *h, const char *path,
			struct xs_permissions *perms,
			unsigned int num_perms)
{
	unsigned int i;
	struct iovec iov[1+num_perms];

	iov[0].iov_base = (void *)path;
	iov[0].iov_len = strlen(path) + 1;
	
	for (i = 0; i < num_perms; i++) {
		char buffer[MAX_STRLEN(domid_t)+1];

		if (!xs_perm_to_string(&perms[i], buffer))
			goto unwind;

		iov[i+1].iov_base = strdup(buffer);
		iov[i+1].iov_len = strlen(buffer) + 1;
		if (!iov[i+1].iov_base)
			goto unwind;
	}

	if (!xs_bool(xs_talkv(h, XS_SET_PERMS, iov, 1+num_perms, NULL)))
		goto unwind;
	for (i = 0; i < num_perms; i++)
		free(iov[i+1].iov_base);
	return true;

unwind:
	num_perms = i;
	for (i = 0; i < num_perms; i++)
		free_no_errno(iov[i+1].iov_base);
	return false;
}

/* Watch a node for changes (poll on fd to detect, or call read_watch()).
 * When the node (or any child) changes, fd will become readable.
 * Token is returned when watch is read, to allow matching.
 * Returns false on failure.
 */
bool xs_watch(struct xs_handle *h, const char *path, const char *token)
{
	struct iovec iov[2];

	iov[0].iov_base = (void *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (void *)token;
	iov[1].iov_len = strlen(token) + 1;

	return xs_bool(xs_talkv(h, XS_WATCH, iov, ARRAY_SIZE(iov), NULL));
}

/* Find out what node change was on (will block if nothing pending).
 * Returns array of two pointers: path and token, or NULL.
 * Call free() after use.
 */
char **xs_read_watch(struct xs_handle *h)
{
	struct xsd_sockmsg msg;
	char **ret;

	if (!read_all(h->fd, &msg, sizeof(msg)))
		return NULL;

	assert(msg.type == XS_WATCH_EVENT);
	ret = malloc(sizeof(char *)*2 + msg.len);
	if (!ret)
		return NULL;

	ret[0] = (char *)(ret + 2);
	if (!read_all(h->fd, ret[0], msg.len)) {
		free_no_errno(ret);
		return NULL;
	}
	ret[1] = ret[0] + strlen(ret[0]) + 1;
	return ret;
}

/* Acknowledge watch on node.  Watches must be acknowledged before
 * any other watches can be read.
 * Returns false on failure.
 */
bool xs_acknowledge_watch(struct xs_handle *h, const char *token)
{
	return xs_bool(xs_single(h, XS_WATCH_ACK, token, NULL));
}

/* Remove a watch on a node.
 * Returns false on failure (no watch on that node).
 */
bool xs_unwatch(struct xs_handle *h, const char *path, const char *token)
{
	struct iovec iov[2];

	iov[0].iov_base = (char *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (char *)token;
	iov[1].iov_len = strlen(token) + 1;

	return xs_bool(xs_talkv(h, XS_UNWATCH, iov, ARRAY_SIZE(iov), NULL));
}

/* Start a transaction: changes by others will not be seen during this
 * transaction, and changes will not be visible to others until end.
 * Transaction only applies to the given subtree.
 * You can only have one transaction at any time.
 * Returns false on failure.
 */
bool xs_transaction_start(struct xs_handle *h, const char *subtree)
{
	return xs_bool(xs_single(h, XS_TRANSACTION_START, subtree, NULL));
}

/* End a transaction.
 * If abandon is true, transaction is discarded instead of committed.
 * Returns false on failure, which indicates an error: transactions will
 * not fail spuriously.
 */
bool xs_transaction_end(struct xs_handle *h, bool abort)
{
	char abortstr[2];

	if (abort)
		strcpy(abortstr, "F");
	else
		strcpy(abortstr, "T");
	return xs_bool(xs_single(h, XS_TRANSACTION_END, abortstr, NULL));
}

/* Introduce a new domain.
 * This tells the store daemon about a shared memory page and event channel
 * associated with a domain: the domain uses these to communicate.
 */
bool xs_introduce_domain(struct xs_handle *h, domid_t domid, unsigned long mfn,
			 unsigned int eventchn, const char *path)
{
	char domid_str[MAX_STRLEN(domid)];
	char mfn_str[MAX_STRLEN(mfn)];
	char eventchn_str[MAX_STRLEN(eventchn)];
	struct iovec iov[4];

	sprintf(domid_str, "%u", domid);
	sprintf(mfn_str, "%lu", mfn);
	sprintf(eventchn_str, "%u", eventchn);

	iov[0].iov_base = domid_str;
	iov[0].iov_len = strlen(domid_str) + 1;
	iov[1].iov_base = mfn_str;
	iov[1].iov_len = strlen(mfn_str) + 1;
	iov[2].iov_base = eventchn_str;
	iov[2].iov_len = strlen(eventchn_str) + 1;
	iov[3].iov_base = (char *)path;
	iov[3].iov_len = strlen(path) + 1;

	return xs_bool(xs_talkv(h, XS_INTRODUCE, iov, ARRAY_SIZE(iov), NULL));
}

bool xs_release_domain(struct xs_handle *h, domid_t domid)
{
	char domid_str[MAX_STRLEN(domid)];

	sprintf(domid_str, "%u", domid);

	return xs_bool(xs_single(h, XS_RELEASE, domid_str, NULL));
}

bool xs_shutdown(struct xs_handle *h)
{
	bool ret = xs_bool(xs_single(h, XS_SHUTDOWN, "", NULL));
	if (ret) {
		char c;
		/* Wait for it to actually shutdown. */
		read(h->fd, &c, 1);
	}
	return ret;
}

/* Only useful for DEBUG versions */
char *xs_debug_command(struct xs_handle *h, const char *cmd,
		       void *data, unsigned int len)
{
	struct iovec iov[2];

	iov[0].iov_base = (void *)cmd;
	iov[0].iov_len = strlen(cmd) + 1;
	iov[1].iov_base = data;
	iov[1].iov_len = len;

	return xs_talkv(h, XS_DEBUG, iov, ARRAY_SIZE(iov), NULL);
}
