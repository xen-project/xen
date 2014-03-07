/* 
    Xen Store Daemon interface providing simple tree-like database.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
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
#include "xenstore.h"
#include "list.h"
#include "utils.h"

struct xs_stored_msg {
	struct list_head list;
	struct xsd_sockmsg hdr;
	char *body;
};

#ifdef USE_PTHREAD

#include <pthread.h>

struct xs_handle {
	/* Communications channel to xenstore daemon. */
	int fd;

	/*
         * A read thread which pulls messages off the comms channel and
         * signals waiters.
         */
	pthread_t read_thr;
	int read_thr_exists;

	/*
         * A list of fired watch messages, protected by a mutex. Users can
         * wait on the conditional variable until a watch is pending.
         */
	struct list_head watch_list;
	pthread_mutex_t watch_mutex;
	pthread_cond_t watch_condvar;

	/* Clients can select() on this pipe to wait for a watch to fire. */
	int watch_pipe[2];
	/* Filtering watch event in unwatch function? */
	bool unwatch_filter;

	/*
         * A list of replies. Currently only one will ever be outstanding
         * because we serialise requests. The requester can wait on the
         * conditional variable for its response.
         */
	struct list_head reply_list;
	pthread_mutex_t reply_mutex;
	pthread_cond_t reply_condvar;

	/* One request at a time. */
	pthread_mutex_t request_mutex;

	/* Lock discipline:
	 *  Only holder of the request lock may write to h->fd.
	 *  Only holder of the request lock may access read_thr_exists.
	 *  If read_thr_exists==0, only holder of request lock may read h->fd;
	 *  If read_thr_exists==1, only the read thread may read h->fd.
	 *  Only holder of the reply lock may access reply_list.
	 *  Only holder of the watch lock may access watch_list.
	 * Lock hierarchy:
	 *  The order in which to acquire locks is
	 *     request_mutex
	 *     reply_mutex
	 *     watch_mutex
	 */
};

#define mutex_lock(m)		pthread_mutex_lock(m)
#define mutex_unlock(m)		pthread_mutex_unlock(m)
#define condvar_signal(c)	pthread_cond_signal(c)
#define condvar_wait(c,m)	pthread_cond_wait(c,m)
#define cleanup_push(f, a)	\
    pthread_cleanup_push((void (*)(void *))(f), (void *)(a))
/*
 * Some definitions of pthread_cleanup_pop() are a macro starting with an
 * end-brace. GCC then complains if we immediately precede that with a label.
 * Hence we insert a dummy statement to appease the compiler in this situation.
 */
#define cleanup_pop(run)        ((void)0); pthread_cleanup_pop(run)

#define read_thread_exists(h)	(h->read_thr_exists)

/* Because pthread_cleanup_p* are not available when USE_PTHREAD is
 * disabled, use these macros which convert appropriately. */
#define cleanup_push_heap(p)        cleanup_push(free, p)
#define cleanup_pop_heap(run, p)    cleanup_pop((run))

static void *read_thread(void *arg);

#else /* !defined(USE_PTHREAD) */

struct xs_handle {
	int fd;
	struct list_head reply_list;
	struct list_head watch_list;
	/* Clients can select() on this pipe to wait for a watch to fire. */
	int watch_pipe[2];
	/* Filtering watch event in unwatch function? */
	bool unwatch_filter;
};

#define mutex_lock(m)		((void)0)
#define mutex_unlock(m)		((void)0)
#define condvar_signal(c)	((void)0)
#define condvar_wait(c,m)	((void)0)
#define cleanup_push(f, a)	((void)0)
#define cleanup_pop(run)	((void)0)
#define read_thread_exists(h)	(0)

#define cleanup_push_heap(p)        ((void)0)
#define cleanup_pop_heap(run, p)    do { if ((run)) free(p); } while(0)

#endif

static int read_message(struct xs_handle *h, int nonblocking);

static bool setnonblock(int fd, int nonblock) {
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return false;

	if (nonblock)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		return false;

	return true;
}

int xs_fileno(struct xs_handle *h)
{
	char c = 0;

	mutex_lock(&h->watch_mutex);

	if ((h->watch_pipe[0] == -1) && (pipe(h->watch_pipe) != -1)) {
		/* Kick things off if the watch list is already non-empty. */
		if (!list_empty(&h->watch_list))
			while (write(h->watch_pipe[1], &c, 1) != 1)
				continue;
	}

	mutex_unlock(&h->watch_mutex);

	return h->watch_pipe[0];
}

static int get_socket(const char *connect_to)
{
	struct sockaddr_un addr;
	int sock, saved_errno, flags;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if ((flags = fcntl(sock, F_GETFD)) < 0)
		goto error;
	flags |= FD_CLOEXEC;
	if (fcntl(sock, F_SETFD, flags) < 0)
		goto error;

	addr.sun_family = AF_UNIX;
	if(strlen(connect_to) >= sizeof(addr.sun_path)) {
		errno = EINVAL;
		goto error;
	}
	strcpy(addr.sun_path, connect_to);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		goto error;

	return sock;

error:
	saved_errno = errno;
	close(sock);
	errno = saved_errno;
	return -1;
}

static int get_dev(const char *connect_to)
{
	/* We cannot open read-only because requests are writes */
	return open(connect_to, O_RDWR);
}

static struct xs_handle *get_handle(const char *connect_to)
{
	struct stat buf;
	struct xs_handle *h = NULL;
	int fd = -1, saved_errno;

	if (stat(connect_to, &buf) != 0)
		return NULL;

	if (S_ISSOCK(buf.st_mode))
		fd = get_socket(connect_to);
	else
		fd = get_dev(connect_to);

	if (fd == -1)
		return NULL;

	h = malloc(sizeof(*h));
	if (h == NULL) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return NULL;
	}

	memset(h, 0, sizeof(*h));

	h->fd = fd;

	INIT_LIST_HEAD(&h->reply_list);
	INIT_LIST_HEAD(&h->watch_list);

	/* Watch pipe is allocated on demand in xs_fileno(). */
	h->watch_pipe[0] = h->watch_pipe[1] = -1;

	h->unwatch_filter = false;

#ifdef USE_PTHREAD
	pthread_mutex_init(&h->watch_mutex, NULL);
	pthread_cond_init(&h->watch_condvar, NULL);

	pthread_mutex_init(&h->reply_mutex, NULL);
	pthread_cond_init(&h->reply_condvar, NULL);

	pthread_mutex_init(&h->request_mutex, NULL);
#endif

	return h;
}

struct xs_handle *xs_daemon_open(void)
{
	return xs_open(0);
}

struct xs_handle *xs_daemon_open_readonly(void)
{
	return xs_open(XS_OPEN_READONLY);
}

struct xs_handle *xs_domain_open(void)
{
	return xs_open(0);
}

struct xs_handle *xs_open(unsigned long flags)
{
	struct xs_handle *xsh = NULL;

	if (flags & XS_OPEN_READONLY)
		xsh = get_handle(xs_daemon_socket_ro());
	else
		xsh = get_handle(xs_daemon_socket());

	if (!xsh && !(flags & XS_OPEN_SOCKETONLY))
		xsh = get_handle(xs_domain_dev());

	if (xsh && (flags & XS_UNWATCH_FILTER))
		xsh->unwatch_filter = true;

	return xsh;
}

static void close_free_msgs(struct xs_handle *h) {
	struct xs_stored_msg *msg, *tmsg;

	list_for_each_entry_safe(msg, tmsg, &h->reply_list, list) {
		free(msg->body);
		free(msg);
	}

	list_for_each_entry_safe(msg, tmsg, &h->watch_list, list) {
		free(msg->body);
		free(msg);
	}
}

static void close_fds_free(struct xs_handle *h) {
	if (h->watch_pipe[0] != -1) {
		close(h->watch_pipe[0]);
		close(h->watch_pipe[1]);
	}

        close(h->fd);
        
	free(h);
}

void xs_daemon_destroy_postfork(struct xs_handle *h)
{
        close_free_msgs(h);
        close_fds_free(h);
}

void xs_daemon_close(struct xs_handle *h)
{
#ifdef USE_PTHREAD
	if (h->read_thr_exists) {
		pthread_cancel(h->read_thr);
		pthread_join(h->read_thr, NULL);
	}
#endif

	mutex_lock(&h->request_mutex);
	mutex_lock(&h->reply_mutex);
	mutex_lock(&h->watch_mutex);

        close_free_msgs(h);

	mutex_unlock(&h->request_mutex);
	mutex_unlock(&h->reply_mutex);
	mutex_unlock(&h->watch_mutex);

        close_fds_free(h);
}

void xs_close(struct xs_handle* xsh)
{
	if (xsh)
		xs_daemon_close(xsh);
}

static bool read_all(int fd, void *data, unsigned int len, int nonblocking)
	/* With nonblocking, either reads either everything requested,
	 * or nothing. */
{
	if (!len)
		return true;

	if (nonblocking && !setnonblock(fd, 1))
		return false;

	while (len) {
		int done;

		done = read(fd, data, len);
		if (done < 0) {
			if (errno == EINTR)
				continue;
			goto out_false;
		}
		if (done == 0) {
			/* It closed fd on us?  EBADF is appropriate. */
			errno = EBADF;
			goto out_false;
		}
		data += done;
		len -= done;

		if (nonblocking) {
			nonblocking = 0;
			if (!setnonblock(fd, 0))
				goto out_false;
		}
	}

	return true;

out_false:
	if (nonblocking)
		setnonblock(fd, 0);
	return false;
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
static void *read_reply(
	struct xs_handle *h, enum xsd_sockmsg_type *type, unsigned int *len)
{
	struct xs_stored_msg *msg;
	char *body;
	int read_from_thread;

	read_from_thread = read_thread_exists(h);

	/* Read from comms channel ourselves if there is no reader thread. */
	if (!read_from_thread && (read_message(h, 0) == -1))
		return NULL;

	mutex_lock(&h->reply_mutex);
#ifdef USE_PTHREAD
	while (list_empty(&h->reply_list) && read_from_thread && h->fd != -1)
		condvar_wait(&h->reply_condvar, &h->reply_mutex);
#endif
	if (list_empty(&h->reply_list)) {
		mutex_unlock(&h->reply_mutex);
		errno = EINVAL;
		return NULL;
	}
	msg = list_top(&h->reply_list, struct xs_stored_msg, list);
	list_del(&msg->list);
	assert(list_empty(&h->reply_list));
	mutex_unlock(&h->reply_mutex);

	*type = msg->hdr.type;
	if (len)
		*len = msg->hdr.len;
	body = msg->body;

	free(msg);

	return body;
}

/* Send message to xs, get malloc'ed reply.  NULL and set errno on error. */
static void *xs_talkv(struct xs_handle *h, xs_transaction_t t,
		      enum xsd_sockmsg_type type,
		      const struct iovec *iovec,
		      unsigned int num_vecs,
		      unsigned int *len)
{
	struct xsd_sockmsg msg;
	void *ret = NULL;
	int saved_errno;
	unsigned int i;
	struct sigaction ignorepipe, oldact;

	msg.tx_id = t;
	msg.req_id = 0;
	msg.type = type;
	msg.len = 0;
	for (i = 0; i < num_vecs; i++)
		msg.len += iovec[i].iov_len;

	if (msg.len > XENSTORE_PAYLOAD_MAX) {
		errno = E2BIG;
		return 0;
	}

	ignorepipe.sa_handler = SIG_IGN;
	sigemptyset(&ignorepipe.sa_mask);
	ignorepipe.sa_flags = 0;
	sigaction(SIGPIPE, &ignorepipe, &oldact);

	mutex_lock(&h->request_mutex);

	if (!xs_write_all(h->fd, &msg, sizeof(msg)))
		goto fail;

	for (i = 0; i < num_vecs; i++)
		if (!xs_write_all(h->fd, iovec[i].iov_base, iovec[i].iov_len))
			goto fail;

	ret = read_reply(h, &msg.type, len);
	if (!ret)
		goto fail;

	mutex_unlock(&h->request_mutex);

	sigaction(SIGPIPE, &oldact, NULL);
	if (msg.type == XS_ERROR) {
		saved_errno = get_error(ret);
		free(ret);
		errno = saved_errno;
		return NULL;
	}

	if (msg.type != type) {
		free(ret);
		saved_errno = EBADF;
		goto close_fd;
	}
	return ret;

fail:
	/* We're in a bad state, so close fd. */
	saved_errno = errno;
	mutex_unlock(&h->request_mutex);
	sigaction(SIGPIPE, &oldact, NULL);
close_fd:
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
static void *xs_single(struct xs_handle *h, xs_transaction_t t,
		       enum xsd_sockmsg_type type,
		       const char *string,
		       unsigned int *len)
{
	struct iovec iovec;

	iovec.iov_base = (void *)string;
	iovec.iov_len = strlen(string) + 1;
	return xs_talkv(h, t, type, &iovec, 1, len);
}

static bool xs_bool(char *reply)
{
	if (!reply)
		return false;
	free(reply);
	return true;
}

char **xs_directory(struct xs_handle *h, xs_transaction_t t,
		    const char *path, unsigned int *num)
{
	char *strings, *p, **ret;
	unsigned int len;

	strings = xs_single(h, t, XS_DIRECTORY, path, &len);
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
void *xs_read(struct xs_handle *h, xs_transaction_t t,
	      const char *path, unsigned int *len)
{
	return xs_single(h, t, XS_READ, path, len);
}

/* Write the value of a single file.
 * Returns false on failure.
 */
bool xs_write(struct xs_handle *h, xs_transaction_t t,
	      const char *path, const void *data, unsigned int len)
{
	struct iovec iovec[2];

	iovec[0].iov_base = (void *)path;
	iovec[0].iov_len = strlen(path) + 1;
	iovec[1].iov_base = (void *)data;
	iovec[1].iov_len = len;

	return xs_bool(xs_talkv(h, t, XS_WRITE, iovec,
				ARRAY_SIZE(iovec), NULL));
}

/* Create a new directory.
 * Returns false on failure, or success if it already exists.
 */
bool xs_mkdir(struct xs_handle *h, xs_transaction_t t,
	      const char *path)
{
	return xs_bool(xs_single(h, t, XS_MKDIR, path, NULL));
}

/* Destroy a file or directory (directories must be empty).
 * Returns false on failure, or success if it doesn't exist.
 */
bool xs_rm(struct xs_handle *h, xs_transaction_t t,
	   const char *path)
{
	return xs_bool(xs_single(h, t, XS_RM, path, NULL));
}

/* Get permissions of node (first element is owner).
 * Returns malloced array, or NULL: call free() after use.
 */
struct xs_permissions *xs_get_permissions(struct xs_handle *h,
					  xs_transaction_t t,
					  const char *path, unsigned int *num)
{
	char *strings;
	unsigned int len;
	struct xs_permissions *ret;

	strings = xs_single(h, t, XS_GET_PERMS, path, &len);
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
bool xs_set_permissions(struct xs_handle *h,
			xs_transaction_t t,
			const char *path,
			struct xs_permissions *perms,
			unsigned int num_perms)
{
	unsigned int i;
	struct iovec iov[1+num_perms];

	iov[0].iov_base = (void *)path;
	iov[0].iov_len = strlen(path) + 1;
	
	for (i = 0; i < num_perms; i++) {
		char buffer[MAX_STRLEN(unsigned int)+1];

		if (!xs_perm_to_string(&perms[i], buffer, sizeof(buffer)))
			goto unwind;

		iov[i+1].iov_base = strdup(buffer);
		iov[i+1].iov_len = strlen(buffer) + 1;
		if (!iov[i+1].iov_base)
			goto unwind;
	}

	if (!xs_bool(xs_talkv(h, t, XS_SET_PERMS, iov, 1+num_perms, NULL)))
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

bool xs_restrict(struct xs_handle *h, unsigned domid)
{
	char buf[16];

	sprintf(buf, "%d", domid);
	return xs_bool(xs_single(h, XBT_NULL, XS_RESTRICT, buf, NULL));
}

/* Watch a node for changes (poll on fd to detect, or call read_watch()).
 * When the node (or any child) changes, fd will become readable.
 * Token is returned when watch is read, to allow matching.
 * Returns false on failure.
 */
bool xs_watch(struct xs_handle *h, const char *path, const char *token)
{
	struct iovec iov[2];

#ifdef USE_PTHREAD
#define DEFAULT_THREAD_STACKSIZE (16 * 1024)
#define READ_THREAD_STACKSIZE 					\
	((DEFAULT_THREAD_STACKSIZE < PTHREAD_STACK_MIN) ? 	\
	PTHREAD_STACK_MIN : DEFAULT_THREAD_STACKSIZE)

	/* We dynamically create a reader thread on demand. */
	mutex_lock(&h->request_mutex);
	if (!h->read_thr_exists) {
		sigset_t set, old_set;
		pthread_attr_t attr;

		if (pthread_attr_init(&attr) != 0) {
			mutex_unlock(&h->request_mutex);
			return false;
		}
		if (pthread_attr_setstacksize(&attr, READ_THREAD_STACKSIZE) != 0) {
			pthread_attr_destroy(&attr);
			mutex_unlock(&h->request_mutex);
			return false;
		}

		sigfillset(&set);
		pthread_sigmask(SIG_SETMASK, &set, &old_set);

		if (pthread_create(&h->read_thr, &attr, read_thread, h) != 0) {
			pthread_sigmask(SIG_SETMASK, &old_set, NULL);
			pthread_attr_destroy(&attr);
			mutex_unlock(&h->request_mutex);
			return false;
		}
		h->read_thr_exists = 1;
		pthread_sigmask(SIG_SETMASK, &old_set, NULL);
		pthread_attr_destroy(&attr);
	}
	mutex_unlock(&h->request_mutex);
#endif

	iov[0].iov_base = (void *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (void *)token;
	iov[1].iov_len = strlen(token) + 1;

	return xs_bool(xs_talkv(h, XBT_NULL, XS_WATCH, iov,
				ARRAY_SIZE(iov), NULL));
}


/* Clear the pipe token if there are no more pending watchs.
 * We suppose the watch_mutex is already taken.
 */
static void xs_maybe_clear_watch_pipe(struct xs_handle *h)
{
	char c;

	if (list_empty(&h->watch_list) && (h->watch_pipe[0] != -1))
		while (read(h->watch_pipe[0], &c, 1) != 1)
			continue;
}

/* Find out what node change was on (will block if nothing pending).
 * Returns array of two pointers: path and token, or NULL.
 * Call free() after use.
 */
static char **read_watch_internal(struct xs_handle *h, unsigned int *num,
				  int nonblocking)
{
	struct xs_stored_msg *msg;
	char **ret, *strings;
	unsigned int num_strings, i;

	mutex_lock(&h->watch_mutex);

#ifdef USE_PTHREAD
	/* Wait on the condition variable for a watch to fire.
	 * If the reader thread doesn't exist yet, then that's because
	 * we haven't called xs_watch.	Presumably the application
	 * will do so later; in the meantime we just block.
	 */
	while (list_empty(&h->watch_list) && h->fd != -1) {
		if (nonblocking) {
			mutex_unlock(&h->watch_mutex);
			errno = EAGAIN;
			return 0;
		}
		condvar_wait(&h->watch_condvar, &h->watch_mutex);
	}
#else /* !defined(USE_PTHREAD) */
	/* Read from comms channel ourselves if there are no threads
	 * and therefore no reader thread. */

	assert(!read_thread_exists(h)); /* not threadsafe but worth a check */
	if ((read_message(h, nonblocking) == -1))
		return NULL;

#endif /* !defined(USE_PTHREAD) */

	if (list_empty(&h->watch_list)) {
		mutex_unlock(&h->watch_mutex);
		errno = EINVAL;
		return NULL;
	}
	msg = list_top(&h->watch_list, struct xs_stored_msg, list);
	list_del(&msg->list);

	xs_maybe_clear_watch_pipe(h);
	mutex_unlock(&h->watch_mutex);

	assert(msg->hdr.type == XS_WATCH_EVENT);

	strings     = msg->body;
	num_strings = xs_count_strings(strings, msg->hdr.len);

	ret = malloc(sizeof(char*) * num_strings + msg->hdr.len);
	if (!ret) {
		free_no_errno(strings);
		free_no_errno(msg);
		return NULL;
	}

	ret[0] = (char *)(ret + num_strings);
	memcpy(ret[0], strings, msg->hdr.len);

	free(strings);
	free(msg);

	for (i = 1; i < num_strings; i++)
		ret[i] = ret[i - 1] + strlen(ret[i - 1]) + 1;

	*num = num_strings;

	return ret;
}

char **xs_check_watch(struct xs_handle *h)
{
	unsigned int num;
	char **ret;
	ret = read_watch_internal(h, &num, 1);
	if (ret) assert(num >= 2);
	return ret;
}

/* Find out what node change was on (will block if nothing pending).
 * Returns array of two pointers: path and token, or NULL.
 * Call free() after use.
 */
char **xs_read_watch(struct xs_handle *h, unsigned int *num)
{
	return read_watch_internal(h, num, 0);
}

/* Remove a watch on a node.
 * Returns false on failure (no watch on that node).
 */
bool xs_unwatch(struct xs_handle *h, const char *path, const char *token)
{
	struct iovec iov[2];
	struct xs_stored_msg *msg, *tmsg;
	bool res;
	char *s, *p;
	unsigned int i;
	char *l_token, *l_path;

	iov[0].iov_base = (char *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (char *)token;
	iov[1].iov_len = strlen(token) + 1;

	res = xs_bool(xs_talkv(h, XBT_NULL, XS_UNWATCH, iov,
			       ARRAY_SIZE(iov), NULL));

	if (!h->unwatch_filter) /* Don't filter the watch list */
		return res;


	/* Filter the watch list to remove potential message */
	mutex_lock(&h->watch_mutex);

	if (list_empty(&h->watch_list)) {
		mutex_unlock(&h->watch_mutex);
		return res;
	}

	list_for_each_entry_safe(msg, tmsg, &h->watch_list, list) {
		assert(msg->hdr.type == XS_WATCH_EVENT);

		s = msg->body;

		l_token = NULL;
		l_path = NULL;

		for (p = s, i = 0; p < msg->body + msg->hdr.len; p++) {
			if (*p == '\0')
			{
				if (i == XS_WATCH_TOKEN)
					l_token = s;
				else if (i == XS_WATCH_PATH)
					l_path = s;
				i++;
				s = p + 1;
			}
		}

		if (l_token && !strcmp(token, l_token) &&
		    l_path && xs_path_is_subpath(path, l_path)) {
			list_del(&msg->list);
			free(msg);
		}
	}

	xs_maybe_clear_watch_pipe(h);

	mutex_unlock(&h->watch_mutex);

	return res;
}

/* Start a transaction: changes by others will not be seen during this
 * transaction, and changes will not be visible to others until end.
 * Returns XBT_NULL on failure.
 */
xs_transaction_t xs_transaction_start(struct xs_handle *h)
{
	char *id_str;
	xs_transaction_t id;

	id_str = xs_single(h, XBT_NULL, XS_TRANSACTION_START, "", NULL);
	if (id_str == NULL)
		return XBT_NULL;

	id = strtoul(id_str, NULL, 0);
	free(id_str);

	return id;
}

/* End a transaction.
 * If abandon is true, transaction is discarded instead of committed.
 * Returns false on failure, which indicates an error: transactions will
 * not fail spuriously.
 */
bool xs_transaction_end(struct xs_handle *h, xs_transaction_t t,
			bool abort)
{
	char abortstr[2];

	if (abort)
		strcpy(abortstr, "F");
	else
		strcpy(abortstr, "T");
	
	return xs_bool(xs_single(h, t, XS_TRANSACTION_END, abortstr, NULL));
}

/* Introduce a new domain.
 * This tells the store daemon about a shared memory page and event channel
 * associated with a domain: the domain uses these to communicate.
 */
bool xs_introduce_domain(struct xs_handle *h,
			 unsigned int domid, unsigned long mfn,
			 unsigned int eventchn)
{
	char domid_str[MAX_STRLEN(domid)];
	char mfn_str[MAX_STRLEN(mfn)];
	char eventchn_str[MAX_STRLEN(eventchn)];
	struct iovec iov[3];

	snprintf(domid_str, sizeof(domid_str), "%u", domid);
	snprintf(mfn_str, sizeof(mfn_str), "%lu", mfn);
	snprintf(eventchn_str, sizeof(eventchn_str), "%u", eventchn);

	iov[0].iov_base = domid_str;
	iov[0].iov_len = strlen(domid_str) + 1;
	iov[1].iov_base = mfn_str;
	iov[1].iov_len = strlen(mfn_str) + 1;
	iov[2].iov_base = eventchn_str;
	iov[2].iov_len = strlen(eventchn_str) + 1;

	return xs_bool(xs_talkv(h, XBT_NULL, XS_INTRODUCE, iov,
				ARRAY_SIZE(iov), NULL));
}

bool xs_set_target(struct xs_handle *h,
			 unsigned int domid, unsigned int target)
{
	char domid_str[MAX_STRLEN(domid)];
	char target_str[MAX_STRLEN(target)];
	struct iovec iov[2];

	snprintf(domid_str, sizeof(domid_str), "%u", domid);
	snprintf(target_str, sizeof(target_str), "%u", target);

	iov[0].iov_base = domid_str;
	iov[0].iov_len = strlen(domid_str) + 1;
	iov[1].iov_base = target_str;
	iov[1].iov_len = strlen(target_str) + 1;

	return xs_bool(xs_talkv(h, XBT_NULL, XS_SET_TARGET, iov,
				ARRAY_SIZE(iov), NULL));
}

static void * single_with_domid(struct xs_handle *h,
				enum xsd_sockmsg_type type,
				unsigned int domid)
{
	char domid_str[MAX_STRLEN(domid)];

	snprintf(domid_str, sizeof(domid_str), "%u", domid);

	return xs_single(h, XBT_NULL, type, domid_str, NULL);
}

bool xs_release_domain(struct xs_handle *h, unsigned int domid)
{
	return xs_bool(single_with_domid(h, XS_RELEASE, domid));
}

/* clear the shutdown bit for the given domain */
bool xs_resume_domain(struct xs_handle *h, unsigned int domid)
{
	return xs_bool(single_with_domid(h, XS_RESUME, domid));
}

char *xs_get_domain_path(struct xs_handle *h, unsigned int domid)
{
	char domid_str[MAX_STRLEN(domid)];

	snprintf(domid_str, sizeof(domid_str), "%u", domid);

	return xs_single(h, XBT_NULL, XS_GET_DOMAIN_PATH, domid_str, NULL);
}

bool xs_path_is_subpath(const char *parent, const char *child)
{
        size_t childlen = strlen(child);
        size_t parentlen = strlen(parent);

	if (childlen < parentlen)
		return false;

	if (memcmp(child, parent, parentlen))
		return false;

	if (childlen > parentlen && child[parentlen] != '/')
		return false;

	return true;
}

bool xs_is_domain_introduced(struct xs_handle *h, unsigned int domid)
{
	char *domain = single_with_domid(h, XS_IS_DOMAIN_INTRODUCED, domid);
	int rc = strcmp("F", domain);

	free(domain);
	return rc;
}

int xs_suspend_evtchn_port(int domid)
{
    char path[128];
    char *portstr;
    int port;
    unsigned int plen;
    struct xs_handle *xs;

    xs = xs_daemon_open();
    if (!xs)
        return -1;

    sprintf(path, "/local/domain/%d/device/suspend/event-channel", domid);
    portstr = xs_read(xs, XBT_NULL, path, &plen);
    xs_daemon_close(xs);

    if (!portstr || !plen) {
        port = -1;
        goto out;
    }

    port = atoi(portstr);

out:
    free(portstr);
    return port;
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

	return xs_talkv(h, XBT_NULL, XS_DEBUG, iov,
			ARRAY_SIZE(iov), NULL);
}

static int read_message(struct xs_handle *h, int nonblocking)
{
	/* IMPORTANT: It is forbidden to call this function without
	 * acquiring the request lock and checking that h->read_thr_exists
	 * is false.  See "Lock discipline" in struct xs_handle, above. */

	/* If nonblocking==1, this function will always read either
	 * nothing, returning -1 and setting errno==EAGAIN, or we read
	 * whole amount requested.  Ie as soon as we have the start of
	 * the message we block until we get all of it.
	 */
         
	struct xs_stored_msg *msg = NULL;
	char *body = NULL;
	int saved_errno = 0;
	int ret = -1;

	/* Allocate message structure and read the message header. */
	msg = malloc(sizeof(*msg));
	if (msg == NULL)
		goto error;
	cleanup_push_heap(msg);
	if (!read_all(h->fd, &msg->hdr, sizeof(msg->hdr), nonblocking)) { /* Cancellation point */
		saved_errno = errno;
		goto error_freemsg;
	}

	/* Sanity check message body length. */
	if (msg->hdr.len > XENSTORE_PAYLOAD_MAX) {
		saved_errno = E2BIG;
		goto error_freemsg;
	}

	/* Allocate and read the message body. */
	body = msg->body = malloc(msg->hdr.len + 1);
	if (body == NULL)
		goto error_freemsg;
	cleanup_push_heap(body);
	if (!read_all(h->fd, body, msg->hdr.len, 0)) { /* Cancellation point */
		saved_errno = errno;
		goto error_freebody;
	}

	body[msg->hdr.len] = '\0';

	if (msg->hdr.type == XS_WATCH_EVENT) {
		mutex_lock(&h->watch_mutex);
		cleanup_push(pthread_mutex_unlock, &h->watch_mutex);

		/* Kick users out of their select() loop. */
		if (list_empty(&h->watch_list) &&
		    (h->watch_pipe[1] != -1))
			while (write(h->watch_pipe[1], body, 1) != 1) /* Cancellation point */
				continue;

		list_add_tail(&msg->list, &h->watch_list);

		condvar_signal(&h->watch_condvar);

		cleanup_pop(1);
	} else {
		mutex_lock(&h->reply_mutex);

		/* There should only ever be one response pending! */
		if (!list_empty(&h->reply_list)) {
			mutex_unlock(&h->reply_mutex);
			saved_errno = EEXIST;
			goto error_freebody;
		}

		list_add_tail(&msg->list, &h->reply_list);
		condvar_signal(&h->reply_condvar);

		mutex_unlock(&h->reply_mutex);
	}

	ret = 0;

error_freebody:
	cleanup_pop_heap(ret == -1, body);
error_freemsg:
	cleanup_pop_heap(ret == -1, msg);
error:
	errno = saved_errno;

	return ret;
}

#ifdef USE_PTHREAD
static void *read_thread(void *arg)
{
	struct xs_handle *h = arg;
	int fd;

	while (read_message(h, 0) != -1)
		continue;

	/* An error return from read_message leaves the socket in an undefined
	 * state; we might have read only the header and not the message after
	 * it, or (more commonly) the other end has closed the connection.
	 * Since further communication is unsafe, close the socket.
	 */
	fd = h->fd;
	h->fd = -1;
	close(fd);

	/* wake up all waiters */
	pthread_mutex_lock(&h->reply_mutex);
	pthread_cond_broadcast(&h->reply_condvar);
	pthread_mutex_unlock(&h->reply_mutex);

	pthread_mutex_lock(&h->watch_mutex);
	pthread_cond_broadcast(&h->watch_condvar);
	pthread_mutex_unlock(&h->watch_mutex);

	return NULL;
}
#endif

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
