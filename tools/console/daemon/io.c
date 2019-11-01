/*
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  Xen Console Daemon
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include "utils.h"
#include "io.h"
#include <xenevtchn.h>
#include <xengnttab.h>
#include <xenstore.h>
#include <xen/io/console.h>
#include <xen/grant_table.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <time.h>
#include <assert.h>
#include <sys/types.h>
#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <util.h>
#elif defined(__linux__)
#include <pty.h>
#elif defined(__sun__)
#include <stropts.h>
#elif defined(__FreeBSD__)
#include <sys/ioctl.h>
#include <libutil.h>
#endif

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/* Each 10 bits takes ~ 3 digits, plus one, plus one for nul terminator. */
#define MAX_STRLEN(x) ((sizeof(x) * CHAR_BIT + CHAR_BIT-1) / 10 * 3 + 2)

/* How many events are allowed in each time period */
#define RATE_LIMIT_ALLOWANCE 30
/* Duration of each time period in ms */
#define RATE_LIMIT_PERIOD 200

extern int log_reload;
extern int log_guest;
extern int log_hv;
extern int log_time_hv;
extern int log_time_guest;
extern char *log_dir;
extern int discard_overflowed_data;
extern int replace_escape;

static int log_time_hv_needts = 1;
static int log_time_guest_needts = 1;
static int log_hv_fd = -1;

static xengnttab_handle *xgt_handle = NULL;

static struct pollfd  *fds;
static unsigned int current_array_size;
static unsigned int nr_fds;

#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))

struct buffer {
	char *data;
	size_t consumed;
	size_t size;
	size_t capacity;
	size_t max_capacity;
};

struct console {
	char *ttyname;
	int master_fd;
	int master_pollfd_idx;
	int slave_fd;
	int log_fd;
	struct buffer buffer;
	char *xspath;
	char *log_suffix;
	int ring_ref;
	xenevtchn_handle *xce_handle;
	int xce_pollfd_idx;
	int event_count;
	long long next_period;
	xenevtchn_port_or_error_t local_port;
	xenevtchn_port_or_error_t remote_port;
	struct xencons_interface *interface;
	struct domain *d;
	bool optional;
	bool use_gnttab;
};

struct console_type {
	char *xsname;
	char *ttyname;
	char *log_suffix;
	bool optional;
	bool use_gnttab;
};

static struct console_type console_type[] = {
	{
		.xsname = "/console",
		.ttyname = "tty",
		.log_suffix = "",
		.optional = false,
		.use_gnttab = true,
	},
#if defined(CONFIG_ARM)
	{
		.xsname = "/vuart/0",
		.ttyname = "tty",
		.log_suffix = "-vuart0",
		.optional = true,
		.use_gnttab = false,
	},
#endif
};

#define NUM_CONSOLE_TYPE (sizeof(console_type)/sizeof(struct console_type))

struct domain {
	int domid;
	bool is_dead;
	unsigned last_seen;
	struct domain *next;
	struct console console[NUM_CONSOLE_TYPE];
};

static struct domain *dom_head;

typedef void (*VOID_ITER_FUNC_ARG1)(struct console *);
typedef int (*INT_ITER_FUNC_ARG1)(struct console *);
typedef void (*VOID_ITER_FUNC_ARG2)(struct console *,  void *);
typedef int (*INT_ITER_FUNC_ARG3)(struct console *,
				  struct domain *dom, void **);

static inline bool console_enabled(struct console *con)
{
	return con->local_port != -1;
}

static inline void console_iter_void_arg1(struct domain *d,
					  VOID_ITER_FUNC_ARG1 iter_func)
{
	unsigned int i;
	struct console *con = &d->console[0];

	for (i = 0; i < NUM_CONSOLE_TYPE; i++, con++) {
		iter_func(con);
	}
}

static inline void console_iter_void_arg2(struct domain *d,
					  VOID_ITER_FUNC_ARG2 iter_func,
					  void *iter_data)
{
	unsigned int i;
	struct console *con = &d->console[0];

	for (i = 0; i < NUM_CONSOLE_TYPE; i++, con++) {
		iter_func(con, iter_data);
	}
}

static inline int console_iter_int_arg1(struct domain *d,
					INT_ITER_FUNC_ARG1 iter_func)
{
	unsigned int i;
	int ret;
	struct console *con = &d->console[0];

	for (i = 0; i < NUM_CONSOLE_TYPE; i++, con++) {
		/*
		 * Zero return values means success.
		 *
		 * Non-zero return value indicates an error in which
		 * case terminate the loop.
		 */
		ret = iter_func(con);
		if (ret)
			break;
	}
	return ret;
}

static inline int console_iter_int_arg3(struct domain *d,
					INT_ITER_FUNC_ARG3 iter_func,
					void **iter_data)
{
	unsigned int i;
	int ret;
	struct console *con = &d->console[0];

	for (i = 0; i < NUM_CONSOLE_TYPE; i++, con++) {
		/*
		 * Zero return values means success.
		 *
		 * Non-zero return value indicates an error in which
		 * case terminate the loop.
		 */
		ret = iter_func(con, d, iter_data);
		if (ret)
			break;
	}
	return ret;
}

static void do_replace_escape(const char *src, char *dest, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (src[i] == '\033')
			dest[i] = '.';
		else
			dest[i] = src[i];
	}
}

static int write_all(int fd, const char* buf, size_t len)
{
	while (len) {
		ssize_t ret;
		if (replace_escape) {
			char buf_replaced[1024];
			size_t this_round;

			if (len > sizeof(buf_replaced))
				this_round = sizeof(buf_replaced);
			else
				this_round = len;
			do_replace_escape(buf, buf_replaced, this_round);
			ret = write(fd, buf_replaced, this_round);
		} else
			ret = write(fd, buf, len);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret <= 0)
			return -1;
		len -= ret;
		buf += ret;
	}

	return 0;
}

static int write_with_timestamp(int fd, const char *data, size_t sz,
				int *needts)
{
	char ts[32];
	time_t now = time(NULL);
	const struct tm *tmnow = localtime(&now);
	size_t tslen = strftime(ts, sizeof(ts), "[%Y-%m-%d %H:%M:%S] ", tmnow);
	const char *last_byte = data + sz - 1;

	while (data <= last_byte) {
		const char *nl = memchr(data, '\n', last_byte + 1 - data);
		int found_nl = (nl != NULL);
		if (!found_nl)
			nl = last_byte;

		if ((*needts && write_all(fd, ts, tslen))
		    || write_all(fd, data, nl + 1 - data))
			return -1;

		*needts = found_nl;
		data = nl + 1;
		if (found_nl) {
			// If we printed a newline, strip all \r following it
			while (data <= last_byte && *data == '\r')
				data++;
		}
	}

	return 0;
}

static inline bool buffer_available(struct console *con)
{
	if (discard_overflowed_data ||
	    !con->buffer.max_capacity ||
	    con->buffer.size < con->buffer.max_capacity)
		return true;
	else
		return false;
}

static void buffer_append(struct console *con)
{
	struct buffer *buffer = &con->buffer;
	struct domain *dom = con->d;
	XENCONS_RING_IDX cons, prod, size;
	struct xencons_interface *intf = con->interface;

	cons = intf->out_cons;
	prod = intf->out_prod;
	xen_mb();

	size = prod - cons;
	if ((size == 0) || (size > sizeof(intf->out)))
		return;

	if ((buffer->capacity - buffer->size) < size) {
		buffer->capacity += (size + 1024);
		buffer->data = realloc(buffer->data, buffer->capacity);
		if (buffer->data == NULL) {
			dolog(LOG_ERR, "Memory allocation failed");
			exit(ENOMEM);
		}
	}

	while (cons != prod)
		buffer->data[buffer->size++] = intf->out[
			MASK_XENCONS_IDX(cons++, intf->out)];

	xen_mb();
	intf->out_cons = cons;
	xenevtchn_notify(con->xce_handle, con->local_port);

	/* Get the data to the logfile as early as possible because if
	 * no one is listening on the console pty then it will fill up
	 * and handle_tty_write will stop being called.
	 */
	if (con->log_fd != -1) {
		int logret;
		if (log_time_guest) {
			logret = write_with_timestamp(
				con->log_fd,
				buffer->data + buffer->size - size,
				size, &log_time_guest_needts);
		} else {
			logret = write_all(
				con->log_fd,
				buffer->data + buffer->size - size,
				size);
		}
		if (logret < 0)
			dolog(LOG_ERR, "Write to log failed "
			      "on domain %d: %d (%s)\n",
			      dom->domid, errno, strerror(errno));
	}

	if (discard_overflowed_data && buffer->max_capacity &&
	    buffer->size > 5 * buffer->max_capacity / 4) {
		if (buffer->consumed > buffer->max_capacity / 4) {
			/* Move data up in buffer, since beginning has
			 * been output.  Only needed because buffer is
			 * not a ring buffer *sigh* */
			memmove(buffer->data,
				buffer->data + buffer->consumed,
				buffer->size - buffer->consumed);
			buffer->size -= buffer->consumed;
			buffer->consumed = 0;
		} else {
			/* Discard the middle of the data. */
			size_t over = buffer->size - buffer->max_capacity;

			memmove(buffer->data + buffer->max_capacity / 2,
				buffer->data + buffer->max_capacity,
				over);
			buffer->size = buffer->max_capacity / 2 + over;
		}
	}
}

static bool buffer_empty(struct buffer *buffer)
{
	return buffer->size == 0;
}

static void buffer_advance(struct buffer *buffer, size_t len)
{
	buffer->consumed += len;
	if (buffer->consumed == buffer->size) {
		buffer->consumed = 0;
		buffer->size = 0;
		if (buffer->max_capacity &&
		    buffer->capacity > buffer->max_capacity) {
			buffer->data = realloc(buffer->data, buffer->max_capacity);
			buffer->capacity = buffer->max_capacity;
		}
	}
}

static bool domain_is_valid(int domid)
{
	bool ret;
	xc_dominfo_t info;

	ret = (xc_domain_getinfo(xc, domid, 1, &info) == 1 &&
	       info.domid == domid);
		
	return ret;
}

static int create_hv_log(void)
{
	char logfile[PATH_MAX];
	int fd;
	snprintf(logfile, PATH_MAX-1, "%s/hypervisor.log", log_dir);
	logfile[PATH_MAX-1] = '\0';

	fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0644);
	if (fd == -1)
		dolog(LOG_ERR, "Failed to open log %s: %d (%s)",
		      logfile, errno, strerror(errno));
	if (fd != -1 && log_time_hv) {
		if (write_with_timestamp(fd, "Logfile Opened\n",
					 strlen("Logfile Opened\n"),
					 &log_time_hv_needts) < 0) {
			dolog(LOG_ERR, "Failed to log opening timestamp "
				       "in %s: %d (%s)", logfile, errno,
				       strerror(errno));
			close(fd);
			return -1;
		}
	}
	return fd;
}

static int create_console_log(struct console *con)
{
	char logfile[PATH_MAX];
	char *namepath, *data, *s;
	int fd;
	unsigned int len;
	struct domain *dom = con->d;

	namepath = xs_get_domain_path(xs, dom->domid);
	s = realloc(namepath, strlen(namepath) + 6);
	if (s == NULL) {
		free(namepath);
		return -1;
	}
	namepath = s;
	strcat(namepath, "/name");
	data = xs_read(xs, XBT_NULL, namepath, &len);
	free(namepath);
	if (!data)
		return -1;
	if (!len) {
		free(data);
		return -1;
	}

	snprintf(logfile, PATH_MAX-1, "%s/guest-%s%s.log",
		 log_dir, data, con->log_suffix);

	free(data);
	logfile[PATH_MAX-1] = '\0';

	fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0644);
	if (fd == -1)
		dolog(LOG_ERR, "Failed to open log %s: %d (%s)",
		      logfile, errno, strerror(errno));
	if (fd != -1 && log_time_guest) {
		if (write_with_timestamp(fd, "Logfile Opened\n",
					 strlen("Logfile Opened\n"),
					 &log_time_guest_needts) < 0) {
			dolog(LOG_ERR, "Failed to log opening timestamp "
				       "in %s: %d (%s)", logfile, errno,
				       strerror(errno));
			close(fd);
			return -1;
		}
	}
	return fd;
}

static void console_close_tty(struct console *con)
{
	if (con->master_fd != -1) {
		close(con->master_fd);
		con->master_fd = -1;
	}

	if (con->slave_fd != -1) {
		close(con->slave_fd);
		con->slave_fd = -1;
	}
}

#ifdef __sun__
static int openpty(int *amaster, int *aslave, char *name,
		   struct termios *termp, struct winsize *winp)
{
	const char *slave;
	int mfd = -1, sfd = -1;

	*amaster = *aslave = -1;

	mfd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	if (mfd < 0)
		goto err;

	if (grantpt(mfd) == -1 || unlockpt(mfd) == -1)
		goto err;

	if ((slave = ptsname(mfd)) == NULL)
		goto err;

	if ((sfd = open(slave, O_RDONLY | O_NOCTTY)) == -1)
		goto err;

	if (ioctl(sfd, I_PUSH, "ptem") == -1)
		goto err;

	if (amaster)
		*amaster = mfd;
	if (aslave)
		*aslave = sfd;
	if (winp)
		ioctl(sfd, TIOCSWINSZ, winp);

	if (termp)
		tcsetattr(sfd, TCSAFLUSH, termp);

	assert(name == NULL);

	return 0;

err:
	if (sfd != -1)
		close(sfd);
	close(mfd);
	return -1;
}

void cfmakeraw(struct termios *termios_p)
{
	termios_p->c_iflag &=
	    ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	termios_p->c_oflag &= ~OPOST;
	termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	termios_p->c_cflag &= ~(CSIZE|PARENB);
	termios_p->c_cflag |= CS8;

	termios_p->c_cc[VMIN] = 0;
	termios_p->c_cc[VTIME] = 0;
}
#endif /* __sun__ */

static int console_create_tty(struct console *con)
{
	const char *slave;
	char *path;
	int err;
	bool success;
	char *data;
	unsigned int len;
	struct termios term;
	struct domain *dom = con->d;

	assert(con->slave_fd == -1);
	assert(con->master_fd == -1);

	if (openpty(&con->master_fd, &con->slave_fd, NULL, NULL, NULL) < 0) {
		err = errno;
		dolog(LOG_ERR, "Failed to create tty for domain-%d "
		      "(errno = %i, %s)",
		      dom->domid, err, strerror(err));
		return 0;
	}

	if (tcgetattr(con->slave_fd, &term) < 0) {
		err = errno;
		dolog(LOG_ERR, "Failed to get tty attributes for domain-%d "
			"(errno = %i, %s)",
			dom->domid, err, strerror(err));
		goto out;
	}
	cfmakeraw(&term);
	if (tcsetattr(con->slave_fd, TCSANOW, &term) < 0) {
		err = errno;
		dolog(LOG_ERR, "Failed to set tty attributes for domain-%d "
			"(errno = %i, %s)",
			dom->domid, err, strerror(err));
		goto out;
	}

	if ((slave = ptsname(con->master_fd)) == NULL) {
		err = errno;
		dolog(LOG_ERR, "Failed to get slave name for domain-%d "
		      "(errno = %i, %s)",
		      dom->domid, err, strerror(err));
		goto out;
	}

	success = asprintf(&path, "%s/limit", con->xspath) !=
		-1;
	if (!success)
		goto out;
	data = xs_read(xs, XBT_NULL, path, &len);
	if (data) {
		con->buffer.max_capacity = strtoul(data, 0, 0);
		free(data);
	}
	free(path);

	success = (asprintf(&path, "%s/%s", con->xspath, con->ttyname) != -1);
	if (!success)
		goto out;
	success = xs_write(xs, XBT_NULL, path, slave, strlen(slave));
	free(path);
	if (!success)
		goto out;

	if (fcntl(con->master_fd, F_SETFL, O_NONBLOCK) == -1)
		goto out;

	return 1;
out:
	console_close_tty(con);
	return 0;
}
 
/* Takes tuples of names, scanf-style args, and void **, NULL terminated. */
static int xs_gather(struct xs_handle *xs, const char *dir, ...)
{
	va_list ap;
	const char *name;
	char *path;
	int ret = 0;

	va_start(ap, dir);
	while (ret == 0 && (name = va_arg(ap, char *)) != NULL) {
		const char *fmt = va_arg(ap, char *);
		void *result = va_arg(ap, void *);
		char *p;

		if (asprintf(&path, "%s/%s", dir, name) == -1) {
			ret = ENOMEM;
			break;
		}
		p = xs_read(xs, XBT_NULL, path, NULL);
		free(path);
		if (p == NULL) {
			ret = ENOENT;
			break;
		}
		if (fmt) {
			if (sscanf(p, fmt, result) == 0)
				ret = EINVAL;
			free(p);
		} else
			*(char **)result = p;
	}
	va_end(ap);
	return ret;
}

static void console_unmap_interface(struct console *con)
{
	if (con->interface == NULL)
		return;
	if (xgt_handle && con->ring_ref == -1)
		xengnttab_unmap(xgt_handle, con->interface, 1);
	else
		munmap(con->interface, XC_PAGE_SIZE);
	con->interface = NULL;
	con->ring_ref = -1;
}
 
static int console_create_ring(struct console *con)
{
	int err, remote_port, ring_ref, rc;
	char *type, path[PATH_MAX];
	struct domain *dom = con->d;

	err = xs_gather(xs, con->xspath,
			"ring-ref", "%u", &ring_ref,
			"port", "%i", &remote_port,
			NULL);

	if (err) {
		/*
		 * This is a normal condition for optional consoles: they might not be
		 * present on xenstore at all. In that case, just return without error.
		*/
		if (con->optional)
			err = 0;

		goto out;
	}

	snprintf(path, sizeof(path), "%s/type", con->xspath);
	type = xs_read(xs, XBT_NULL, path, NULL);
	if (type && strcmp(type, "xenconsoled") != 0) {
		free(type);
		return 0;
	}
	free(type);

	/* If using ring_ref and it has changed, remap */
	if (ring_ref != con->ring_ref && con->ring_ref != -1)
		console_unmap_interface(con);

	if (!con->interface && xgt_handle && con->use_gnttab) {
		/* Prefer using grant table */
		con->interface = xengnttab_map_grant_ref(xgt_handle,
			dom->domid, GNTTAB_RESERVED_CONSOLE,
			PROT_READ|PROT_WRITE);
		con->ring_ref = -1;
	}
	if (!con->interface) {
		/* Fall back to xc_map_foreign_range */
		con->interface = xc_map_foreign_range(
			xc, dom->domid, XC_PAGE_SIZE,
			PROT_READ|PROT_WRITE,
			(unsigned long)ring_ref);
		if (con->interface == NULL) {
			err = EINVAL;
			goto out;
		}
		con->ring_ref = ring_ref;
	}

	/* Go no further if port has not changed and we are still bound. */
	if (remote_port == con->remote_port) {
		xc_evtchn_status_t status = {
			.dom = DOMID_SELF,
			.port = con->local_port };
		if ((xc_evtchn_status(xc, &status) == 0) &&
		    (status.status == EVTCHNSTAT_interdomain))
			goto out;
	}

	con->local_port = -1;
	con->remote_port = -1;
	if (con->xce_handle != NULL)
		xenevtchn_close(con->xce_handle);

	/* Opening evtchn independently for each console is a bit
	 * wasteful, but that's how the code is structured... */
	con->xce_handle = xenevtchn_open(NULL, 0);
	if (con->xce_handle == NULL) {
		err = errno;
		goto out;
	}
 
	rc = xenevtchn_bind_interdomain(con->xce_handle,
		dom->domid, remote_port);

	if (rc == -1) {
		err = errno;
		xenevtchn_close(con->xce_handle);
		con->xce_handle = NULL;
		goto out;
	}
	con->local_port = rc;
	con->remote_port = remote_port;

	if (con->master_fd == -1) {
		if (!console_create_tty(con)) {
			err = errno;
			xenevtchn_close(con->xce_handle);
			con->xce_handle = NULL;
			con->local_port = -1;
			con->remote_port = -1;
			goto out;
		}
	}

	if (log_guest && (con->log_fd == -1))
		con->log_fd = create_console_log(con);

 out:
	return err;
}

static bool watch_domain(struct domain *dom, bool watch)
{
	char domid_str[3 + MAX_STRLEN(dom->domid)];
	bool success;
	struct console *con = &dom->console[0];

	snprintf(domid_str, sizeof(domid_str), "dom%u", dom->domid);
	if (watch) {
		success = xs_watch(xs, con->xspath, domid_str);
		if (success)
			console_iter_int_arg1(dom, console_create_ring);
		else
			xs_unwatch(xs, con->xspath, domid_str);
	} else {
		success = xs_unwatch(xs, con->xspath, domid_str);
	}

	return success;
}

static int console_init(struct console *con, struct domain *dom, void **data)
{
	char *s;
	int err = -1;
	struct timespec ts;
	struct console_type **con_type = (struct console_type **)data;
	char *xsname, *xspath;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
		dolog(LOG_ERR, "Cannot get time of day %s:%s:L%d",
		      __FILE__, __FUNCTION__, __LINE__);
		return err;
	}

	con->master_fd = -1;
	con->master_pollfd_idx = -1;
	con->slave_fd = -1;
	con->log_fd = -1;
	con->ring_ref = -1;
	con->local_port = -1;
	con->remote_port = -1;
	con->xce_pollfd_idx = -1;
	con->next_period = ((long long)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000) + RATE_LIMIT_PERIOD;
	con->d = dom;
	con->ttyname = (*con_type)->ttyname;
	con->log_suffix = (*con_type)->log_suffix;
	con->optional = (*con_type)->optional;
	con->use_gnttab = (*con_type)->use_gnttab;
	xsname = (char *)(*con_type)->xsname;
	xspath = xs_get_domain_path(xs, dom->domid);
	s = realloc(xspath, strlen(xspath) +
		    strlen(xsname) + 1);
	if (s) {
		xspath = s;
		strcat(xspath, xsname);
		con->xspath = xspath;
		err = 0;
	}

	(*con_type)++;

	return err;
}

static void console_free(struct console *con)
{
	if (con->xspath)
		free(con->xspath);
}

static struct domain *create_domain(int domid)
{
	struct domain *dom;
	struct console_type *con_type = &console_type[0];

	dom = calloc(1, sizeof *dom);
	if (dom == NULL) {
		dolog(LOG_ERR, "Out of memory %s:%s():L%d",
		      __FILE__, __FUNCTION__, __LINE__);
		exit(ENOMEM);
	}

	dom->domid = domid;

	if (console_iter_int_arg3(dom, console_init, (void **)&con_type))
		goto out;

	if (!watch_domain(dom, true))
		goto out;

	dom->next = dom_head;
	dom_head = dom;

	dolog(LOG_DEBUG, "New domain %d", domid);

	return dom;
 out:
	console_iter_void_arg1(dom, console_free);
	free(dom);
	return NULL;
}

static struct domain *lookup_domain(int domid)
{
	struct domain *dom;

	for (dom = dom_head; dom; dom = dom->next)
		if (dom->domid == domid)
			return dom;
	return NULL;
}

static void remove_domain(struct domain *dom)
{
	struct domain **pp;

	dolog(LOG_DEBUG, "Removing domain-%d", dom->domid);

	for (pp = &dom_head; *pp; pp = &(*pp)->next) {
		if (dom == *pp) {
			*pp = dom->next;
			free(dom);
			break;
		}
	}
}

static void console_cleanup(struct console *con)
{
	if (con->log_fd != -1) {
		close(con->log_fd);
		con->log_fd = -1;
	}

	free(con->buffer.data);
	con->buffer.data = NULL;

	free(con->xspath);
	con->xspath = NULL;
}

static void cleanup_domain(struct domain *d)
{
	console_iter_void_arg1(d, console_close_tty);

	console_iter_void_arg1(d, console_cleanup);

	remove_domain(d);
}

static void console_close_evtchn(struct console *con)
{
	if (con->xce_handle != NULL)
		xenevtchn_close(con->xce_handle);

	con->xce_handle = NULL;
}

static void shutdown_domain(struct domain *d)
{
	d->is_dead = true;
	watch_domain(d, false);
	console_iter_void_arg1(d, console_unmap_interface);
	console_iter_void_arg1(d, console_close_evtchn);
}

static unsigned enum_pass = 0;

static void enum_domains(void)
{
	int domid = 1;
	xc_dominfo_t dominfo;
	struct domain *dom;

	enum_pass++;

	while (xc_domain_getinfo(xc, domid, 1, &dominfo) == 1) {
		dom = lookup_domain(dominfo.domid);
		if (dominfo.dying) {
			if (dom)
				shutdown_domain(dom);
		} else {
			if (dom == NULL)
				dom = create_domain(dominfo.domid);
		}
		if (dom)
			dom->last_seen = enum_pass;
		domid = dominfo.domid + 1;
	}
}

static int ring_free_bytes(struct console *con)
{
	struct xencons_interface *intf = con->interface;
	XENCONS_RING_IDX cons, prod, space;

	cons = intf->in_cons;
	prod = intf->in_prod;
	xen_mb();

	space = prod - cons;
	if (space > sizeof(intf->in))
		return 0; /* ring is screwed: ignore it */

	return (sizeof(intf->in) - space);
}

static void console_handle_broken_tty(struct console *con, int recreate)
{
	console_close_tty(con);

	if (recreate) {
		console_create_tty(con);
	} else {
		shutdown_domain(con->d);
	}
}

static void handle_tty_read(struct console *con)
{
	ssize_t len = 0;
	char msg[80];
	int i;
	struct xencons_interface *intf = con->interface;
	struct domain *dom = con->d;
	XENCONS_RING_IDX prod;

	if (dom->is_dead)
		return;

	len = ring_free_bytes(con);
	if (len == 0)
		return;

	if (len > sizeof(msg))
		len = sizeof(msg);

	len = read(con->master_fd, msg, len);
	/*
	 * Note: on Solaris, len == 0 means the slave closed, and this
	 * is no problem, but Linux can't handle this usefully, so we
	 * keep the slave open for the duration.
	 */
	if (len < 0) {
		console_handle_broken_tty(con, domain_is_valid(dom->domid));
	} else if (domain_is_valid(dom->domid)) {
		prod = intf->in_prod;
		for (i = 0; i < len; i++) {
			intf->in[MASK_XENCONS_IDX(prod++, intf->in)] =
				msg[i];
		}
		xen_wmb();
		intf->in_prod = prod;
		xenevtchn_notify(con->xce_handle, con->local_port);
	} else {
		console_close_tty(con);
		shutdown_domain(dom);
	}
}

static void handle_tty_write(struct console *con)
{
	ssize_t len;
	struct domain *dom = con->d;

	if (dom->is_dead)
		return;

	len = write(con->master_fd, con->buffer.data + con->buffer.consumed,
		    con->buffer.size - con->buffer.consumed);
 	if (len < 1) {
		dolog(LOG_DEBUG, "Write failed on domain %d: %zd, %d\n",
		      dom->domid, len, errno);
		console_handle_broken_tty(con, domain_is_valid(dom->domid));
	} else {
		buffer_advance(&con->buffer, len);
	}
}

static void console_evtchn_unmask(struct console *con, void *data)
{
	long long now = *(long long *)data;

	if (!console_enabled(con))
		return;

	/* CS 16257:955ee4fa1345 introduces a 5ms fuzz
	 * for select(), it is not clear poll() has
	 * similar behavior (returning a couple of ms
	 * sooner than requested) as well. Just leave
	 * the fuzz here. Remove it with a separate
	 * patch if necessary */
	if ((now+5) > con->next_period) {
		con->next_period = now + RATE_LIMIT_PERIOD;
		if (con->event_count >= RATE_LIMIT_ALLOWANCE)
			(void)xenevtchn_unmask(con->xce_handle, con->local_port);
		con->event_count = 0;
	}
}

static void handle_ring_read(struct console *con)
{
	xenevtchn_port_or_error_t port;

	if (con->d->is_dead)
		return;

	if ((port = xenevtchn_pending(con->xce_handle)) == -1)
		return;

	if (port != con->local_port) {
		dolog(LOG_ERR,
		      "Event received for invalid port %d, Expected port is %d\n",
		      port, con->local_port);
		return;
	}

	con->event_count++;

	buffer_append(con);

	if (con->event_count < RATE_LIMIT_ALLOWANCE)
		(void)xenevtchn_unmask(con->xce_handle, port);
}

static void handle_console_ring(struct console *con)
{
	if (con->event_count < RATE_LIMIT_ALLOWANCE) {
		if (con->xce_handle != NULL &&
		    con->xce_pollfd_idx != -1 &&
		    !(fds[con->xce_pollfd_idx].revents &
		      ~(POLLIN|POLLOUT|POLLPRI)) &&
		    (fds[con->xce_pollfd_idx].revents &
		     POLLIN))
			handle_ring_read(con);
	}

	con->xce_pollfd_idx = -1;
}

static void handle_xs(void)
{
	char **vec;
	int domid;
	struct domain *dom;
	unsigned int num;

	vec = xs_read_watch(xs, &num);
	if (!vec)
		return;

	if (!strcmp(vec[XS_WATCH_TOKEN], "domlist"))
		enum_domains();
	else if (sscanf(vec[XS_WATCH_TOKEN], "dom%u", &domid) == 1) {
		dom = lookup_domain(domid);
		/* We may get watches firing for domains that have recently
		   been removed, so dom may be NULL here. */
		if (dom && dom->is_dead == false)
			console_iter_int_arg1(dom, console_create_ring);
	}

	free(vec);
}

static void handle_hv_logs(xenevtchn_handle *xce_handle, bool force)
{
	static char buffer[1024*16];
	char *bufptr = buffer;
	unsigned int size;
	static uint32_t index = 0;
	xenevtchn_port_or_error_t port = -1;

	if (!force && ((port = xenevtchn_pending(xce_handle)) == -1))
		return;

	do
	{
		int logret;

		size = sizeof(buffer);
		if (xc_readconsolering(xc, bufptr, &size, 0, 1, &index) != 0 ||
		    size == 0)
			break;

		if (log_time_hv)
			logret = write_with_timestamp(log_hv_fd, buffer, size,
						      &log_time_hv_needts);
		else
			logret = write_all(log_hv_fd, buffer, size);

		if (logret < 0)
			dolog(LOG_ERR, "Failed to write hypervisor log: "
				       "%d (%s)", errno, strerror(errno));
	} while (size == sizeof(buffer));

	if (port != -1)
		(void)xenevtchn_unmask(xce_handle, port);
}

static void console_open_log(struct console *con)
{
	if (console_enabled(con)) {
		if (con->log_fd != -1)
			close(con->log_fd);
		con->log_fd = create_console_log(con);
	}
}

static void handle_log_reload(void)
{
	if (log_guest) {
		struct domain *d;
		for (d = dom_head; d; d = d->next) {
			console_iter_void_arg1(d, console_open_log);
		}
	}

	if (log_hv) {
		if (log_hv_fd != -1)
			close(log_hv_fd);
		log_hv_fd = create_hv_log();
	}
}

/* Returns index inside fds array if succees, -1 if fail */
static int set_fds(int fd, short events)
{
	int ret;
	if (current_array_size < nr_fds + 1) {
		struct pollfd  *new_fds = NULL;
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
		       sizeof(struct pollfd) * (newsize-current_array_size));
		current_array_size = newsize;
	}

	fds[nr_fds].fd = fd;
	fds[nr_fds].events = events;
	ret = nr_fds;
	nr_fds++;

	return ret;
fail:
	dolog(LOG_ERR, "realloc failed, ignoring fd %d\n", fd);
	return -1;
}

static void reset_fds(void)
{
	nr_fds = 0;
	if (fds)
		memset(fds, 0, sizeof(struct pollfd) * current_array_size);
}

static void maybe_add_console_evtchn_fd(struct console *con, void *data)
{
	long long next_timeout = *((long long *)data);

	if (con->event_count >= RATE_LIMIT_ALLOWANCE) {
		/* Determine if we're going to be the next time slice to expire */
		if (!next_timeout ||
		    con->next_period < next_timeout)
			next_timeout = con->next_period;
	} else if (con->xce_handle != NULL) {
		if (buffer_available(con)) {
			int evtchn_fd = xenevtchn_fd(con->xce_handle);
			con->xce_pollfd_idx = set_fds(evtchn_fd,
						      POLLIN|POLLPRI);
		}
	}

	*((long long *)data) = next_timeout;
}

static void maybe_add_console_tty_fd(struct console *con)
{
	if (con->master_fd != -1) {
		short events = 0;
		if (!con->d->is_dead && ring_free_bytes(con))
			events |= POLLIN;

		if (!buffer_empty(&con->buffer))
			events |= POLLOUT;

		if (events)
			con->master_pollfd_idx =
				set_fds(con->master_fd, events|POLLPRI);
	}
}

static void handle_console_tty(struct console *con)
{
	if (con->master_fd != -1 && con->master_pollfd_idx != -1) {
		if (fds[con->master_pollfd_idx].revents &
		    ~(POLLIN|POLLOUT|POLLPRI))
			console_handle_broken_tty(con, domain_is_valid(con->d->domid));
		else {
			if (fds[con->master_pollfd_idx].revents &
			    POLLIN)
				handle_tty_read(con);
			if (fds[con->master_pollfd_idx].revents &
			    POLLOUT)
				handle_tty_write(con);
		}
	}
	con->master_pollfd_idx = -1;
}

void handle_io(void)
{
	int ret;
	xenevtchn_port_or_error_t log_hv_evtchn = -1;
	int xce_pollfd_idx = -1;
	int xs_pollfd_idx = -1;
	xenevtchn_handle *xce_handle = NULL;

	if (log_hv) {
		xce_handle = xenevtchn_open(NULL, 0);
		if (xce_handle == NULL) {
			dolog(LOG_ERR, "Failed to open xce handle: %d (%s)",
			      errno, strerror(errno));
			goto out;
		}
		log_hv_fd = create_hv_log();
		if (log_hv_fd == -1)
			goto out;
		log_hv_evtchn = xenevtchn_bind_virq(xce_handle, VIRQ_CON_RING);
		if (log_hv_evtchn == -1) {
			dolog(LOG_ERR, "Failed to bind to VIRQ_CON_RING: "
			      "%d (%s)", errno, strerror(errno));
			goto out;
		}
		/* Log the boot dmesg even if VIRQ_CON_RING isn't pending. */
		handle_hv_logs(xce_handle, true);
	}

	xgt_handle = xengnttab_open(NULL, 0);
	if (xgt_handle == NULL) {
		dolog(LOG_DEBUG, "Failed to open xcg handle: %d (%s)",
		      errno, strerror(errno));
	}

	enum_domains();

	for (;;) {
		struct domain *d, *n;
		int poll_timeout; /* timeout in milliseconds */
		struct timespec ts;
		long long now, next_timeout = 0;

		reset_fds();

		xs_pollfd_idx = set_fds(xs_fileno(xs), POLLIN|POLLPRI);

		if (log_hv)
			xce_pollfd_idx = set_fds(xenevtchn_fd(xce_handle),
						 POLLIN|POLLPRI);

		if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
			break;
		now = ((long long)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);

		/* Re-calculate any event counter allowances & unblock
		   domains with new allowance */
		for (d = dom_head; d; d = d->next) {

			console_iter_void_arg2(d, console_evtchn_unmask, (void *)&now);

			console_iter_void_arg2(d, maybe_add_console_evtchn_fd, 
					       (void *)&next_timeout);

			console_iter_void_arg1(d, maybe_add_console_tty_fd);
		}

		/* If any domain has been rate limited, we need to work
		   out what timeout to supply to poll */
		if (next_timeout) {
			long long duration = (next_timeout - now);
			if (duration <= 0) /* sanity check */
				duration = 1;
			poll_timeout = (int)duration;
		}

		ret = poll(fds, nr_fds, next_timeout ? poll_timeout : -1);

		if (log_reload) {
			int saved_errno = errno;

			handle_log_reload();
			log_reload = 0;

			errno = saved_errno;
		}

		/* Abort if poll failed, except for EINTR cases
		   which indicate a possible log reload */
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			dolog(LOG_ERR, "Failure in poll: %d (%s)",
			      errno, strerror(errno));
			break;
		}

		if (log_hv && xce_pollfd_idx != -1) {
			if (fds[xce_pollfd_idx].revents & ~(POLLIN|POLLOUT|POLLPRI)) {
				dolog(LOG_ERR,
				      "Failure in poll xce_handle: %d (%s)",
				      errno, strerror(errno));
				break;
			} else if (fds[xce_pollfd_idx].revents & POLLIN)
				handle_hv_logs(xce_handle, false);

			xce_pollfd_idx = -1;
		}

		if (ret <= 0)
			continue;

		if (xs_pollfd_idx != -1) {
			if (fds[xs_pollfd_idx].revents & ~(POLLIN|POLLOUT|POLLPRI)) {
				dolog(LOG_ERR,
				      "Failure in poll xs_handle: %d (%s)",
				      errno, strerror(errno));
				break;
			} else if (fds[xs_pollfd_idx].revents & POLLIN)
				handle_xs();

			xs_pollfd_idx = -1;
		}

		for (d = dom_head; d; d = n) {

			n = d->next;

			console_iter_void_arg1(d, handle_console_ring);

			console_iter_void_arg1(d, handle_console_tty);

			if (d->last_seen != enum_pass)
				shutdown_domain(d);

			if (d->is_dead)
				cleanup_domain(d);
		}
	}

	free(fds);
	current_array_size = 0;

 out:
	if (log_hv_fd != -1) {
		close(log_hv_fd);
		log_hv_fd = -1;
	}
	if (xce_handle != NULL) {
		xenevtchn_close(xce_handle);
		xce_handle = NULL;
	}
	if (xgt_handle != NULL) {
		xengnttab_close(xgt_handle);
		xgt_handle = NULL;
	}
	log_hv_evtchn = -1;
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
