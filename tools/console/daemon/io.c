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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE

#include "utils.h"
#include "io.h"
#include <xs.h>
#include <xen/io/console.h>
#include <xenctrl.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <assert.h>
#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <util.h>
#elif defined(__linux__)
#include <pty.h>
#elif defined(__sun__)
#include <stropts.h>
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

static int log_time_hv_needts = 1;
static int log_time_guest_needts = 1;
static int log_hv_fd = -1;
static evtchn_port_or_error_t log_hv_evtchn = -1;
static int xc_handle = -1;
static int xce_handle = -1;

struct buffer {
	char *data;
	size_t consumed;
	size_t size;
	size_t capacity;
	size_t max_capacity;
};

struct domain {
	int domid;
	int master_fd;
	int slave_fd;
	int log_fd;
	bool is_dead;
	struct buffer buffer;
	struct domain *next;
	char *conspath;
	char *serialpath;
	int use_consolepath;
	int ring_ref;
	evtchn_port_or_error_t local_port;
	evtchn_port_or_error_t remote_port;
	int xce_handle;
	struct xencons_interface *interface;
	int event_count;
	long long next_period;
};

static struct domain *dom_head;

static int write_all(int fd, const char* buf, size_t len)
{
	while (len) {
		ssize_t ret = write(fd, buf, len);
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

static void buffer_append(struct domain *dom)
{
	struct buffer *buffer = &dom->buffer;
	XENCONS_RING_IDX cons, prod, size;
	struct xencons_interface *intf = dom->interface;

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
	xc_evtchn_notify(dom->xce_handle, dom->local_port);

	/* Get the data to the logfile as early as possible because if
	 * no one is listening on the console pty then it will fill up
	 * and handle_tty_write will stop being called.
	 */
	if (dom->log_fd != -1) {
		int logret;
		if (log_time_guest) {
			logret = write_with_timestamp(
				dom->log_fd,
				buffer->data + buffer->size - size,
				size, &log_time_guest_needts);
		} else {
			logret = write_all(
				dom->log_fd,
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
		if (write_with_timestamp(fd, "Logfile Opened",
					 strlen("Logfile Opened"),
					 &log_time_hv_needts) < 0) {
			dolog(LOG_ERR, "Failed to log opening timestamp "
				       "in %s: %d (%s)", logfile, errno,
				       strerror(errno));
			return -1;
		}
	}
	return fd;
}

static int create_domain_log(struct domain *dom)
{
	char logfile[PATH_MAX];
	char *namepath, *data, *s;
	int fd;
	unsigned int len;

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

	snprintf(logfile, PATH_MAX-1, "%s/guest-%s.log", log_dir, data);
	free(data);
	logfile[PATH_MAX-1] = '\0';

	fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0644);
	if (fd == -1)
		dolog(LOG_ERR, "Failed to open log %s: %d (%s)",
		      logfile, errno, strerror(errno));
	if (fd != -1 && log_time_guest) {
		if (write_with_timestamp(fd, "Logfile Opened",
					 strlen("Logfile Opened"),
					 &log_time_guest_needts) < 0) {
			dolog(LOG_ERR, "Failed to log opening timestamp "
				       "in %s: %d (%s)", logfile, errno,
				       strerror(errno));
			return -1;
		}
	}
	return fd;
}

static void domain_close_tty(struct domain *dom)
{
	if (dom->master_fd != -1) {
		close(dom->master_fd);
		dom->master_fd = -1;
	}

	if (dom->slave_fd != -1) {
		close(dom->slave_fd);
		dom->slave_fd = -1;
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

static int domain_create_tty(struct domain *dom)
{
	const char *slave;
	char *path;
	int err;
	bool success;
	char *data;
	unsigned int len;
	struct termios term;

	assert(dom->slave_fd == -1);
	assert(dom->master_fd == -1);

	if (openpty(&dom->master_fd, &dom->slave_fd, NULL, NULL, NULL) < 0) {
		err = errno;
		dolog(LOG_ERR, "Failed to create tty for domain-%d "
		      "(errno = %i, %s)",
		      dom->domid, err, strerror(err));
		return 0;
	}

	if (tcgetattr(dom->slave_fd, &term) < 0) {
		err = errno;
		dolog(LOG_ERR, "Failed to get tty attributes for domain-%d "
			"(errno = %i, %s)",
			dom->domid, err, strerror(err));
		goto out;
	}
	cfmakeraw(&term);
	if (tcsetattr(dom->slave_fd, TCSANOW, &term) < 0) {
		err = errno;
		dolog(LOG_ERR, "Failed to set tty attributes for domain-%d "
			"(errno = %i, %s)",
			dom->domid, err, strerror(err));
		goto out;
	}

	if ((slave = ptsname(dom->master_fd)) == NULL) {
		err = errno;
		dolog(LOG_ERR, "Failed to get slave name for domain-%d "
		      "(errno = %i, %s)",
		      dom->domid, err, strerror(err));
		goto out;
	}

	if (dom->use_consolepath) {
		success = asprintf(&path, "%s/limit", dom->conspath) !=
			-1;
		if (!success)
			goto out;
		data = xs_read(xs, XBT_NULL, path, &len);
		if (data) {
			dom->buffer.max_capacity = strtoul(data, 0, 0);
			free(data);
		}
		free(path);
	}

	success = asprintf(&path, "%s/limit", dom->serialpath) != -1;
	if (!success)
		goto out;
	data = xs_read(xs, XBT_NULL, path, &len);
	if (data) {
		dom->buffer.max_capacity = strtoul(data, 0, 0);
		free(data);
	}
	free(path);

	success = asprintf(&path, "%s/tty", dom->serialpath) != -1;
	if (!success)
		goto out;
	success = xs_write(xs, XBT_NULL, path, slave, strlen(slave));
	free(path);
	if (!success)
		goto out;

	if (dom->use_consolepath) {
		success = (asprintf(&path, "%s/tty", dom->conspath) != -1);
		if (!success)
			goto out;
		success = xs_write(xs, XBT_NULL, path, slave, strlen(slave));
		free(path);
		if (!success)
			goto out;
	}

	if (fcntl(dom->master_fd, F_SETFL, O_NONBLOCK) == -1)
		goto out;

	return 1;
out:
	domain_close_tty(dom);
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

static int domain_create_ring(struct domain *dom)
{
	int err, remote_port, ring_ref, rc;
	char *type, path[PATH_MAX];

	err = xs_gather(xs, dom->serialpath,
			"ring-ref", "%u", &ring_ref,
			"port", "%i", &remote_port,
			NULL);
	if (err) {
		err = xs_gather(xs, dom->conspath,
				"ring-ref", "%u", &ring_ref,
				"port", "%i", &remote_port,
				NULL);
		if (err)
			goto out;
		dom->use_consolepath = 1;
	} else
		dom->use_consolepath = 0;

	snprintf(path, sizeof(path), "%s/type",
		dom->use_consolepath ? dom->conspath: dom->serialpath);
	type = xs_read(xs, XBT_NULL, path, NULL);
	if (type && strcmp(type, "xenconsoled") != 0) {
		free(type);
		return 0;
	}
	free(type);

	if (ring_ref != dom->ring_ref) {
		if (dom->interface != NULL)
			munmap(dom->interface, getpagesize());
		dom->interface = xc_map_foreign_range(
			xc, dom->domid, getpagesize(),
			PROT_READ|PROT_WRITE,
			(unsigned long)ring_ref);
		if (dom->interface == NULL) {
			err = EINVAL;
			goto out;
		}
		dom->ring_ref = ring_ref;
	}

	/* Go no further if port has not changed and we are still bound. */
	if (remote_port == dom->remote_port) {
		xc_evtchn_status_t status = {
			.dom = DOMID_SELF,
			.port = dom->local_port };
		if ((xc_evtchn_status(xc, &status) == 0) &&
		    (status.status == EVTCHNSTAT_interdomain))
			goto out;
	}

	dom->local_port = -1;
	dom->remote_port = -1;
	if (dom->xce_handle != -1)
		xc_evtchn_close(dom->xce_handle);

	/* Opening evtchn independently for each console is a bit
	 * wasteful, but that's how the code is structured... */
	dom->xce_handle = xc_evtchn_open();
	if (dom->xce_handle == -1) {
		err = errno;
		goto out;
	}
 
	rc = xc_evtchn_bind_interdomain(dom->xce_handle,
		dom->domid, remote_port);

	if (rc == -1) {
		err = errno;
		xc_evtchn_close(dom->xce_handle);
		dom->xce_handle = -1;
		goto out;
	}
	dom->local_port = rc;
	dom->remote_port = remote_port;

	if (dom->master_fd == -1) {
		if (!domain_create_tty(dom)) {
			err = errno;
			xc_evtchn_close(dom->xce_handle);
			dom->xce_handle = -1;
			dom->local_port = -1;
			dom->remote_port = -1;
			goto out;
		}
	}

	if (log_guest && (dom->log_fd == -1))
		dom->log_fd = create_domain_log(dom);

 out:
	return err;
}

static bool watch_domain(struct domain *dom, bool watch)
{
	char domid_str[3 + MAX_STRLEN(dom->domid)];
	bool success;

	snprintf(domid_str, sizeof(domid_str), "dom%u", dom->domid);
	if (watch) {
		success = xs_watch(xs, dom->serialpath, domid_str);
		if (success) {
			success = xs_watch(xs, dom->conspath, domid_str);
			if (success)
				domain_create_ring(dom);
			else
				xs_unwatch(xs, dom->serialpath, domid_str);
		}
	} else {
		success = xs_unwatch(xs, dom->serialpath, domid_str);
		success = xs_unwatch(xs, dom->conspath, domid_str);
	}

	return success;
}


static struct domain *create_domain(int domid)
{
	struct domain *dom;
	char *s;
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
		dolog(LOG_ERR, "Cannot get time of day %s:%s:L%d",
		      __FILE__, __FUNCTION__, __LINE__);
		return NULL;
	}

	dom = (struct domain *)malloc(sizeof(struct domain));
	if (dom == NULL) {
		dolog(LOG_ERR, "Out of memory %s:%s():L%d",
		      __FILE__, __FUNCTION__, __LINE__);
		exit(ENOMEM);
	}

	dom->domid = domid;

	dom->serialpath = xs_get_domain_path(xs, dom->domid);
	s = realloc(dom->serialpath, strlen(dom->serialpath) +
		    strlen("/serial/0") + 1);
	if (s == NULL)
		goto out;
	dom->serialpath = s;
	strcat(dom->serialpath, "/serial/0");

	dom->conspath = xs_get_domain_path(xs, dom->domid);
	s = realloc(dom->conspath, strlen(dom->conspath) +
		    strlen("/console") + 1);
	if (s == NULL)
		goto out;
	dom->conspath = s;
	strcat(dom->conspath, "/console");

	dom->master_fd = -1;
	dom->slave_fd = -1;
	dom->log_fd = -1;

	dom->is_dead = false;
	dom->buffer.data = 0;
	dom->buffer.consumed = 0;
	dom->buffer.size = 0;
	dom->buffer.capacity = 0;
	dom->buffer.max_capacity = 0;
	dom->event_count = 0;
	dom->next_period = ((long long)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000) + RATE_LIMIT_PERIOD;
	dom->next = NULL;

	dom->ring_ref = -1;
	dom->local_port = -1;
	dom->remote_port = -1;
	dom->interface = NULL;
	dom->xce_handle = -1;

	if (!watch_domain(dom, true))
		goto out;

	dom->next = dom_head;
	dom_head = dom;

	dolog(LOG_DEBUG, "New domain %d", domid);

	return dom;
 out:
	free(dom->serialpath);
	free(dom->conspath);
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

static void cleanup_domain(struct domain *d)
{
	domain_close_tty(d);

	free(d->buffer.data);
	d->buffer.data = NULL;

	free(d->serialpath);
	d->serialpath = NULL;

	free(d->conspath);
	d->conspath = NULL;

	remove_domain(d);
}

static void shutdown_domain(struct domain *d)
{
	d->is_dead = true;
	watch_domain(d, false);
	if (d->interface != NULL)
		munmap(d->interface, getpagesize());
	d->interface = NULL;
	if (d->xce_handle != -1)
		xc_evtchn_close(d->xce_handle);
	d->xce_handle = -1;
}

void enum_domains(void)
{
	int domid = 1;
	xc_dominfo_t dominfo;
	struct domain *dom;

	while (xc_domain_getinfo(xc, domid, 1, &dominfo) == 1) {
		dom = lookup_domain(dominfo.domid);
		if (dominfo.dying) {
			if (dom)
				shutdown_domain(dom);
		} else {
			if (dom == NULL)
				create_domain(dominfo.domid);
		}
		domid = dominfo.domid + 1;
	}
}

static int ring_free_bytes(struct domain *dom)
{
	struct xencons_interface *intf = dom->interface;
	XENCONS_RING_IDX cons, prod, space;

	cons = intf->in_cons;
	prod = intf->in_prod;
	xen_mb();

	space = prod - cons;
	if (space > sizeof(intf->in))
		return 0; /* ring is screwed: ignore it */

	return (sizeof(intf->in) - space);
}

static void handle_tty_read(struct domain *dom)
{
	ssize_t len = 0;
	char msg[80];
	int i;
	struct xencons_interface *intf = dom->interface;
	XENCONS_RING_IDX prod;

	if (dom->is_dead)
		return;

	len = ring_free_bytes(dom);
	if (len == 0)
		return;

	if (len > sizeof(msg))
		len = sizeof(msg);

	len = read(dom->master_fd, msg, len);
	/*
	 * Note: on Solaris, len == 0 means the slave closed, and this
	 * is no problem, but Linux can't handle this usefully, so we
	 * keep the slave open for the duration.
	 */
	if (len < 0) {
		domain_close_tty(dom);

		if (domain_is_valid(dom->domid)) {
			domain_create_tty(dom);
		} else {
			shutdown_domain(dom);
		}
	} else if (domain_is_valid(dom->domid)) {
		prod = intf->in_prod;
		for (i = 0; i < len; i++) {
			intf->in[MASK_XENCONS_IDX(prod++, intf->in)] =
				msg[i];
		}
		xen_wmb();
		intf->in_prod = prod;
		xc_evtchn_notify(dom->xce_handle, dom->local_port);
	} else {
		domain_close_tty(dom);
		shutdown_domain(dom);
	}
}

static void handle_tty_write(struct domain *dom)
{
	ssize_t len;

	if (dom->is_dead)
		return;

	len = write(dom->master_fd, dom->buffer.data + dom->buffer.consumed,
		    dom->buffer.size - dom->buffer.consumed);
 	if (len < 1) {
		dolog(LOG_DEBUG, "Write failed on domain %d: %zd, %d\n",
		      dom->domid, len, errno);

		domain_close_tty(dom);

		if (domain_is_valid(dom->domid)) {
			domain_create_tty(dom);
		} else {
			shutdown_domain(dom);
		}
	} else {
		buffer_advance(&dom->buffer, len);
	}
}

static void handle_ring_read(struct domain *dom)
{
	evtchn_port_or_error_t port;

	if (dom->is_dead)
		return;

	if ((port = xc_evtchn_pending(dom->xce_handle)) == -1)
		return;

	dom->event_count++;

	buffer_append(dom);

	if (dom->event_count < RATE_LIMIT_ALLOWANCE)
		(void)xc_evtchn_unmask(dom->xce_handle, port);
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
			domain_create_ring(dom);
	}

	free(vec);
}

static void handle_hv_logs(void)
{
	char buffer[1024*16];
	char *bufptr = buffer;
	unsigned int size = sizeof(buffer);
	static uint32_t index = 0;
	evtchn_port_or_error_t port;

	if ((port = xc_evtchn_pending(xce_handle)) == -1)
		return;

	if (xc_readconsolering(xc_handle, &bufptr, &size, 0, 1, &index) == 0 && size > 0) {
		int logret;
		if (log_time_hv)
			logret = write_with_timestamp(log_hv_fd, buffer, size,
						      &log_time_hv_needts);
		else
			logret = write_all(log_hv_fd, buffer, size);

		if (logret < 0)
			dolog(LOG_ERR, "Failed to write hypervisor log: "
				       "%d (%s)", errno, strerror(errno));
	}

	(void)xc_evtchn_unmask(xce_handle, port);
}

static void handle_log_reload(void)
{
	if (log_guest) {
		struct domain *d;
		for (d = dom_head; d; d = d->next) {
			if (d->log_fd != -1)
				close(d->log_fd);
			d->log_fd = create_domain_log(d);
		}
	}

	if (log_hv) {
		if (log_hv_fd != -1)
			close(log_hv_fd);
		log_hv_fd = create_hv_log();
	}
}

void handle_io(void)
{
	fd_set readfds, writefds;
	int ret;

	if (log_hv) {
		xc_handle = xc_interface_open();
		if (xc_handle == -1) {
			dolog(LOG_ERR, "Failed to open xc handle: %d (%s)",
			      errno, strerror(errno));
			goto out;
		}
		xce_handle = xc_evtchn_open();
		if (xce_handle == -1) {
			dolog(LOG_ERR, "Failed to open xce handle: %d (%s)",
			      errno, strerror(errno));
			goto out;
		}
		log_hv_fd = create_hv_log();
		if (log_hv_fd == -1)
			goto out;
		log_hv_evtchn = xc_evtchn_bind_virq(xce_handle, VIRQ_CON_RING);
		if (log_hv_evtchn == -1) {
			dolog(LOG_ERR, "Failed to bind to VIRQ_CON_RING: "
			      "%d (%s)", errno, strerror(errno));
			goto out;
		}
	}

	for (;;) {
		struct domain *d, *n;
		int max_fd = -1;
		struct timeval timeout;
		struct timespec ts;
		long long now, next_timeout = 0;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(xs_fileno(xs), &readfds);
		max_fd = MAX(xs_fileno(xs), max_fd);

		if (log_hv) {
			FD_SET(xc_evtchn_fd(xce_handle), &readfds);
			max_fd = MAX(xc_evtchn_fd(xce_handle), max_fd);
		}

		if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
			return;
		now = ((long long)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);

		/* Re-calculate any event counter allowances & unblock
		   domains with new allowance */
		for (d = dom_head; d; d = d->next) {
			/* Add 5ms of fuzz since select() often returns
			   a couple of ms sooner than requested. Without
			   the fuzz we typically do an extra spin in select()
			   with a 1/2 ms timeout every other iteration */
			if ((now+5) > d->next_period) {
				d->next_period = now + RATE_LIMIT_PERIOD;
				if (d->event_count >= RATE_LIMIT_ALLOWANCE) {
					(void)xc_evtchn_unmask(d->xce_handle, d->local_port);
				}
				d->event_count = 0;
			}
		}

		for (d = dom_head; d; d = d->next) {
			if (d->event_count >= RATE_LIMIT_ALLOWANCE) {
				/* Determine if we're going to be the next time slice to expire */
				if (!next_timeout ||
				    d->next_period < next_timeout)
					next_timeout = d->next_period;
			} else if (d->xce_handle != -1) {
				if (discard_overflowed_data ||
				    !d->buffer.max_capacity ||
				    d->buffer.size < d->buffer.max_capacity) {
					int evtchn_fd = xc_evtchn_fd(d->xce_handle);
					FD_SET(evtchn_fd, &readfds);
					max_fd = MAX(evtchn_fd, max_fd);
				}
			}

			if (d->master_fd != -1) {
				if (!d->is_dead && ring_free_bytes(d))
					FD_SET(d->master_fd, &readfds);

				if (!buffer_empty(&d->buffer))
					FD_SET(d->master_fd, &writefds);
				max_fd = MAX(d->master_fd, max_fd);
			}
		}

		/* If any domain has been rate limited, we need to work
		   out what timeout to supply to select */
		if (next_timeout) {
			long long duration = (next_timeout - now);
			if (duration <= 0) /* sanity check */
				duration = 1;
			timeout.tv_sec = duration / 1000;
			timeout.tv_usec = ((duration - (timeout.tv_sec * 1000))
					   * 1000);
		}

		ret = select(max_fd + 1, &readfds, &writefds, 0,
			     next_timeout ? &timeout : NULL);

		if (log_reload) {
			handle_log_reload();
			log_reload = 0;
		}

		/* Abort if select failed, except for EINTR cases
		   which indicate a possible log reload */
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			dolog(LOG_ERR, "Failure in select: %d (%s)",
			      errno, strerror(errno));
			break;
		}

		if (log_hv && FD_ISSET(xc_evtchn_fd(xce_handle), &readfds))
			handle_hv_logs();

		if (ret <= 0)
			continue;

		if (FD_ISSET(xs_fileno(xs), &readfds))
			handle_xs();

		for (d = dom_head; d; d = n) {
			n = d->next;
			if (d->event_count < RATE_LIMIT_ALLOWANCE) {
				if (d->xce_handle != -1 &&
				    FD_ISSET(xc_evtchn_fd(d->xce_handle),
					     &readfds))
					handle_ring_read(d);
			}

			if (d->master_fd != -1 && FD_ISSET(d->master_fd,
							   &readfds))
				handle_tty_read(d);

			if (d->master_fd != -1 && FD_ISSET(d->master_fd,
							   &writefds))
				handle_tty_write(d);

			if (d->is_dead)
				cleanup_domain(d);
		}
	}

 out:
	if (log_hv_fd != -1) {
		close(log_hv_fd);
		log_hv_fd = -1;
	}
	if (xc_handle != -1) {
		xc_interface_close(xc_handle);
		xc_handle = -1;
	}
	if (xce_handle != -1) {
		xc_evtchn_close(xce_handle);
		xce_handle = -1;
	}
	log_hv_evtchn = -1;
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
