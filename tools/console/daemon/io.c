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
#include <xenctrl.h>
#include <xs.h>
#include <xen/linux/evtchn.h>
#include <xen/io/console.h>

#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/* Each 10 bits takes ~ 3 digits, plus one, plus one for nul terminator. */
#define MAX_STRLEN(x) ((sizeof(x) * CHAR_BIT + CHAR_BIT-1) / 10 * 3 + 2)

struct buffer
{
	char *data;
	size_t size;
	size_t capacity;
	size_t max_capacity;
};

struct domain
{
	int domid;
	int tty_fd;
	bool is_dead;
	struct buffer buffer;
	struct domain *next;
	char *conspath;
	int ring_ref;
	int local_port;
	int evtchn_fd;
	struct xencons_interface *interface;
};

static struct domain *dom_head;

static void evtchn_notify(struct domain *dom)
{
	struct ioctl_evtchn_notify notify;
	notify.port = dom->local_port;
	(void)ioctl(dom->evtchn_fd, IOCTL_EVTCHN_NOTIFY, &notify);
}

static void buffer_append(struct domain *dom)
{
	struct buffer *buffer = &dom->buffer;
	XENCONS_RING_IDX cons, prod, size;
	struct xencons_interface *intf = dom->interface;

	cons = intf->out_cons;
	prod = intf->out_prod;
	mb();

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

	mb();
	intf->out_cons = cons;
	evtchn_notify(dom);

	if (buffer->max_capacity &&
	    buffer->size > buffer->max_capacity) {
		memmove(buffer->data + (buffer->size -
					buffer->max_capacity),
			buffer->data, buffer->max_capacity);
		buffer->data = realloc(buffer->data,
				       buffer->max_capacity);
		buffer->size = buffer->capacity = buffer->max_capacity;
	}
}

static bool buffer_empty(struct buffer *buffer)
{
	return buffer->size == 0;
}

static void buffer_advance(struct buffer *buffer, size_t size)
{
	size = MIN(size, buffer->size);
	memmove(buffer->data, buffer + size, buffer->size - size);
	buffer->size -= size;
}

static bool domain_is_valid(int domid)
{
	bool ret;
	xc_dominfo_t info;

	ret = (xc_domain_getinfo(xc, domid, 1, &info) == 1 &&
	       info.domid == domid);
		
	return ret;
}

static int domain_create_tty(struct domain *dom)
{
	char *path;
	int master;
	bool success;

	if ((master = getpt()) == -1 ||
	    grantpt(master) == -1 || unlockpt(master) == -1) {
		dolog(LOG_ERR, "Failed to create tty for domain-%d",
		      dom->domid);
		master = -1;
	} else {
		const char *slave = ptsname(master);
		struct termios term;
		char *data;
		unsigned int len;

		if (tcgetattr(master, &term) != -1) {
			cfmakeraw(&term);
			tcsetattr(master, TCSAFLUSH, &term);
		}

		success = asprintf(&path, "%s/limit", dom->conspath) != -1;
		if (!success)
			goto out;
		data = xs_read(xs, NULL, path, &len);
		if (data) {
			dom->buffer.max_capacity = strtoul(data, 0, 0);
			free(data);
		}
		free(path);

		success = asprintf(&path, "%s/tty", dom->conspath) != -1;
		if (!success)
			goto out;
		success = xs_write(xs, NULL, path, slave, strlen(slave));
		free(path);
		if (!success)
			goto out;
	}

	return master;
 out:
	close(master);
	return -1;
}

/* Takes tuples of names, scanf-style args, and void **, NULL terminated. */
int xs_gather(struct xs_handle *xs, const char *dir, ...)
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

		asprintf(&path, "%s/%s", dir, name);
		p = xs_read(xs, NULL, path, NULL);
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
	struct ioctl_evtchn_bind_interdomain bind;

	err = xs_gather(xs, dom->conspath,
			"ring-ref", "%u", &ring_ref,
			"port", "%i", &remote_port,
			NULL);
	if (err)
		goto out;

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

	dom->local_port = -1;
	if (dom->evtchn_fd != -1)
		close(dom->evtchn_fd);

	/* Opening evtchn independently for each console is a bit
	 * wasteful, but that's how the code is structured... */
	dom->evtchn_fd = open("/dev/xen/evtchn", O_RDWR);
	if (dom->evtchn_fd == -1) {
		err = errno;
		goto out;
	}
 
	bind.remote_domain = dom->domid;
	bind.remote_port   = remote_port;
	rc = ioctl(dom->evtchn_fd, IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
	if (rc == -1) {
		err = errno;
		close(dom->evtchn_fd);
		dom->evtchn_fd = -1;
		goto out;
	}
	dom->local_port = rc;

	if (dom->tty_fd == -1) {
		dom->tty_fd = domain_create_tty(dom);

		if (dom->tty_fd == -1) {
			err = errno;
			close(dom->evtchn_fd);
			dom->evtchn_fd = -1;
			dom->local_port = -1;
			goto out;
		}
	}

 out:
	return err;
}

static bool watch_domain(struct domain *dom, bool watch)
{
	char domid_str[3 + MAX_STRLEN(dom->domid)];
	bool success;

	sprintf(domid_str, "dom%u", dom->domid);
	if (watch)
		success = xs_watch(xs, dom->conspath, domid_str);
	else
		success = xs_unwatch(xs, dom->conspath, domid_str);
	if (success)
		domain_create_ring(dom);
	return success;
}

static struct domain *create_domain(int domid)
{
	struct domain *dom;
	char *s;

	dom = (struct domain *)malloc(sizeof(struct domain));
	if (dom == NULL) {
		dolog(LOG_ERR, "Out of memory %s:%s():L%d",
		      __FILE__, __FUNCTION__, __LINE__);
		exit(ENOMEM);
	}

	dom->domid = domid;
	dom->conspath = xs_get_domain_path(xs, dom->domid);
	s = realloc(dom->conspath, strlen(dom->conspath) +
		    strlen("/console") + 1);
	if (s == NULL)
		goto out;
	dom->conspath = s;
	strcat(dom->conspath, "/console");

	dom->tty_fd = -1;
	dom->is_dead = false;
	dom->buffer.data = 0;
	dom->buffer.size = 0;
	dom->buffer.capacity = 0;
	dom->buffer.max_capacity = 0;
	dom->next = NULL;

	dom->ring_ref = -1;
	dom->local_port = -1;
	dom->interface = NULL;
	dom->evtchn_fd = -1;

	if (!watch_domain(dom, true))
		goto out;

	dom->next = dom_head;
	dom_head = dom;

	dolog(LOG_DEBUG, "New domain %d", domid);

	return dom;
 out:
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
	if (!buffer_empty(&d->buffer))
		return;

	if (d->tty_fd != -1) {
		close(d->tty_fd);
		d->tty_fd = -1;
	}

	free(d->buffer.data);
	d->buffer.data = NULL;

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
	if (d->evtchn_fd != -1)
		close(d->evtchn_fd);
	d->evtchn_fd = -1;
	cleanup_domain(d);
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

static void handle_tty_read(struct domain *dom)
{
	ssize_t len = 0;
	char msg[80];
	int i;
	struct xencons_interface *intf = dom->interface;
	XENCONS_RING_IDX cons, prod;

	cons = intf->in_cons;
	prod = intf->in_prod;
	mb();

	if (sizeof(intf->in) > (prod - cons))
		len = sizeof(intf->in) - (prod - cons);
	if (len > sizeof(msg))
		len = sizeof(msg);

	if (len == 0)
		return;

	len = read(dom->tty_fd, msg, len);
	if (len < 1) {
		close(dom->tty_fd);
		dom->tty_fd = -1;

		if (domain_is_valid(dom->domid)) {
			dom->tty_fd = domain_create_tty(dom);
		} else {
			shutdown_domain(dom);
		}
	} else if (domain_is_valid(dom->domid)) {
		for (i = 0; i < len; i++) {
			intf->in[MASK_XENCONS_IDX(prod++, intf->in)] =
				msg[i];
		}
		wmb();
		intf->in_prod = prod;
		evtchn_notify(dom);
	} else {
		close(dom->tty_fd);
		dom->tty_fd = -1;
		shutdown_domain(dom);
	}
}

static void handle_tty_write(struct domain *dom)
{
	ssize_t len;

	len = write(dom->tty_fd, dom->buffer.data, dom->buffer.size);
	if (len < 1) {
		close(dom->tty_fd);
		dom->tty_fd = -1;

		if (domain_is_valid(dom->domid)) {
			dom->tty_fd = domain_create_tty(dom);
		} else {
			shutdown_domain(dom);
		}
	} else {
		buffer_advance(&dom->buffer, len);
	}
}

static void handle_ring_read(struct domain *dom)
{
	uint16_t v;

	if (!read_sync(dom->evtchn_fd, &v, sizeof(v)))
		return;

	buffer_append(dom);

	(void)write_sync(dom->evtchn_fd, &v, sizeof(v));
}

static void handle_xs(int fd)
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

void handle_io(void)
{
	fd_set readfds, writefds;
	int ret;

	do {
		struct domain *d, *n;
		struct timeval tv = { 100, 0 };
		int max_fd = -1;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(xs_fileno(xs), &readfds);
		max_fd = MAX(xs_fileno(xs), max_fd);

		for (d = dom_head; d; d = d->next) {
			if (d->evtchn_fd != -1) {
				FD_SET(d->evtchn_fd, &readfds);
				max_fd = MAX(d->evtchn_fd, max_fd);
			}

			if (d->tty_fd != -1) {
				if (!d->is_dead)
					FD_SET(d->tty_fd, &readfds);

				if (!buffer_empty(&d->buffer))
					FD_SET(d->tty_fd, &writefds);
				max_fd = MAX(d->tty_fd, max_fd);
			}
		}

		ret = select(max_fd + 1, &readfds, &writefds, 0, &tv);

		if (FD_ISSET(xs_fileno(xs), &readfds))
			handle_xs(xs_fileno(xs));

		for (d = dom_head; d; d = n) {
			n = d->next;
			if (d->evtchn_fd != -1 &&
			    FD_ISSET(d->evtchn_fd, &readfds))
				handle_ring_read(d);

			if (d->tty_fd != -1) {
				if (FD_ISSET(d->tty_fd, &readfds))
					handle_tty_read(d);

				if (FD_ISSET(d->tty_fd, &writefds))
					handle_tty_write(d);

				if (d->is_dead)
					cleanup_domain(d);
			}
		}
	} while (ret > -1);
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
