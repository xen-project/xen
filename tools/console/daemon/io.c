/*\
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
\*/

#define _GNU_SOURCE

#include "utils.h"
#include "io.h"

#include "xenctrl.h"
#include "xs.h"
#include "xen/io/domain_controller.h"
#include "xcs_proto.h"

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
	unsigned long mfn;
	int local_port;
	int remote_port;
	char *page;
	int evtchn_fd;
};

static struct domain *dom_head;

struct ring_head
{
	u32 cons;
	u32 prod;
	char buf[0];
} __attribute__((packed));

#define PAGE_SIZE (getpagesize())
#define XENCONS_RING_SIZE (PAGE_SIZE/2 - sizeof (struct ring_head))
#define XENCONS_IDX(cnt) ((cnt) % XENCONS_RING_SIZE)
#define XENCONS_FULL(ring) (((ring)->prod - (ring)->cons) == XENCONS_RING_SIZE)
#define XENCONS_SPACE(ring) (XENCONS_RING_SIZE - ((ring)->prod - (ring)->cons))

static void buffer_append(struct domain *dom)
{
	struct buffer *buffer = &dom->buffer;
	struct ring_head *ring = (struct ring_head *)dom->page;
	size_t size;

	while ((size = ring->prod - ring->cons) != 0) {
		if ((buffer->capacity - buffer->size) < size) {
			buffer->capacity += (size + 1024);
			buffer->data = realloc(buffer->data, buffer->capacity);
			if (buffer->data == NULL) {
				dolog(LOG_ERR, "Memory allocation failed");
				exit(ENOMEM);
			}
		}

		while (ring->cons < ring->prod) {
			buffer->data[buffer->size] =
				ring->buf[XENCONS_IDX(ring->cons)];
			buffer->size++;
			ring->cons++;
		}

		if (buffer->max_capacity &&
		    buffer->size > buffer->max_capacity) {
			memmove(buffer->data + (buffer->size -
						buffer->max_capacity),
				buffer->data, buffer->max_capacity);
			buffer->data = realloc(buffer->data,
					       buffer->max_capacity);
			buffer->capacity = buffer->max_capacity;
		}
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

		asprintf(&path, "/console/%d/tty", dom->domid);
		xs_write(xs, path, slave, strlen(slave), O_CREAT);
		free(path);

		asprintf(&path, "/console/%d/limit", dom->domid);
		data = xs_read(xs, path, &len);
		if (data) {
			dom->buffer.max_capacity = strtoul(data, 0, 0);
			free(data);
		}
		free(path);
	}

	return master;
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
		p = xs_read(xs, path, NULL);
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

#define EVENTCHN_BIND		_IO('E', 2)
#define EVENTCHN_UNBIND 	_IO('E', 3)

static int domain_create_ring(struct domain *dom)
{
	char *dompath, *path;
	int err;

	dom->page = NULL;
	dom->evtchn_fd = -1;

	asprintf(&path, "/console/%d/domain", dom->domid);
	dompath = xs_read(xs, path, NULL);
	free(path);
	if (!dompath)
		return ENOENT;

	err = xs_gather(xs, dompath,
			"console_mfn", "%li", &dom->mfn,
			"console_channel/port1", "%i", &dom->local_port,
			"console_channel/port2", "%i", &dom->remote_port,
			NULL);
	if (err)
		goto out;

	dom->page = xc_map_foreign_range(xc, dom->domid, getpagesize(),
					 PROT_READ|PROT_WRITE, dom->mfn);
	if (dom->page == NULL) {
		err = EINVAL;
		goto out;
	}

	/* Opening evtchn independently for each console is a bit
	 * wastefule, but that's how the code is structured... */
	err = open("/dev/xen/evtchn", O_RDWR);
	if (err == -1) {
		err = errno;
		goto out;
	}
	dom->evtchn_fd = err;

	if (ioctl(dom->evtchn_fd, EVENTCHN_BIND, dom->local_port) == -1) {
		err = errno;
		munmap(dom->page, getpagesize());
		close(dom->evtchn_fd);
		dom->evtchn_fd = -1;
		goto out;
	}

 out:
	free(dompath);
	return err;
}

static struct domain *create_domain(int domid)
{
	struct domain *dom;

	dom = (struct domain *)malloc(sizeof(struct domain));
	if (dom == NULL) {
		dolog(LOG_ERR, "Out of memory %s:%s():L%d",
		      __FILE__, __FUNCTION__, __LINE__);
		exit(ENOMEM);
	}

	dom->domid = domid;
	dom->tty_fd = domain_create_tty(dom);
	dom->is_dead = false;
	dom->buffer.data = 0;
	dom->buffer.size = 0;
	dom->buffer.capacity = 0;
	dom->buffer.max_capacity = 0;
	dom->next = NULL;

	domain_create_ring(dom);

	dolog(LOG_DEBUG, "New domain %d", domid);

	return dom;
}

static struct domain *lookup_domain(int domid)
{
	struct domain **pp;

	for (pp = &dom_head; *pp; pp = &(*pp)->next) {
		struct domain *dom = *pp;

		if (dom->domid == domid) {
			return dom;
		} else if (dom->domid > domid) {
			*pp = create_domain(domid);
			(*pp)->next = dom;
			return *pp;
		}
	}

	*pp = create_domain(domid);
	return *pp;
}

static void remove_domain(struct domain *dom)
{
	struct domain **pp;

	dolog(LOG_DEBUG, "Removing domain-%d", dom->domid);

	for (pp = &dom_head; *pp; pp = &(*pp)->next) {
		struct domain *d = *pp;

		if (dom->domid == d->domid) {
			*pp = d->next;
			if (d->buffer.data)
				free(d->buffer.data);
			if (d->page)
				munmap(d->page, getpagesize());
			if (d->evtchn_fd != -1)
				close(d->evtchn_fd);
			if (d->tty_fd != -1)
				close(d->tty_fd);
			free(d);
			break;
		}
	}
}

static void remove_dead_domains(struct domain *dom)
{
	struct domain *n;

	while (dom != NULL) {
		n = dom->next;
		if (dom->is_dead)
			remove_domain(dom);
		dom = n;
	}
}

static void handle_tty_read(struct domain *dom)
{
	ssize_t len;
	char msg[80];
	struct ring_head *inring =
		(struct ring_head *)(dom->page + PAGE_SIZE/2);
	int i;

	len = read(dom->tty_fd, msg, MAX(XENCONS_SPACE(inring), sizeof(msg)));
	if (len < 1) {
		close(dom->tty_fd);
		dom->tty_fd = -1;

		if (domain_is_valid(dom->domid)) {
			dom->tty_fd = domain_create_tty(dom);
		} else {
			dom->is_dead = true;
		}
	} else if (domain_is_valid(dom->domid)) {
		for (i = 0; i < len; i++) {
			inring->buf[XENCONS_IDX(inring->prod)] = msg[i];
			inring->prod++;
		}
		xc_evtchn_send(xc, dom->local_port);
	} else {
		close(dom->tty_fd);
		dom->tty_fd = -1;
		dom->is_dead = true;
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
			dom->is_dead = true;
		}
	} else {
		buffer_advance(&dom->buffer, len);
	}
}

static void handle_ring_read(struct domain *dom)
{
	u16 v;

	if (!read_sync(dom->evtchn_fd, &v, sizeof(v)))
		return;

	buffer_append(dom);

	(void)write_sync(dom->evtchn_fd, &v, sizeof(v));
}

static void handle_xcs_msg(int fd)
{
	xcs_msg_t msg;

	if (!read_sync(fd, &msg, sizeof(msg))) {
		dolog(LOG_ERR, "read from xcs failed! %m");
		exit(1);
	}
}

static void enum_domains(void)
{
	int domid = 0;
	xc_dominfo_t dominfo;
	struct domain *dom;

	while (xc_domain_getinfo(xc, domid, 1, &dominfo) == 1) {
		dom = lookup_domain(dominfo.domid);
		if (dominfo.dying || dominfo.crashed || dominfo.shutdown)
			dom->is_dead = true;
		domid = dominfo.domid + 1;
	}
}

void handle_io(void)
{
	fd_set readfds, writefds;
	int ret;

	do {
		struct domain *d;
		struct timeval tv = { 1, 0 };
		int max_fd = -1;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(xcs_data_fd, &readfds);
		max_fd = MAX(xcs_data_fd, max_fd);

		for (d = dom_head; d; d = d->next) {
			if (d->tty_fd != -1) {
				FD_SET(d->tty_fd, &readfds);
			}
			if (d->evtchn_fd != -1)
				FD_SET(d->evtchn_fd, &readfds);

			if (d->tty_fd != -1 && !buffer_empty(&d->buffer)) {
				FD_SET(d->tty_fd, &writefds);
			}

			max_fd = MAX(d->tty_fd, max_fd);
			max_fd = MAX(d->evtchn_fd, max_fd);
		}

		ret = select(max_fd + 1, &readfds, &writefds, 0, &tv);
		enum_domains();

		if (FD_ISSET(xcs_data_fd, &readfds))
			handle_xcs_msg(xcs_data_fd);

		for (d = dom_head; d; d = d->next) {
			if (d->is_dead || d->tty_fd == -1 ||
			    d->evtchn_fd == -1)
				continue;

			if (FD_ISSET(d->tty_fd, &readfds))
				handle_tty_read(d);

			if (FD_ISSET(d->evtchn_fd, &readfds))
				handle_ring_read(d);

			if (FD_ISSET(d->tty_fd, &writefds))
				handle_tty_write(d);
		}

		remove_dead_domains(dom_head);
	} while (ret > -1);
}
