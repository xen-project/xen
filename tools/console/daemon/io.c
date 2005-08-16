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

#include "xc.h"
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

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

struct buffer
{
	char *data;
	size_t size;
	size_t capacity;
	size_t max_capacity;
};

static void buffer_append(struct buffer *buffer, const void *data, size_t size)
{
	if ((buffer->capacity - buffer->size) < size) {
		buffer->capacity += (size + 1024);
		buffer->data = realloc(buffer->data, buffer->capacity);
		if (buffer->data == NULL) {
			dolog(LOG_ERR, "Memory allocation failed");
			exit(ENOMEM);
		}
	}

	memcpy(buffer->data + buffer->size, data, size);
	buffer->size += size;

	if (buffer->max_capacity &&
	    buffer->size > buffer->max_capacity) {
		memmove(buffer->data + (buffer->size - buffer->max_capacity),
			buffer->data, buffer->max_capacity);
		buffer->data = realloc(buffer->data, buffer->max_capacity);
		buffer->capacity = buffer->max_capacity;
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

struct domain
{
	int domid;
	int tty_fd;
	bool is_dead;
	struct buffer buffer;
	struct domain *next;
};

static struct domain *dom_head;

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
	char path[1024];
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

		xs_mkdir(xs, "/console");
		snprintf(path, sizeof(path), "/console/%d", dom->domid);
		xs_mkdir(xs, path);
		strcat(path, "/tty");

		xs_write(xs, path, slave, strlen(slave), O_CREAT);

		snprintf(path, sizeof(path), "/console/%d/limit", dom->domid);
		data = xs_read(xs, path, &len);
		if (data) {
			dom->buffer.max_capacity = strtoul(data, 0, 0);
			free(data);
		}
	}

	return master;
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
	dom->next = 0;

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
			if (d->buffer.data) {
				free(d->buffer.data);
			}
			free(d);
			break;
		}
	}
}

static void remove_dead_domains(struct domain *dom)
{
	if (dom == NULL) return;
	remove_dead_domains(dom->next);

	if (dom->is_dead) {
		remove_domain(dom);
	}
}

static void handle_tty_read(struct domain *dom)
{
	ssize_t len;
	xcs_msg_t msg;

	msg.type = XCS_REQUEST;
	msg.u.control.remote_dom = dom->domid;
	msg.u.control.msg.type = CMSG_CONSOLE;
	msg.u.control.msg.subtype = CMSG_CONSOLE_DATA;
	msg.u.control.msg.id = 1;

	len = read(dom->tty_fd, msg.u.control.msg.msg, 60);
	if (len < 1) {
		close(dom->tty_fd);

		if (domain_is_valid(dom->domid)) {
			dom->tty_fd = domain_create_tty(dom);
		} else {
			dom->is_dead = true;
		}
	} else if (domain_is_valid(dom->domid)) {
		msg.u.control.msg.length = len;

		if (!write_sync(xcs_data_fd, &msg, sizeof(msg))) {
			dolog(LOG_ERR, "Write to xcs failed: %m");
			exit(1);
		}
	} else {
		close(dom->tty_fd);
		dom->is_dead = true;
	}
}

static void handle_tty_write(struct domain *dom)
{
	ssize_t len;

	len = write(dom->tty_fd, dom->buffer.data, dom->buffer.size);
	if (len < 1) {
		close(dom->tty_fd);

		if (domain_is_valid(dom->domid)) {
			dom->tty_fd = domain_create_tty(dom);
		} else {
			dom->is_dead = true;
		}
	} else {
		buffer_advance(&dom->buffer, len);
	}
}

static void handle_xcs_msg(int fd)
{
	xcs_msg_t msg;

	if (!read_sync(fd, &msg, sizeof(msg))) {
		dolog(LOG_ERR, "read from xcs failed! %m");
		exit(1);
	} else if (msg.type == XCS_REQUEST) {
		struct domain *dom;

		dom = lookup_domain(msg.u.control.remote_dom);
		buffer_append(&dom->buffer,
			      msg.u.control.msg.msg,
			      msg.u.control.msg.length);
	}
}

static void enum_domains(void)
{
	int domid = 0;
	xc_dominfo_t dominfo;

	while (xc_domain_getinfo(xc, domid, 1, &dominfo) == 1) {
		lookup_domain(dominfo.domid);
		domid = dominfo.domid + 1;
	}
}

void handle_io(void)
{
	fd_set readfds, writefds;
	int ret;
	int max_fd = -1;
	int num_of_writes = 0;

	do {
		struct domain *d;
		struct timeval tv = { 1, 0 };

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(xcs_data_fd, &readfds);
		max_fd = MAX(xcs_data_fd, max_fd);

		for (d = dom_head; d; d = d->next) {
			if (d->tty_fd != -1) {
				FD_SET(d->tty_fd, &readfds);
			}

			if (d->tty_fd != -1 && !buffer_empty(&d->buffer)) {
				FD_SET(d->tty_fd, &writefds);
			}

			max_fd = MAX(d->tty_fd, max_fd);
		}

		ret = select(max_fd + 1, &readfds, &writefds, 0, &tv);
		if (tv.tv_sec == 1 && (++num_of_writes % 100) == 0) {
#if 0
			/* FIXME */
			/* This is a nasty hack.  xcs does not handle the
			   control channels filling up well at all.  We'll
			   throttle ourselves here since we do proper
			   queueing to give the domains a shot at pulling out
			   the data.  Fixing xcs is not worth it as it's
			   going away */
			tv.tv_usec = 1000;
			select(0, 0, 0, 0, &tv);
#endif
		}
		enum_domains();

		if (FD_ISSET(xcs_data_fd, &readfds)) {
			handle_xcs_msg(xcs_data_fd);
		}

		for (d = dom_head; d; d = d->next) {
			if (!d->is_dead && FD_ISSET(d->tty_fd, &readfds)) {
				handle_tty_read(d);
			}

			if (!d->is_dead && FD_ISSET(d->tty_fd, &writefds)) {
				handle_tty_write(d);
			}
		}

		remove_dead_domains(dom_head);
	} while (ret > -1);
}
