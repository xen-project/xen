/* 
    Domain communications for Xen Store Daemon.
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

#include <stdio.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//#define DEBUG
#include "utils.h"
#include "talloc.h"
#include "xenstored_core.h"
#include "xenstored_domain.h"
#include "xenstored_test.h"

static int *xc_handle;
static int eventchn_fd;
static unsigned int ringbuf_datasize;

struct domain
{
	struct list_head list;

	/* The id of this domain */
	domid_t domid;

	/* Event channel port */
	u16 port;

	/* Domain path in store. */
	char *path;

	/* Shared page. */
	void *page;

	/* Input and output ringbuffer heads. */
	struct ringbuf_head *input, *output;

	/* The connection associated with this. */
	struct connection *conn;

};

static LIST_HEAD(domains);

struct ringbuf_head
{
	u32 write; /* Next place to write to */
	u32 read; /* Next place to read from */
	u8 flags;
	char buf[0];
} __attribute__((packed));

#define EVENTCHN_BIND		_IO('E', 2)
#define EVENTCHN_UNBIND 	_IO('E', 3)

/* FIXME: Mark connection as broken (close it?) when this happens. */
static bool check_buffer(const struct ringbuf_head *h)
{
	return (h->write < ringbuf_datasize && h->read < ringbuf_datasize);
}

/* We can't fill last byte: would look like empty buffer. */
static void *get_output_chunk(const struct ringbuf_head *h,
			      void *buf, u32 *len)
{
	u32 read_mark;

	if (h->read == 0)
		read_mark = ringbuf_datasize - 1;
	else
		read_mark = h->read - 1;

	/* Here to the end of buffer, unless they haven't read some out. */
	*len = ringbuf_datasize - h->write;
	if (read_mark >= h->write)
		*len = read_mark - h->write;
	return buf + h->write;
}

static const void *get_input_chunk(const struct ringbuf_head *h,
				   const void *buf, u32 *len)
{
	/* Here to the end of buffer, unless they haven't written some. */
	*len = ringbuf_datasize - h->read;
	if (h->write >= h->read)
		*len = h->write - h->read;
	return buf + h->read;
}

static void update_output_chunk(struct ringbuf_head *h, u32 len)
{
	h->write += len;
	if (h->write == ringbuf_datasize)
		h->write = 0;
}

static void update_input_chunk(struct ringbuf_head *h, u32 len)
{
	h->read += len;
	if (h->read == ringbuf_datasize)
		h->read = 0;
}

static bool buffer_has_input(const struct ringbuf_head *h)
{
	u32 len;

	get_input_chunk(h, NULL, &len);
	return (len != 0);
}

static bool buffer_has_output_room(const struct ringbuf_head *h)
{
	u32 len;

	get_output_chunk(h, NULL, &len);
	return (len != 0);
}

static int writechn(struct connection *conn, const void *data, unsigned int len)
{
	u32 avail;
	void *dest;
	struct ringbuf_head h;

	/* Must read head once, and before anything else, and verified. */
	h = *conn->domain->output;
	mb();
	if (!check_buffer(&h)) {
		errno = EIO;
		return -1;
	}

	dest = get_output_chunk(&h, conn->domain->output->buf, &avail);
	if (avail < len)
		len = avail;

	memcpy(dest, data, len);
	mb();
	update_output_chunk(conn->domain->output, len);
	/* FIXME: Probably not neccessary. */
	mb();
	xc_evtchn_send(*xc_handle, conn->domain->port);
	return len;
}

static int readchn(struct connection *conn, void *data, unsigned int len)
{
	u32 avail;
	const void *src;
	struct ringbuf_head h;
	bool was_full;

	/* Must read head once, and before anything else, and verified. */
	h = *conn->domain->input;
	mb();

	if (!check_buffer(&h)) {
		errno = EIO;
		return -1;
	}

	src = get_input_chunk(&h, conn->domain->input->buf, &avail);
	if (avail < len)
		len = avail;

	was_full = !buffer_has_output_room(&h);
	memcpy(data, src, len);
	mb();
	update_input_chunk(conn->domain->input, len);
	/* FIXME: Probably not neccessary. */
	mb();

	/* If it was full, tell them we've taken some. */
	if (was_full)
		xc_evtchn_send(*xc_handle, conn->domain->port);
	return len;
}

static int destroy_domain(void *_domain)
{
	struct domain *domain = _domain;

	list_del(&domain->list);

	if (domain->port &&
	    (ioctl(eventchn_fd, EVENTCHN_UNBIND, domain->port) != 0))
		eprintf("> Unbinding port %i failed!\n", domain->port);

	if(domain->page)
		munmap(domain->page, getpagesize());

	return 0;
}

static struct domain *find_domain(u16 port)
{
	struct domain *i;

	list_for_each_entry(i, &domains, list) {
		if (i->port == port)
			return i;
	}
	return NULL;
}

/* We scan all domains rather than use the information given here. */
void handle_event(int event_fd)
{
	u16 port;

	if (read(event_fd, &port, sizeof(port)) != sizeof(port))
		barf_perror("Failed to read from event fd");
#ifndef TESTING
	if (write(event_fd, &port, sizeof(port)) != sizeof(port))
		barf_perror("Failed to write to event fd");
#endif
}

bool domain_can_read(struct connection *conn)
{
	return conn->state == OK && buffer_has_input(conn->domain->input);
}

bool domain_can_write(struct connection *conn)
{
	return conn->out && buffer_has_output_room(conn->domain->output);
}

static struct domain *new_domain(void *context, domid_t domid,
				 unsigned long mfn, int port,
				 const char *path)
{
	struct domain *domain;
	domain = talloc(context, struct domain);
	domain->port = 0;
	domain->domid = domid;
	domain->path = talloc_strdup(domain, path);
	domain->page = xc_map_foreign_range(*xc_handle, domain->domid,
					    getpagesize(),
					    PROT_READ|PROT_WRITE,
					    mfn);
	if (!domain->page)
		return NULL;

	list_add(&domain->list, &domains);
	talloc_set_destructor(domain, destroy_domain);

	/* One in each half of page. */
	domain->input = domain->page;
	domain->output = domain->page + getpagesize()/2;

	/* Tell kernel we're interested in this event. */
	if (ioctl(eventchn_fd, EVENTCHN_BIND, port) != 0)
		return NULL;

	domain->port = port;
	domain->conn = new_connection(writechn, readchn);
	domain->conn->domain = domain;
	return domain;
}

/* domid, mfn, evtchn, path */
void do_introduce(struct connection *conn, struct buffered_data *in)
{
	struct domain *domain;
	char *vec[4];

	if (get_strings(in, vec, ARRAY_SIZE(vec)) < ARRAY_SIZE(vec)) {
		send_error(conn, EINVAL);
		return;
	}

	if (conn->id != 0) {
		send_error(conn, EACCES);
		return;
	}

	if (!conn->can_write) {
		send_error(conn, EROFS);
		return;
	}

	/* Sanity check args. */
	if ((atoi(vec[2]) <= 0) || !is_valid_nodename(vec[3])) {
		send_error(conn, EINVAL);
		return;
	}
	/* Hang domain off "in" until we're finished. */
	domain = new_domain(in, atoi(vec[0]), atol(vec[1]), atol(vec[2]),
			    vec[3]);
	if (!domain) {
		send_error(conn, errno);
		return;
	}

	/* Now domain belongs to its connection. */
	talloc_steal(domain->conn, domain);
	send_ack(conn, XS_INTRODUCE);
}

static struct domain *find_domain_by_domid(domid_t domid)
{
	struct domain *i;

	list_for_each_entry(i, &domains, list) {
		if (i->domid == domid)
			return i;
	}
	return NULL;
}

/* domid */
void do_release(struct connection *conn, const char *domid_str)
{
	struct domain *domain;
	domid_t domid;

	if (!domid_str) {
		send_error(conn, EINVAL);
		return;
	}

	domid = atoi(domid_str);
	if (!domid) {
		send_error(conn, EINVAL);
		return;
	}

	if (conn->id != 0) {
		send_error(conn, EACCES);
		return;
	}

	domain = find_domain_by_domid(domid);
	if (!domain) {
		send_error(conn, ENOENT);
		return;
	}

	if (!domain->conn) {
		send_error(conn, EINVAL);
		return;
	}

	talloc_free(domain->conn);
	send_ack(conn, XS_RELEASE);
}

void do_get_domain_path(struct connection *conn, const char *domid_str)
{
	struct domain *domain;
	domid_t domid;

	if (!domid_str) {
		send_error(conn, EINVAL);
		return;
	}

	domid = atoi(domid_str);
	if (domid == DOMID_SELF)
		domain = conn->domain;
	else
		domain = find_domain_by_domid(domid);

	if (!domain) 
		send_error(conn, ENOENT);
	else
		send_reply(conn, XS_GETDOMAINPATH, domain->path,
			   strlen(domain->path) + 1);
}

static int close_xc_handle(void *_handle)
{
	xc_interface_close(*(int *)_handle);
	return 0;
}

/* Returns the implicit path of a connection (only domains have this) */
const char *get_implicit_path(const struct connection *conn)
{
	if (!conn->domain)
		return NULL;
	return conn->domain->path;
}

/* Restore existing connections. */
void restore_existing_connections(void)
{
}

/* Returns the event channel handle. */
int domain_init(void)
{
	/* The size of the ringbuffer: half a page minus head structure. */
	ringbuf_datasize = getpagesize() / 2 - sizeof(struct ringbuf_head);

	xc_handle = talloc(talloc_autofree_context(), int);
	if (!xc_handle)
		barf_perror("Failed to allocate domain handle");
	*xc_handle = xc_interface_open();
	if (*xc_handle < 0)
		barf_perror("Failed to open connection to hypervisor");
	talloc_set_destructor(xc_handle, close_xc_handle);

#ifdef TESTING
	eventchn_fd = fake_open_eventchn();
#else
	eventchn_fd = open("/dev/xen/evtchn", O_RDWR);
#endif
	if (eventchn_fd < 0)
		barf_perror("Failed to open connection to hypervisor");
	return eventchn_fd;
}
