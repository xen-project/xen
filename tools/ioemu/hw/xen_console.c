/*
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  Copyright (C) Red Hat 2007
 *
 *  Xen Console
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

#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <xs.h>
#include <xen/io/console.h>
#include <xenctrl.h>

#include "vl.h"

#include "xen_console.h"

#define dolog(val, fmt, ...) fprintf(stderr, fmt "\n", ## __VA_ARGS__)

struct buffer
{
	uint8_t *data;
	size_t consumed;
	size_t size;
	size_t capacity;
	size_t max_capacity;
};

struct domain
{
	int domid;
	struct buffer buffer;

	char *conspath;
	char *serialpath;
	int use_consolepath;
	int ring_ref;
	evtchn_port_t local_port;
	evtchn_port_t remote_port;
	int xce_handle;
	struct xs_handle *xsh;
	struct xencons_interface *interface;
	CharDriverState *chr;
};


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

	if (buffer->max_capacity &&
	    buffer->size > buffer->max_capacity) {
		/* Discard the middle of the data. */

		size_t over = buffer->size - buffer->max_capacity;
		uint8_t *maxpos = buffer->data + buffer->max_capacity;

		memmove(maxpos - over, maxpos, over);
		buffer->data = realloc(buffer->data, buffer->max_capacity);
		buffer->size = buffer->capacity = buffer->max_capacity;

		if (buffer->consumed > buffer->max_capacity - over)
			buffer->consumed = buffer->max_capacity - over;
	}
}

static void buffer_advance(struct buffer *buffer, size_t len)
{
	buffer->consumed += len;
	if (buffer->consumed == buffer->size) {
		buffer->consumed = 0;
		buffer->size = 0;
	}
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

	err = xs_gather(dom->xsh, dom->serialpath,
			"ring-ref", "%u", &ring_ref,
			"port", "%i", &remote_port,
			NULL);
	if (err) {
		err = xs_gather(dom->xsh, dom->conspath,
				"ring-ref", "%u", &ring_ref,
				"port", "%i", &remote_port,
				NULL);
		if (err) {
			fprintf(stderr, "Console: failed to find ring-ref/port yet\n");
			goto out;
		}
		dom->use_consolepath = 1;
	} else
		dom->use_consolepath = 0;
	fprintf(stderr, "Console: got ring-ref %d port %d\n", ring_ref, remote_port);

	if ((ring_ref == dom->ring_ref) && (remote_port == dom->remote_port))
		goto out;

	if (ring_ref != dom->ring_ref) {
		if (dom->interface != NULL)
			munmap(dom->interface, getpagesize());
		dom->interface = xc_map_foreign_range(
			xc_handle, dom->domid, getpagesize(),
			PROT_READ|PROT_WRITE,
			(unsigned long)ring_ref);
		if (dom->interface == NULL) {
			err = errno;
			goto out;
		}
		dom->ring_ref = ring_ref;
	}

	dom->local_port = -1;
	dom->remote_port = -1;

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

 out:
	return err;
}


static struct domain *create_domain(int domid, CharDriverState *chr)
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
	dom->chr = chr;

	dom->xsh = xs_daemon_open();
	if (dom->xsh == NULL) {
		fprintf(logfile, "Could not contact xenstore for console watch\n");
		goto out;
	}

	dom->serialpath = xs_get_domain_path(dom->xsh, dom->domid);
	s = realloc(dom->serialpath, strlen(dom->serialpath) +
		    strlen("/serial/0") + 1);
	if (s == NULL)
		goto out;
	dom->serialpath = s;
	strcat(dom->serialpath, "/serial/0");

	dom->conspath = xs_get_domain_path(dom->xsh, dom->domid);
	s = realloc(dom->conspath, strlen(dom->conspath) +
		    strlen("/console") + 1);
	if (s == NULL)
		goto out;
	dom->conspath = s;
	strcat(dom->conspath, "/console");

	dom->buffer.data = 0;
	dom->buffer.consumed = 0;
	dom->buffer.size = 0;
	dom->buffer.capacity = 0;
	dom->buffer.max_capacity = 0;

	dom->ring_ref = -1;
	dom->local_port = -1;
	dom->remote_port = -1;
	dom->interface = NULL;
	dom->xce_handle = -1;


	return dom;
 out:
	free(dom->serialpath);
	free(dom->conspath);
	free(dom);
	return NULL;
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

static int xencons_can_receive(void *opaque)
{
	struct domain *dom = (struct domain *)opaque;

	return ring_free_bytes(dom);
}

static void xencons_receive(void *opaque, const uint8_t *buf, int len)
{
	struct domain *dom = (struct domain *)opaque;
	int i, max;
	struct xencons_interface *intf = dom->interface;
	XENCONS_RING_IDX prod;

	max = ring_free_bytes(dom);
	/* The can_receive() func limits this, but check again anyway */
	if (max < len)
		len = max;

	prod = intf->in_prod;
	for (i = 0; i < len; i++) {
		intf->in[MASK_XENCONS_IDX(prod++, intf->in)] =
			buf[i];
	}
	xen_wmb();
	intf->in_prod = prod;
	xc_evtchn_notify(dom->xce_handle, dom->local_port);
}

static void xencons_send(struct domain *dom)
{
	ssize_t len;
	len = qemu_chr_write(dom->chr, dom->buffer.data + dom->buffer.consumed,
			     dom->buffer.size - dom->buffer.consumed);
 	if (len < 1) {
		/*
		 * Disable log because if we're redirecting to /dev/pts/N we
		 * don't want to flood logs when no client has the PTY open
		 */
		/*
		dolog(LOG_DEBUG, "Write failed on domain %d: %zd, %d\n",
		      dom->domid, len, errno);
		*/
	} else {
		buffer_advance(&dom->buffer, len);
	}
}

static void xencons_ring_read(void *opaque)
{
	evtchn_port_t port;
	struct domain *dom = (struct domain *)opaque;

	if ((port = xc_evtchn_pending(dom->xce_handle)) == -1)
		return;

	buffer_append(dom);

	(void)xc_evtchn_unmask(dom->xce_handle, port);

	if (dom->buffer.size - dom->buffer.consumed)
		xencons_send(dom);
}

static void xencons_startup(void *opaque)
{
	struct domain *dom = (struct domain *)opaque;
	unsigned dummy;
	char **vec;
	int err;
	vec = xs_read_watch(dom->xsh, &dummy);
	if (vec)
		free(vec);
	fprintf(stderr, "Console: got watch\n");
	err = domain_create_ring(dom);
	if (err)
		return;

	xs_unwatch(dom->xsh, dom->conspath, "");
	xs_unwatch(dom->xsh, dom->serialpath, "");
	qemu_set_fd_handler2(xs_fileno(dom->xsh), NULL, NULL, NULL, NULL);

	fprintf(stderr, "Console: connected to guest frontend\n");
	if (qemu_set_fd_handler2(xc_evtchn_fd(dom->xce_handle), NULL, xencons_ring_read, NULL, dom) < 0)
		return;

	qemu_chr_add_handlers(dom->chr, xencons_can_receive, xencons_receive,
			      NULL, dom);
}


int xencons_init(int domid, CharDriverState *chr)
{
	struct domain *dom = create_domain(domid, chr);

	if (!dom)
		return -1;

	/* Setup watches so we asynchronously connect to serial console */
	if (!(xs_watch(dom->xsh, dom->conspath, ""))) {
		fprintf(stderr, "Unable to watch console %s\n", dom->conspath);
		goto fail;
	}
	if (!(xs_watch(dom->xsh, dom->serialpath, ""))) {
		fprintf(stderr, "Unable to watch console %s\n", dom->conspath);
		xs_unwatch(dom->xsh, dom->conspath, "");
		goto fail;
	}
	qemu_set_fd_handler2(xs_fileno(dom->xsh), NULL, xencons_startup, NULL, dom);
	fprintf(stderr, "Console: prepared domain, waiting for ringref at %s or %s\n",
		dom->conspath, dom->serialpath);

	return 0;

fail:
	xs_daemon_close(dom->xsh);
	free(dom->serialpath);
	free(dom->conspath);
	free(dom);
	return -1;
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
