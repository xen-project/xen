#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <xenctrl.h>
#include <xen/io/xenbus.h>
#include <xen/io/fbif.h>
#include <xen/io/kbdif.h>
#include <xen/io/protocols.h>
#include <sys/select.h>
#include <stdbool.h>
#include <xen/linux/evtchn.h>
#include <xen/event_channel.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <xs.h>

#include "xenfb.h"

// FIXME defend against malicious frontend?

struct xenfb_device {
	const char *devicetype;
	char nodename[64];	/* backend xenstore dir */
	char otherend[64];	/* frontend xenstore dir */
	int otherend_id;	/* frontend domid */
	enum xenbus_state state; /* backend state */
	void *page;		/* shared page */
	evtchn_port_t port;
	struct xenfb_private *xenfb;
};

struct xenfb_private {
	struct xenfb pub;
	int evt_xch;		/* event channel driver handle */
	int xc;			/* hypervisor interface handle */
	struct xs_handle *xsh;	/* xs daemon handle */
	struct xenfb_device fb, kbd;
	size_t fb_len;		/* size of framebuffer */
	char protocol[64];	/* frontend protocol */
};

static void xenfb_detach_dom(struct xenfb_private *);

static char *xenfb_path_in_dom(struct xs_handle *xsh,
			       char *buf, size_t size,
			       unsigned domid, const char *fmt, ...)
{
	va_list ap;
	char *domp = xs_get_domain_path(xsh, domid);
	int n;

        if (domp == NULL)
		return NULL;

	n = snprintf(buf, size, "%s/", domp);
	free(domp);
	if (n >= size)
		return NULL;

	va_start(ap, fmt);
	n += vsnprintf(buf + n, size - n, fmt, ap);
	va_end(ap);
	if (n >= size)
		return NULL;

	return buf;
}

static int xenfb_xs_scanf1(struct xs_handle *xsh,
			   const char *dir, const char *node,
			   const char *fmt, void *dest)
{
	char buf[1024];
	char *p;
	int ret;

	if (snprintf(buf, sizeof(buf), "%s/%s", dir, node) >= sizeof(buf)) {
		errno = ENOENT;
		return -1;
        }
	p = xs_read(xsh, XBT_NULL, buf, NULL);
	if (!p) {
		errno = ENOENT;
		return -1;
        }
	ret = sscanf(p, fmt, dest);
	free(p);
	if (ret != 1) {
		errno = EDOM;
		return -1;
        }
	return ret;
}

static int xenfb_xs_printf(struct xs_handle *xsh,
			   const char *dir, const char *node, char *fmt, ...)
{
	va_list ap;
	char key[1024];
	char val[1024];
	int n;

	if (snprintf(key, sizeof(key), "%s/%s", dir, node) >= sizeof(key)) {
		errno = ENOENT;
		return -1;
        }

	va_start(ap, fmt);
	n = vsnprintf(val, sizeof(val), fmt, ap);
	va_end(ap);
	if (n >= sizeof(val)) {
		errno = ENOSPC; /* close enough */
		return -1;
	}

	if (!xs_write(xsh, XBT_NULL, key, val, n))
		return -1;
	return 0;
}

static void xenfb_device_init(struct xenfb_device *dev,
			      const char *type,
			      struct xenfb_private *xenfb)
{
	dev->devicetype = type;
	dev->otherend_id = -1;
	dev->port = -1;
	dev->xenfb = xenfb;
}

int xenfb_device_set_domain(struct xenfb_device *dev, int domid)
{
	struct xenfb_private *xenfb = dev->xenfb;

	dev->otherend_id = domid;

	if (!xenfb_path_in_dom(xenfb->xsh,
			       dev->otherend, sizeof(dev->otherend),
			       domid, "device/%s/0", dev->devicetype)) {
		errno = ENOENT;
		return -1;
	}
	if (!xenfb_path_in_dom(xenfb->xsh,
			       dev->nodename, sizeof(dev->nodename),
			       0, "backend/%s/%d/0", dev->devicetype, domid)) {
		errno = ENOENT;
		return -1;
	}

	return 0;
}

struct xenfb *xenfb_new(void)
{
	struct xenfb_private *xenfb = malloc(sizeof(*xenfb));
	int serrno;

	if (xenfb == NULL)
		return NULL;

	memset(xenfb, 0, sizeof(*xenfb));
	xenfb->evt_xch = xenfb->xc = -1;
	xenfb_device_init(&xenfb->fb, "vfb", xenfb);
	xenfb_device_init(&xenfb->kbd, "vkbd", xenfb);

	xenfb->evt_xch = xc_evtchn_open();
	if (xenfb->evt_xch == -1)
		goto fail;

	xenfb->xc = xc_interface_open();
	if (xenfb->xc == -1)
		goto fail;

	xenfb->xsh = xs_daemon_open();
	if (!xenfb->xsh)
		goto fail;

	return &xenfb->pub;

 fail:
	serrno = errno;
	xenfb_delete(&xenfb->pub);
	errno = serrno;
	return NULL;
}

/* Remove the backend area in xenbus since the framebuffer really is
   going away. */
void xenfb_teardown(struct xenfb *xenfb_pub)
{
       struct xenfb_private *xenfb = (struct xenfb_private *)xenfb_pub;

       xs_rm(xenfb->xsh, XBT_NULL, xenfb->fb.nodename);
       xs_rm(xenfb->xsh, XBT_NULL, xenfb->kbd.nodename);
}


void xenfb_delete(struct xenfb *xenfb_pub)
{
	struct xenfb_private *xenfb = (struct xenfb_private *)xenfb_pub;

	xenfb_detach_dom(xenfb);
	if (xenfb->xc >= 0)
		xc_interface_close(xenfb->xc);
	if (xenfb->evt_xch >= 0)
		xc_evtchn_close(xenfb->evt_xch);
	if (xenfb->xsh)
		xs_daemon_close(xenfb->xsh);
	free(xenfb);
}

static enum xenbus_state xenfb_read_state(struct xs_handle *xsh,
					  const char *dir)
{
	int ret, state;

	ret = xenfb_xs_scanf1(xsh, dir, "state", "%d", &state);
	if (ret < 0)
		return XenbusStateUnknown;

	if ((unsigned)state > XenbusStateClosed)
		state = XenbusStateUnknown;
	return state;
}

static int xenfb_switch_state(struct xenfb_device *dev,
			      enum xenbus_state state)
{
	struct xs_handle *xsh = dev->xenfb->xsh;

	if (xenfb_xs_printf(xsh, dev->nodename, "state", "%d", state) < 0)
		return -1;
	dev->state = state;
	return 0;
}

static int xenfb_wait_for_state(struct xs_handle *xsh, const char *dir,
				unsigned awaited)
{
	unsigned state, dummy;
	char **vec;

	for (;;) {
		state = xenfb_read_state(xsh, dir);
		if (state < 0)
			return -1;

		if ((1 << state) & awaited)
			return state;

		vec = xs_read_watch(xsh, &dummy);
		if (!vec)
			return -1;
		free(vec);
	}
}

static int xenfb_wait_for_backend_creation(struct xenfb_device *dev)
{
	struct xs_handle *xsh = dev->xenfb->xsh;
	int state;

	if (!xs_watch(xsh, dev->nodename, ""))
		return -1;
	state = xenfb_wait_for_state(xsh, dev->nodename,
			(1 << XenbusStateInitialising)
			| (1 << XenbusStateClosed)
#if 1 /* TODO fudging state to permit restarting; to be removed */
			| (1 << XenbusStateInitWait)
			| (1 << XenbusStateConnected)
			| (1 << XenbusStateClosing)
#endif
			);
	xs_unwatch(xsh, dev->nodename, "");

	switch (state) {
#if 1
	case XenbusStateInitWait:
	case XenbusStateConnected:
		printf("Fudging state to %d\n", XenbusStateInitialising); /* FIXME */
#endif
	case XenbusStateInitialising:
	case XenbusStateClosing:
	case XenbusStateClosed:
		break;
	default:
		return -1;
	}

	return 0;
}

static int xenfb_hotplug(struct xenfb_device *dev)
{
	if (xenfb_xs_printf(dev->xenfb->xsh, dev->nodename,
			    "hotplug-status", "connected"))
		return -1;
	return 0;
}

static int xenfb_wait_for_frontend_initialised(struct xenfb_device *dev)
{
	switch (xenfb_wait_for_state(dev->xenfb->xsh, dev->otherend,
#if 1 /* TODO fudging state to permit restarting; to be removed */
			(1 << XenbusStateInitialised)
			| (1 << XenbusStateConnected)
#else
			1 << XenbusStateInitialised,
#endif
			)) {
#if 1
	case XenbusStateConnected:
		printf("Fudging state to %d\n", XenbusStateInitialised); /* FIXME */
#endif
	case XenbusStateInitialised:
		break;
	default:
		return -1;
	}

	return 0;
}

static void xenfb_copy_mfns(int mode, int count, unsigned long *dst, void *src)
{
	uint32_t *src32 = src;
	uint64_t *src64 = src;
	int i;

	for (i = 0; i < count; i++)
		dst[i] = (mode == 32) ? src32[i] : src64[i];
}

static int xenfb_map_fb(struct xenfb_private *xenfb, int domid)
{
	struct xenfb_page *page = xenfb->fb.page;
	int n_fbmfns;
	int n_fbdirs;
	unsigned long *pgmfns = NULL;
	unsigned long *fbmfns = NULL;
	void *map, *pd;
	int mode, ret = -1;

	/* default to native */
	pd = page->pd;
	mode = sizeof(unsigned long) * 8;

	if (0 == strlen(xenfb->protocol)) {
		/*
		 * Undefined protocol, some guesswork needed.
		 *
		 * Old frontends which don't set the protocol use
		 * one page directory only, thus pd[1] must be zero.
		 * pd[1] of the 32bit struct layout and the lower
		 * 32 bits of pd[0] of the 64bit struct layout have
		 * the same location, so we can check that ...
		 */
		uint32_t *ptr32 = NULL;
		uint32_t *ptr64 = NULL;
#if defined(__i386__)
		ptr32 = (void*)page->pd;
		ptr64 = ((void*)page->pd) + 4;
#elif defined(__x86_64__)
		ptr32 = ((void*)page->pd) - 4;
		ptr64 = (void*)page->pd;
#endif
		if (ptr32) {
			if (0 == ptr32[1]) {
				mode = 32;
				pd   = ptr32;
			} else {
				mode = 64;
				pd   = ptr64;
			}
		}
#if defined(__x86_64__)
	} else if (0 == strcmp(xenfb->protocol, XEN_IO_PROTO_ABI_X86_32)) {
		/* 64bit dom0, 32bit domU */
		mode = 32;
		pd   = ((void*)page->pd) - 4;
#elif defined(__i386__)
	} else if (0 == strcmp(xenfb->protocol, XEN_IO_PROTO_ABI_X86_64)) {
		/* 32bit dom0, 64bit domU */
		mode = 64;
		pd   = ((void*)page->pd) + 4;
#endif
	}

	n_fbmfns = (xenfb->fb_len + (XC_PAGE_SIZE - 1)) / XC_PAGE_SIZE;
	n_fbdirs = n_fbmfns * mode / 8;
	n_fbdirs = (n_fbdirs + (XC_PAGE_SIZE - 1)) / XC_PAGE_SIZE;

	pgmfns = malloc(sizeof(unsigned long) * n_fbdirs);
	fbmfns = malloc(sizeof(unsigned long) * n_fbmfns);
	if (!pgmfns || !fbmfns)
		goto out;

	/*
	 * Bug alert: xc_map_foreign_batch() can fail partly and
	 * return a non-null value.  This is a design flaw.  When it
	 * happens, we happily continue here, and later crash on
	 * access.
	 */
	xenfb_copy_mfns(mode, n_fbdirs, pgmfns, pd);
	map = xc_map_foreign_batch(xenfb->xc, domid,
				   PROT_READ, pgmfns, n_fbdirs);
	if (map == NULL)
		goto out;
	xenfb_copy_mfns(mode, n_fbmfns, fbmfns, map);
	munmap(map, n_fbdirs * XC_PAGE_SIZE);

	xenfb->pub.pixels = xc_map_foreign_batch(xenfb->xc, domid,
				PROT_READ | PROT_WRITE, fbmfns, n_fbmfns);
	if (xenfb->pub.pixels == NULL)
		goto out;

	ret = 0; /* all is fine */

 out:
	if (pgmfns)
		free(pgmfns);
	if (fbmfns)
		free(fbmfns);
	return ret;
}

static int xenfb_bind(struct xenfb_device *dev)
{
	struct xenfb_private *xenfb = dev->xenfb;
	unsigned long mfn;
	evtchn_port_t evtchn;

	if (xenfb_xs_scanf1(xenfb->xsh, dev->otherend, "page-ref", "%lu",
			    &mfn) < 0)
		return -1;
	if (xenfb_xs_scanf1(xenfb->xsh, dev->otherend, "event-channel", "%u",
			    &evtchn) < 0)
		return -1;

	dev->port = xc_evtchn_bind_interdomain(xenfb->evt_xch,
					       dev->otherend_id, evtchn);
	if (dev->port == -1)
		return -1;

	dev->page = xc_map_foreign_range(xenfb->xc, dev->otherend_id,
			XC_PAGE_SIZE, PROT_READ | PROT_WRITE, mfn);
	if (dev->page == NULL)
		return -1;

	return 0;
}

static void xenfb_unbind(struct xenfb_device *dev)
{
	if (dev->page) {
		munmap(dev->page, XC_PAGE_SIZE);
		dev->page = NULL;
	}
        if (dev->port >= 0) {
		xc_evtchn_unbind(dev->xenfb->evt_xch, dev->port);
		dev->port = -1;
	}
}

static int xenfb_wait_for_frontend_connected(struct xenfb_device *dev)
{
	switch (xenfb_wait_for_state(dev->xenfb->xsh, dev->otherend,
				     1 << XenbusStateConnected)) {
	case XenbusStateConnected:
		break;
	default:
		return -1;
	}

	return 0;
}

static void xenfb_dev_fatal(struct xenfb_device *dev, int err,
			    const char *fmt, ...)
{
	struct xs_handle *xsh = dev->xenfb->xsh;
	va_list ap;
	char errdir[80];
	char buf[1024];
	int n;

	fprintf(stderr, "%s ", dev->nodename); /* somewhat crude */
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (err)
		fprintf(stderr, " (%s)", strerror(err));
	putc('\n', stderr);

	if (!xenfb_path_in_dom(xsh, errdir, sizeof(errdir), 0,
			       "error/%s", dev->nodename))
		goto out;	/* FIXME complain */

	va_start(ap, fmt);
	n = snprintf(buf, sizeof(buf), "%d ", err);
	snprintf(buf + n, sizeof(buf) - n, fmt, ap);
	va_end(ap);

	if (xenfb_xs_printf(xsh, buf, "error", "%s", buf) < 0)
		goto out;	/* FIXME complain */

 out:
	xenfb_switch_state(dev, XenbusStateClosing);
}

int xenfb_attach_dom(struct xenfb *xenfb_pub, int domid)
{
	struct xenfb_private *xenfb = (struct xenfb_private *)xenfb_pub;
	struct xs_handle *xsh = xenfb->xsh;
	int val, serrno;
	struct xenfb_page *fb_page;

	xenfb_detach_dom(xenfb);

	xenfb_device_set_domain(&xenfb->fb, domid);
	xenfb_device_set_domain(&xenfb->kbd, domid);

	if (xenfb_wait_for_backend_creation(&xenfb->fb) < 0)
		goto error;
	if (xenfb_wait_for_backend_creation(&xenfb->kbd) < 0)
		goto error;

	if (xenfb_xs_printf(xsh, xenfb->kbd.nodename, "feature-abs-pointer", "1"))
		goto error;
	if (xenfb_switch_state(&xenfb->fb, XenbusStateInitWait))
		goto error;
	if (xenfb_switch_state(&xenfb->kbd, XenbusStateInitWait))
		goto error;

	if (xenfb_hotplug(&xenfb->fb) < 0)
		goto error;
	if (xenfb_hotplug(&xenfb->kbd) < 0)
		goto error;

	if (!xs_watch(xsh, xenfb->fb.otherend, ""))
		goto error;
	if (!xs_watch(xsh, xenfb->kbd.otherend, ""))
		goto error;

	if (xenfb_wait_for_frontend_initialised(&xenfb->fb) < 0)
		goto error;
	if (xenfb_wait_for_frontend_initialised(&xenfb->kbd) < 0)
		goto error;

	if (xenfb_bind(&xenfb->fb) < 0)
		goto error;
	if (xenfb_bind(&xenfb->kbd) < 0)
		goto error;

	if (xenfb_xs_scanf1(xsh, xenfb->fb.otherend, "feature-update",
			    "%d", &val) < 0)
		val = 0;
	if (!val) {
		errno = ENOTSUP;
		goto error;
	}
	if (xenfb_xs_scanf1(xsh, xenfb->fb.otherend, "protocol", "%63s",
			    xenfb->protocol) < 0)
		xenfb->protocol[0] = '\0';
	xenfb_xs_printf(xsh, xenfb->fb.nodename, "request-update", "1");

	/* TODO check for permitted ranges */
	fb_page = xenfb->fb.page;
	xenfb->pub.depth = fb_page->depth;
	xenfb->pub.width = fb_page->width;
	xenfb->pub.height = fb_page->height;
	/* TODO check for consistency with the above */
	xenfb->fb_len = fb_page->mem_length;
	xenfb->pub.row_stride = fb_page->line_length;

	if (xenfb_map_fb(xenfb, domid) < 0)
		goto error;

	if (xenfb_switch_state(&xenfb->fb, XenbusStateConnected))
		goto error;
	if (xenfb_switch_state(&xenfb->kbd, XenbusStateConnected))
		goto error;

	if (xenfb_wait_for_frontend_connected(&xenfb->kbd) < 0)
		goto error;
	if (xenfb_xs_scanf1(xsh, xenfb->kbd.otherend, "request-abs-pointer",
			    "%d", &val) < 0)
		val = 0;
	xenfb->pub.abs_pointer_wanted = val;

	return 0;

 error:
	serrno = errno;
	xenfb_detach_dom(xenfb);
	xenfb_dev_fatal(&xenfb->fb, serrno, "on fire");
	xenfb_dev_fatal(&xenfb->kbd, serrno, "on fire");
        errno = serrno;
        return -1;
}

static void xenfb_detach_dom(struct xenfb_private *xenfb)
{
	xenfb_unbind(&xenfb->fb);
	xenfb_unbind(&xenfb->kbd);
	if (xenfb->pub.pixels) {
		munmap(xenfb->pub.pixels, xenfb->fb_len);
		xenfb->pub.pixels = NULL;
	}
}

static void xenfb_on_fb_event(struct xenfb_private *xenfb)
{
	uint32_t prod, cons;
	struct xenfb_page *page = xenfb->fb.page;

	prod = page->out_prod;
	if (prod == page->out_cons)
		return;
	rmb();			/* ensure we see ring contents up to prod */
	for (cons = page->out_cons; cons != prod; cons++) {
		union xenfb_out_event *event = &XENFB_OUT_RING_REF(page, cons);

		switch (event->type) {
		case XENFB_TYPE_UPDATE:
                    if (xenfb->pub.update)
			xenfb->pub.update(&xenfb->pub,
					  event->update.x, event->update.y,
					  event->update.width, event->update.height);
                    break;
		}
	}
	mb();			/* ensure we're done with ring contents */
	page->out_cons = cons;
	xc_evtchn_notify(xenfb->evt_xch, xenfb->fb.port);
}

static void xenfb_on_kbd_event(struct xenfb_private *xenfb)
{
	struct xenkbd_page *page = xenfb->kbd.page;

	/* We don't understand any keyboard events, so just ignore them. */
	if (page->out_prod == page->out_cons)
		return;
	page->out_cons = page->out_prod;
	xc_evtchn_notify(xenfb->evt_xch, xenfb->kbd.port);
}

static int xenfb_on_state_change(struct xenfb_device *dev)
{
	enum xenbus_state state;

	state = xenfb_read_state(dev->xenfb->xsh, dev->otherend);

	switch (state) {
	case XenbusStateUnknown:
		/* There was an error reading the frontend state.  The
		   domain has probably gone away; in any case, there's
		   not much point in us continuing. */
		return -1;
	case XenbusStateInitialising:
	case XenbusStateInitWait:
	case XenbusStateInitialised:
	case XenbusStateConnected:
		break;
	case XenbusStateClosing:
		xenfb_unbind(dev);
		xenfb_switch_state(dev, state);
		break;
	case XenbusStateClosed:
		xenfb_switch_state(dev, state);
	}
	return 0;
}

/* Returns 0 normally, -1 on error, or -2 if the domain went away. */
int xenfb_poll(struct xenfb *xenfb_pub, fd_set *readfds)
{
	struct xenfb_private *xenfb = (struct xenfb_private *)xenfb_pub;
	evtchn_port_t port;
	unsigned dummy;
	char **vec;
	int r;

	if (FD_ISSET(xc_evtchn_fd(xenfb->evt_xch), readfds)) {
		port = xc_evtchn_pending(xenfb->evt_xch);
		if (port == -1)
			return -1;

		if (port == xenfb->fb.port)
			xenfb_on_fb_event(xenfb);
		else if (port == xenfb->kbd.port)
			xenfb_on_kbd_event(xenfb);

		if (xc_evtchn_unmask(xenfb->evt_xch, port) == -1)
			return -1;
	}

	if (FD_ISSET(xs_fileno(xenfb->xsh), readfds)) {
		vec = xs_read_watch(xenfb->xsh, &dummy);
		free(vec);
		r = xenfb_on_state_change(&xenfb->fb);
		if (r == 0)
			r = xenfb_on_state_change(&xenfb->kbd);
		if (r == -1)
			return -2;
	}

	return 0;
}

int xenfb_select_fds(struct xenfb *xenfb_pub, fd_set *readfds)
{
	struct xenfb_private *xenfb = (struct xenfb_private *)xenfb_pub;
	int fd1 = xc_evtchn_fd(xenfb->evt_xch);
	int fd2 = xs_fileno(xenfb->xsh);

	FD_SET(fd1, readfds);
	FD_SET(fd2, readfds);
	return fd1 > fd2 ? fd1 + 1 : fd2 + 1;
}

static int xenfb_kbd_event(struct xenfb_private *xenfb,
			   union xenkbd_in_event *event)
{
	uint32_t prod;
	struct xenkbd_page *page = xenfb->kbd.page;

	if (xenfb->kbd.state != XenbusStateConnected)
		return 0;

	prod = page->in_prod;
	if (prod - page->in_cons == XENKBD_IN_RING_LEN) {
		errno = EAGAIN;
		return -1;
	}

	mb();			/* ensure ring space available */
	XENKBD_IN_RING_REF(page, prod) = *event;
	wmb();			/* ensure ring contents visible */
	page->in_prod = prod + 1;
	return xc_evtchn_notify(xenfb->evt_xch, xenfb->kbd.port);
}

int xenfb_send_key(struct xenfb *xenfb_pub, bool down, int keycode)
{
	struct xenfb_private *xenfb = (struct xenfb_private *)xenfb_pub;
	union xenkbd_in_event event;

	memset(&event, 0, XENKBD_IN_EVENT_SIZE);
	event.type = XENKBD_TYPE_KEY;
	event.key.pressed = down ? 1 : 0;
	event.key.keycode = keycode;

	return xenfb_kbd_event(xenfb, &event);
}

int xenfb_send_motion(struct xenfb *xenfb_pub, int rel_x, int rel_y)
{
	struct xenfb_private *xenfb = (struct xenfb_private *)xenfb_pub;
	union xenkbd_in_event event;

	memset(&event, 0, XENKBD_IN_EVENT_SIZE);
	event.type = XENKBD_TYPE_MOTION;
	event.motion.rel_x = rel_x;
	event.motion.rel_y = rel_y;

	return xenfb_kbd_event(xenfb, &event);
}

int xenfb_send_position(struct xenfb *xenfb_pub, int abs_x, int abs_y)
{
	struct xenfb_private *xenfb = (struct xenfb_private *)xenfb_pub;
	union xenkbd_in_event event;

	memset(&event, 0, XENKBD_IN_EVENT_SIZE);
	event.type = XENKBD_TYPE_POS;
	event.pos.abs_x = abs_x;
	event.pos.abs_y = abs_y;

	return xenfb_kbd_event(xenfb, &event);
}
