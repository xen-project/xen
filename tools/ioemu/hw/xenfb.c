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
#include <stdbool.h>
#include <xen/event_channel.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <xs.h>

#include "xenfb.h"

#ifdef CONFIG_STUBDOM
#include <semaphore.h>
#include <sched.h>
#include <fbfront.h>
#endif

#ifndef BTN_LEFT
#define BTN_LEFT 0x110 /* from <linux/input.h> */
#endif

struct xenfb;

struct xenfb_device {
	const char *devicetype;
	char nodename[64];	/* backend xenstore dir */
	char otherend[64];	/* frontend xenstore dir */
	int otherend_id;	/* frontend domid */
	enum xenbus_state state; /* backend state */
	void *page;		/* shared page */
	evtchn_port_t port;
	struct xenfb *xenfb;
};

struct xenfb {
	DisplayState *ds;       /* QEMU graphical console state */
	int evt_xch;		/* event channel driver handle */
	int xc;			/* hypervisor interface handle */
	struct xs_handle *xsh;	/* xs daemon handle */
	struct xenfb_device fb, kbd;
	void *pixels;           /* guest framebuffer data */
	size_t fb_len;		/* size of framebuffer */
	int row_stride;         /* width of one row in framebuffer */
	int depth;              /* colour depth of guest framebuffer */
	int width;              /* pixel width of guest framebuffer */
	int height;             /* pixel height of guest framebuffer */
	int offset;             /* offset of the framebuffer */
	int abs_pointer_wanted; /* Whether guest supports absolute pointer */
	int button_state;       /* Last seen pointer button state */
	int refresh_period;     /* The refresh period we have advised */
	char protocol[64];	/* frontend protocol */
};

/* Functions for frontend/backend state machine*/
static int xenfb_wait_for_frontend(struct xenfb_device *dev, IOHandler *handler);
static int xenfb_wait_for_backend(struct xenfb_device *dev, IOHandler *handler);
static void xenfb_backend_created_kbd(void *opaque);
static void xenfb_backend_created_fb(void *opaque);
static void xenfb_frontend_initialized_kbd(void *opaque);
static void xenfb_frontend_initialized_fb(void *opaque);
static void xenfb_frontend_connected_kbd(void *opaque);

/* Helper functions for checking state of frontend/backend devices */
static int xenfb_frontend_connected(struct xenfb_device *dev);
static int xenfb_frontend_initialized(struct xenfb_device *dev);
static int xenfb_backend_created(struct xenfb_device *dev);

/* Functions which tie the PVFB into the QEMU device model */
static void xenfb_key_event(void *opaque, int keycode);
static void xenfb_mouse_event(void *opaque,
			      int dx, int dy, int dz, int button_state);
static void xenfb_guest_copy(struct xenfb *xenfb, int x, int y, int w, int h);
static void xenfb_update(void *opaque);
static void xenfb_invalidate(void *opaque);
static void xenfb_screen_dump(void *opaque, const char *name);
static int xenfb_register_console(struct xenfb *xenfb);

/*
 * Tables to map from scancode to Linux input layer keycode.
 * Scancodes are hardware-specific.  These maps assumes a 
 * standard AT or PS/2 keyboard which is what QEMU feeds us.
 */
static const unsigned char atkbd_set2_keycode[512] = {

	  0, 67, 65, 63, 61, 59, 60, 88,  0, 68, 66, 64, 62, 15, 41,117,
	  0, 56, 42, 93, 29, 16,  2,  0,  0,  0, 44, 31, 30, 17,  3,  0,
	  0, 46, 45, 32, 18,  5,  4, 95,  0, 57, 47, 33, 20, 19,  6,183,
	  0, 49, 48, 35, 34, 21,  7,184,  0,  0, 50, 36, 22,  8,  9,185,
	  0, 51, 37, 23, 24, 11, 10,  0,  0, 52, 53, 38, 39, 25, 12,  0,
	  0, 89, 40,  0, 26, 13,  0,  0, 58, 54, 28, 27,  0, 43,  0, 85,
	  0, 86, 91, 90, 92,  0, 14, 94,  0, 79,124, 75, 71,121,  0,  0,
	 82, 83, 80, 76, 77, 72,  1, 69, 87, 78, 81, 74, 55, 73, 70, 99,

	  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	217,100,255,  0, 97,165,  0,  0,156,  0,  0,  0,  0,  0,  0,125,
	173,114,  0,113,  0,  0,  0,126,128,  0,  0,140,  0,  0,  0,127,
	159,  0,115,  0,164,  0,  0,116,158,  0,150,166,  0,  0,  0,142,
	157,  0,  0,  0,  0,  0,  0,  0,155,  0, 98,  0,  0,163,  0,  0,
	226,  0,  0,  0,  0,  0,  0,  0,  0,255, 96,  0,  0,  0,143,  0,
	  0,  0,  0,  0,  0,  0,  0,  0,  0,107,  0,105,102,  0,  0,112,
	110,111,108,112,106,103,  0,119,  0,118,109,  0, 99,104,119,  0,

};

static const unsigned char atkbd_unxlate_table[128] = {

	  0,118, 22, 30, 38, 37, 46, 54, 61, 62, 70, 69, 78, 85,102, 13,
	 21, 29, 36, 45, 44, 53, 60, 67, 68, 77, 84, 91, 90, 20, 28, 27,
	 35, 43, 52, 51, 59, 66, 75, 76, 82, 14, 18, 93, 26, 34, 33, 42,
	 50, 49, 58, 65, 73, 74, 89,124, 17, 41, 88,  5,  6,  4, 12,  3,
	 11,  2, 10,  1,  9,119,126,108,117,125,123,107,115,116,121,105,
	114,122,112,113,127, 96, 97,120,  7, 15, 23, 31, 39, 47, 55, 63,
	 71, 79, 86, 94,  8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 87,111,
	 19, 25, 57, 81, 83, 92, 95, 98, 99,100,101,103,104,106,109,110

};

static unsigned char scancode2linux[512];

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
			      struct xenfb *xenfb)
{
	dev->devicetype = type;
	dev->otherend_id = -1;
	dev->port = -1;
	dev->xenfb = xenfb;
}

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

static int xenfb_device_set_domain(struct xenfb_device *dev, int domid)
{
        dev->otherend_id = domid;

        if (!xenfb_path_in_dom(dev->xenfb->xsh,
                               dev->otherend, sizeof(dev->otherend),
                               domid, "device/%s/0", dev->devicetype)) {
                errno = ENOENT;
                return -1;
        }
        if (!xenfb_path_in_dom(dev->xenfb->xsh,
                               dev->nodename, sizeof(dev->nodename),
                               0, "backend/%s/%d/0", dev->devicetype, domid)) {
                errno = ENOENT;
                return -1;
        }

        return 0;
}

struct xenfb *xenfb_new(int domid, DisplayState *ds)
{
	struct xenfb *xenfb = qemu_malloc(sizeof(struct xenfb));
	int serrno;
	int i;

	if (xenfb == NULL)
		return NULL;

	/* Prepare scancode mapping table */
	for (i = 0; i < 128; i++) {
		scancode2linux[i] = atkbd_set2_keycode[atkbd_unxlate_table[i]];
		scancode2linux[i | 0x80] = 
			atkbd_set2_keycode[atkbd_unxlate_table[i] | 0x80];
	}

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

	xenfb->ds = ds;
	xenfb_device_set_domain(&xenfb->fb, domid);
	xenfb_device_set_domain(&xenfb->kbd, domid);

	fprintf(stderr, "FB: Waiting for KBD backend creation\n");
	xenfb_wait_for_backend(&xenfb->kbd, xenfb_backend_created_kbd);

	return xenfb;

 fail:
	serrno = errno;
	xenfb_shutdown(xenfb);
	errno = serrno;
	return NULL;
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


static int xenfb_hotplug(struct xenfb_device *dev)
{
	if (xenfb_xs_printf(dev->xenfb->xsh, dev->nodename,
			    "hotplug-status", "connected"))
		return -1;
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

static int xenfb_map_fb(struct xenfb *xenfb, int domid)
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

	xenfb_copy_mfns(mode, n_fbdirs, pgmfns, pd);
	map = xc_map_foreign_pages(xenfb->xc, domid,
				   PROT_READ, pgmfns, n_fbdirs);
	if (map == NULL)
		goto out;
	xenfb_copy_mfns(mode, n_fbmfns, fbmfns, map);
	munmap(map, n_fbdirs * XC_PAGE_SIZE);

	xenfb->pixels = xc_map_foreign_pages(xenfb->xc, domid,
				PROT_READ | PROT_WRITE, fbmfns, n_fbmfns);
	if (xenfb->pixels == NULL)
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
	struct xenfb *xenfb = dev->xenfb;
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


static void xenfb_detach_dom(struct xenfb *xenfb)
{
	xenfb_unbind(&xenfb->fb);
	xenfb_unbind(&xenfb->kbd);
	if (xenfb->pixels) {
		munmap(xenfb->pixels, xenfb->fb_len);
		xenfb->pixels = NULL;
	}
}

/* Remove the backend area in xenbus since the framebuffer really is
   going away. */
void xenfb_shutdown(struct xenfb *xenfb)
{
	fprintf(stderr, "FB: Shutting down backend\n");
	xs_rm(xenfb->xsh, XBT_NULL, xenfb->fb.nodename);
	xs_rm(xenfb->xsh, XBT_NULL, xenfb->kbd.nodename);

	xenfb_detach_dom(xenfb);
	if (xenfb->xc >= 0)
		xc_interface_close(xenfb->xc);
	if (xenfb->evt_xch >= 0)
		xc_evtchn_close(xenfb->evt_xch);
	if (xenfb->xsh)
		xs_daemon_close(xenfb->xsh);
	free(xenfb);
}

static int xenfb_configure_fb(struct xenfb *xenfb, size_t fb_len_lim,
			      int width, int height, int depth,
			      size_t fb_len, int offset, int row_stride)
{
	size_t mfn_sz = sizeof(*((struct xenfb_page *)0)->pd);
	size_t pd_len = sizeof(((struct xenfb_page *)0)->pd) / mfn_sz;
	size_t fb_pages = pd_len * XC_PAGE_SIZE / mfn_sz;
	size_t fb_len_max = fb_pages * XC_PAGE_SIZE;
	int max_width, max_height;

	if (fb_len_lim > fb_len_max) {
		fprintf(stderr,
			"FB: fb size limit %zu exceeds %zu, corrected\n",
			fb_len_lim, fb_len_max);
		fb_len_lim = fb_len_max;
	}
	if (fb_len > fb_len_lim) {
		fprintf(stderr,
			"FB: frontend fb size %zu limited to %zu\n",
			fb_len, fb_len_lim);
		fb_len = fb_len_lim;
	}
	if (depth != 8 && depth != 16 && depth != 24 && depth != 32) {
		fprintf(stderr,
			"FB: can't handle frontend fb depth %d\n",
			depth);
		return -1;
	}
	if (row_stride < 0 || row_stride > fb_len) {
		fprintf(stderr,
			"FB: invalid frontend stride %d\n", row_stride);
		return -1;
	}
	max_width = row_stride / (depth / 8);
	if (width < 0 || width > max_width) {
		fprintf(stderr,
			"FB: invalid frontend width %d limited to %d\n",
			width, max_width);
		width = max_width;
	}
	if (offset < 0 || offset >= fb_len) {
		fprintf(stderr,
			"FB: invalid frontend offset %d (max %zu)\n",
			offset, fb_len - 1);
		return -1;
	}
	max_height = (fb_len - offset) / row_stride;
	if (height < 0 || height > max_height) {
		fprintf(stderr,
			"FB: invalid frontend height %d limited to %d\n",
			height, max_height);
		height = max_height;
	}
	xenfb->fb_len = fb_len;
	xenfb->row_stride = row_stride;
	xenfb->depth = depth;
	xenfb->width = width;
	xenfb->height = height;
	xenfb->offset = offset;
	fprintf(stderr, "Framebuffer %dx%dx%d offset %d stride %d\n",
		width, height, depth, offset, row_stride);
	return 0;
}

static void xenfb_on_fb_event(struct xenfb *xenfb)
{
	uint32_t prod, cons;
	struct xenfb_page *page = xenfb->fb.page;

	prod = page->out_prod;
	if (prod == page->out_cons)
		return;
	xen_rmb();		/* ensure we see ring contents up to prod */
	for (cons = page->out_cons; cons != prod; cons++) {
		union xenfb_out_event *event = &XENFB_OUT_RING_REF(page, cons);
		int x, y, w, h;

		switch (event->type) {
		case XENFB_TYPE_UPDATE:
			x = MAX(event->update.x, 0);
			y = MAX(event->update.y, 0);
			w = MIN(event->update.width, xenfb->width - x);
			h = MIN(event->update.height, xenfb->height - y);
			if (w < 0 || h < 0) {
				fprintf(stderr, "%s bogus update ignored\n",
					xenfb->fb.nodename);
				break;
			}
			if (x != event->update.x || y != event->update.y
			    || w != event->update.width
			    || h != event->update.height) {
				fprintf(stderr, "%s bogus update clipped\n",
					xenfb->fb.nodename);
			}
			xenfb_guest_copy(xenfb, x, y, w, h);
			break;
		case XENFB_TYPE_RESIZE:
			if (xenfb_configure_fb(xenfb, xenfb->fb_len,
					       event->resize.width,
					       event->resize.height,
					       event->resize.depth,
					       xenfb->fb_len,
					       event->resize.offset,
					       event->resize.stride) < 0)
				break;
			dpy_colourdepth(xenfb->ds, xenfb->depth);
			dpy_resize(xenfb->ds, xenfb->width, xenfb->height, xenfb->row_stride);
			if (xenfb->ds->shared_buf)
				dpy_setdata(xenfb->ds, xenfb->pixels + xenfb->offset);
			xenfb_invalidate(xenfb);
			break;
		}
	}
	xen_mb();		/* ensure we're done with ring contents */
	page->out_cons = cons;
	xc_evtchn_notify(xenfb->evt_xch, xenfb->fb.port);
}

static int xenfb_queue_full(struct xenfb *xenfb)
{
	struct xenfb_page *page = xenfb->fb.page;
	uint32_t cons, prod;

	prod = page->in_prod;
	cons = page->in_cons;
	return prod - cons == XENFB_IN_RING_LEN;
}

static void xenfb_send_event(struct xenfb *xenfb, union xenfb_in_event *event)
{
	uint32_t prod;
	struct xenfb_page *page = xenfb->fb.page;

	prod = page->in_prod;
	/* caller ensures !xenfb_queue_full() */
	xen_mb();                   /* ensure ring space available */
	XENFB_IN_RING_REF(page, prod) = *event;
	xen_wmb();                  /* ensure ring contents visible */
	page->in_prod = prod + 1;

	xc_evtchn_notify(xenfb->evt_xch, xenfb->fb.port);
}

static void xenfb_send_refresh_period(struct xenfb *xenfb, int period)
{
	union xenfb_in_event event;

	memset(&event, 0, sizeof(event));
	event.type = XENFB_TYPE_REFRESH_PERIOD;
	event.refresh_period.period = period;
	xenfb_send_event(xenfb, &event);
}

static void xenfb_on_kbd_event(struct xenfb *xenfb)
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

/* Send an event to the keyboard frontend driver */
static int xenfb_kbd_event(struct xenfb *xenfb,
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

	xen_mb();		/* ensure ring space available */
	XENKBD_IN_RING_REF(page, prod) = *event;
	xen_wmb();		/* ensure ring contents visible */
	page->in_prod = prod + 1;
	return xc_evtchn_notify(xenfb->evt_xch, xenfb->kbd.port);
}

/* Send a keyboard (or mouse button) event */
static int xenfb_send_key(struct xenfb *xenfb, bool down, int keycode)
{
	union xenkbd_in_event event;

	memset(&event, 0, XENKBD_IN_EVENT_SIZE);
	event.type = XENKBD_TYPE_KEY;
	event.key.pressed = down ? 1 : 0;
	event.key.keycode = keycode;

	return xenfb_kbd_event(xenfb, &event);
}

/* Send a relative mouse movement event */
static int xenfb_send_motion(struct xenfb *xenfb,
			     int rel_x, int rel_y, int rel_z)
{
	union xenkbd_in_event event;

	memset(&event, 0, XENKBD_IN_EVENT_SIZE);
	event.type = XENKBD_TYPE_MOTION;
	event.motion.rel_x = rel_x;
	event.motion.rel_y = rel_y;
	event.motion.rel_z = rel_z;

	return xenfb_kbd_event(xenfb, &event);
}

/* Send an absolute mouse movement event */
static int xenfb_send_position(struct xenfb *xenfb,
			       int abs_x, int abs_y, int rel_z)
{
	union xenkbd_in_event event;

	memset(&event, 0, XENKBD_IN_EVENT_SIZE);
	event.type = XENKBD_TYPE_POS;
	event.pos.abs_x = abs_x;
	event.pos.abs_y = abs_y;
	event.pos.rel_z = rel_z;

	return xenfb_kbd_event(xenfb, &event);
}

/* Process events from the frontend event channel */
static void xenfb_dispatch_channel(void *opaque)
{
	struct xenfb *xenfb = (struct xenfb *)opaque;
	evtchn_port_t port;
	port = xc_evtchn_pending(xenfb->evt_xch);
	if (port == -1) {
		xenfb_shutdown(xenfb);
		exit(1);
	}

	if (port == xenfb->fb.port)
		xenfb_on_fb_event(xenfb);
	else if (port == xenfb->kbd.port)
		xenfb_on_kbd_event(xenfb);

	if (xc_evtchn_unmask(xenfb->evt_xch, port) == -1) {
		xenfb_shutdown(xenfb);
		exit(1);
	}
}

/* Process ongoing events from the frontend devices */
static void xenfb_dispatch_store(void *opaque)
{
	struct xenfb *xenfb = (struct xenfb *)opaque;
	unsigned dummy;
	char **vec;
	int r;

	vec = xs_read_watch(xenfb->xsh, &dummy);
	free(vec);
	r = xenfb_on_state_change(&xenfb->fb);
	if (r == 0)
		r = xenfb_on_state_change(&xenfb->kbd);
	if (r < 0) {
		xenfb_shutdown(xenfb);
		exit(1);
	}
}


/****************************************************************
 *
 * Functions for processing frontend config
 *
 ****************************************************************/


/* Process the frontend framebuffer config */
static int xenfb_read_frontend_fb_config(struct xenfb *xenfb) {
	struct xenfb_page *fb_page;
	int val;
	int videoram;

        if (xenfb_xs_scanf1(xenfb->xsh, xenfb->fb.otherend, "feature-update",
                            "%d", &val) < 0)
                val = 0;
        if (!val) {
                fprintf(stderr, "feature-update not supported\n");
                errno = ENOTSUP;
                return -1;
        }
        if (xenfb_xs_scanf1(xenfb->xsh, xenfb->fb.otherend, "protocol", "%63s",
                            xenfb->protocol) < 0)
                xenfb->protocol[0] = '\0';
        xenfb_xs_printf(xenfb->xsh, xenfb->fb.nodename, "request-update", "1");
        xenfb->refresh_period = -1;

        if (xenfb_xs_scanf1(xenfb->xsh, xenfb->fb.nodename, "videoram", "%d",
                            &videoram) < 0)
                videoram = 0;
	fb_page = xenfb->fb.page;
	if (xenfb_configure_fb(xenfb, videoram * 1024 * 1024U,
			       fb_page->width, fb_page->height, fb_page->depth,
			       fb_page->mem_length, 0, fb_page->line_length)
	    < 0) {
		errno = EINVAL;
		return -1;
	}

        if (xenfb_map_fb(xenfb, xenfb->fb.otherend_id) < 0)
		return -1;

        /* Indicate we have the frame buffer resize feature */
        xenfb_xs_printf(xenfb->xsh, xenfb->fb.nodename, "feature-resize", "1");

        /* Tell kbd pointer the screen geometry */
        xenfb_xs_printf(xenfb->xsh, xenfb->kbd.nodename, "width", "%d", xenfb->width);
        xenfb_xs_printf(xenfb->xsh, xenfb->kbd.nodename, "height", "%d", xenfb->height);

        if (xenfb_switch_state(&xenfb->fb, XenbusStateConnected))
                return -1;
        if (xenfb_switch_state(&xenfb->kbd, XenbusStateConnected))
                return -1;

	return 0;
}

/* Process the frontend keyboard config */
static int xenfb_read_frontend_kbd_config(struct xenfb *xenfb)
{
	int val;

	if (xenfb_xs_scanf1(xenfb->xsh, xenfb->kbd.otherend, "request-abs-pointer",
			    "%d", &val) < 0)
		val = 0;
	xenfb->abs_pointer_wanted = val;

	return 0;
}


/****************************************************************
 *
 * Functions for frontend/backend state machine
 *
 ****************************************************************/

/* Register a watch against a frontend device, and setup
 * QEMU event loop to poll the xenstore FD for notification */
static int xenfb_wait_for_frontend(struct xenfb_device *dev, IOHandler *handler)
{
        fprintf(stderr, "Doing frontend watch on %s\n", dev->otherend);
	if (!xs_watch(dev->xenfb->xsh, dev->otherend, "")) {
		fprintf(stderr, "Watch for dev failed\n");
		return -1;
	}

	if (qemu_set_fd_handler2(xs_fileno(dev->xenfb->xsh), NULL, handler, NULL, dev) < 0)
		return -1;

	return 0;
}

/* Register a watch against a backend device, and setup
 * QEMU event loop to poll the xenstore FD for notification */
static int xenfb_wait_for_backend(struct xenfb_device *dev, IOHandler *handler)
{
	fprintf(stderr, "Doing backend watch on %s\n", dev->nodename);
	if (!xs_watch(dev->xenfb->xsh, dev->nodename, "")) {
		fprintf(stderr, "Watch for dev failed\n");
		return -1;
	}

	if (qemu_set_fd_handler2(xs_fileno(dev->xenfb->xsh), NULL, handler, NULL, dev) < 0)
		return -1;

	return 0;
}

/* Callback invoked while waiting for KBD backend to change
 * to the created state */
static void xenfb_backend_created_kbd(void *opaque)
{
	struct xenfb_device *dev = (struct xenfb_device *)opaque;
	int ret = xenfb_backend_created(dev);
	if (ret < 0) {
		xenfb_shutdown(dev->xenfb);
		exit(1);
	}
	if (ret)
		return; /* Still waiting */

	if (xenfb_xs_printf(dev->xenfb->xsh, dev->nodename, "feature-abs-pointer", "1")) {
		xenfb_shutdown(dev->xenfb);
		exit(1);
	}

	fprintf(stderr, "FB: Waiting for FB backend creation\n");
	xenfb_wait_for_backend(&dev->xenfb->fb, xenfb_backend_created_fb);
}

/* Callback invoked while waiting for FB backend to change
 * to the created state */
static void xenfb_backend_created_fb(void *opaque)
{
	struct xenfb_device *dev = (struct xenfb_device *)opaque;
	int ret = xenfb_backend_created(dev);
	if (ret < 0) {
		xenfb_shutdown(dev->xenfb);
		exit(1);
	}
	if (ret)
		return; /* Still waiting */

	fprintf(stderr, "FB: Waiting for KBD frontend initialization\n");
	xenfb_wait_for_frontend(&dev->xenfb->kbd, xenfb_frontend_initialized_kbd);
}

/* Callback invoked while waiting for KBD frontend to change
 * to the initialized state */
static void xenfb_frontend_initialized_kbd(void *opaque)
{
	struct xenfb_device *dev = (struct xenfb_device *)opaque;
	int ret = xenfb_frontend_initialized(dev);
	if (ret < 0) {
		xenfb_shutdown(dev->xenfb);
		exit(1);
	}
	if (ret)
		return; /* Still waiting */


        fprintf(stderr, "FB: Waiting for FB frontend initialization\n");
	xenfb_wait_for_frontend(&dev->xenfb->fb, xenfb_frontend_initialized_fb);
}

/* Callback invoked while waiting for FB frontend to change
 * to the initialized state */
static void xenfb_frontend_initialized_fb(void *opaque)
{
	struct xenfb_device *dev = (struct xenfb_device *)opaque;
	int ret = xenfb_frontend_initialized(dev);
	if (ret < 0) {
		xenfb_shutdown(dev->xenfb);
		exit(1);
	}
	if (ret)
		return; /* Still waiting */


	if (xenfb_read_frontend_fb_config(dev->xenfb)) {
		xenfb_shutdown(dev->xenfb);
	        exit(1);
	}

        fprintf(stderr, "FB: Waiting for KBD frontend connection\n");
	xenfb_wait_for_frontend(&dev->xenfb->kbd, xenfb_frontend_connected_kbd);
}

/* Callback invoked while waiting for KBD frontend to change
 * to the connected state */
static void xenfb_frontend_connected_kbd(void *opaque)
{
	struct xenfb_device *dev = (struct xenfb_device *)opaque;
	int ret = xenfb_frontend_connected(dev);
	if (ret < 0) {
		xenfb_shutdown(dev->xenfb);
		exit(1);
	}
	if (ret)
		return; /* Still waiting */

	if (xenfb_read_frontend_kbd_config(dev->xenfb) < 0) {
		xenfb_shutdown(dev->xenfb);
	        exit(1);
	}

	xenfb_register_console(dev->xenfb);
}


/****************************************************************
 *
 * Helper functions for checking state of frontend/backend devices
 *
 ****************************************************************/

/* Helper to determine if a frontend device is in Connected state */
static int xenfb_frontend_connected(struct xenfb_device *dev)
{
	unsigned int state;
	unsigned int dummy;
	char **vec;
	vec = xs_read_watch(dev->xenfb->xsh, &dummy);
	if (!vec)
		return -1;
	free(vec);

	state = xenfb_read_state(dev->xenfb->xsh, dev->otherend);
	if (!((1 <<state) & ((1 << XenbusStateUnknown) |
			     (1 << XenbusStateConnected)))) {
		fprintf(stderr, "FB: Carry on waiting\n");
		return 1;
	}

	/* Don't unwatch frontend - we need to detect shutdown */
	/*xs_unwatch(dev->xenfb->xsh, dev->otherend, "");*/

	switch (state) {
	case XenbusStateConnected:
		break;
	default:
		return -1;
	}
	return 0;
}


/* Helper to determine if a frontend device is in Initialized state */
static int xenfb_frontend_initialized(struct xenfb_device *dev)
{
	unsigned int state;
	unsigned int dummy;
	char **vec;
	vec = xs_read_watch(dev->xenfb->xsh, &dummy);
	if (!vec)
		return -1;
	free(vec);

	state = xenfb_read_state(dev->xenfb->xsh, dev->otherend);

	if (!((1 << state) & ((1 << XenbusStateUnknown)
			      | (1 << XenbusStateInitialised)
#if 1 /* TODO fudging state to permit restarting; to be removed */
			      | (1 << XenbusStateConnected)
#endif
			      ))) {
		fprintf(stderr, "FB: Carry on waiting\n");
		return 1;
	}

	xs_unwatch(dev->xenfb->xsh, dev->otherend, "");

	switch (state) {
#if 1
	case XenbusStateConnected:
                printf("Fudging state to %d\n", XenbusStateInitialised); /* FIXME */
#endif
        case XenbusStateInitialised:
                break;
        default:
                return -1;
        }

	if (xenfb_bind(dev) < 0)
		return -1;

	return 0;
}

/* Helper to determine if a backend device is in Created state */
static int xenfb_backend_created(struct xenfb_device *dev)
{
	unsigned int state;
	unsigned int dummy;
	char **vec;
	vec = xs_read_watch(dev->xenfb->xsh, &dummy);
	if (!vec)
		return -1;
	free(vec);

	state = xenfb_read_state(dev->xenfb->xsh, dev->nodename);

	if (!((1 <<state) & ((1 << XenbusStateUnknown)
			     | (1 << XenbusStateInitialising)
			     | (1 << XenbusStateClosed)
#if 1 /* TODO fudging state to permit restarting; to be removed */
			     | (1 << XenbusStateInitWait)
			     | (1 << XenbusStateConnected)
			     | (1 << XenbusStateClosing)
#endif
			     ))) {
		fprintf(stderr, "FB: Carry on waiting\n");
		return 1;
	}

	xs_unwatch(dev->xenfb->xsh, dev->nodename, "");

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
                fprintf(stderr, "Wrong state %d\n", state);
                return -1;
        }
        xenfb_switch_state(dev, XenbusStateInitWait);
        if (xenfb_hotplug(dev) < 0)
                return -1;

        return 0;
}


/****************************************************************
 * 
 * QEMU device model integration functions
 *
 ****************************************************************/

/* 
 * Send a key event from the client to the guest OS
 * QEMU gives us a raw scancode from an AT / PS/2 style keyboard.
 * We have to turn this into a Linux Input layer keycode.
 * 
 * Extra complexity from the fact that with extended scancodes 
 * (like those produced by arrow keys) this method gets called
 * twice, but we only want to send a single event. So we have to
 * track the '0xe0' scancode state & collapse the extended keys
 * as needed.
 * 
 * Wish we could just send scancodes straight to the guest which
 * already has code for dealing with this...
 */
static void xenfb_key_event(void *opaque, int scancode)
{
    static int extended = 0;
    int down = 1;
    if (scancode == 0xe0) {
        extended = 1;
        return;
    } else if (scancode & 0x80) {
        scancode &= 0x7f;
        down = 0;
    }
    if (extended) {
        scancode |= 0x80;
        extended = 0;
    }
    xenfb_send_key(opaque, down, scancode2linux[scancode]);
}

/*
 * Send a mouse event from the client to the guest OS
 * 
 * The QEMU mouse can be in either relative, or absolute mode.
 * Movement is sent separately from button state, which has to
 * be encoded as virtual key events. We also don't actually get
 * given any button up/down events, so have to track changes in
 * the button state.
 */
static void xenfb_mouse_event(void *opaque,
			      int dx, int dy, int dz, int button_state)
{
    int i;
    struct xenfb *xenfb = opaque;
    if (xenfb->abs_pointer_wanted)
	    xenfb_send_position(xenfb,
                                dx * (xenfb->ds->width - 1) / 0x7fff,
                                dy * (xenfb->ds->height - 1) / 0x7fff,
				dz);
    else
	    xenfb_send_motion(xenfb, dx, dy, dz);

    for (i = 0 ; i < 8 ; i++) {
	    int lastDown = xenfb->button_state & (1 << i);
	    int down = button_state & (1 << i);
	    if (down == lastDown)
		    continue;

	    if (xenfb_send_key(xenfb, down, BTN_LEFT+i) < 0)
		    return;
    }
    xenfb->button_state = button_state;
}

/* A convenient function for munging pixels between different depths */
#define BLT(SRC_T,DST_T,RSB,GSB,BSB,RDB,GDB,BDB)                        \
    for (line = y ; line < (y+h) ; line++) {                            \
        SRC_T *src = (SRC_T *)(xenfb->pixels                            \
                               + xenfb->offset                          \
                               + (line * xenfb->row_stride)             \
                               + (x * xenfb->depth / 8));               \
        DST_T *dst = (DST_T *)(xenfb->ds->data                                 \
                               + (line * xenfb->ds->linesize)                  \
                               + (x * xenfb->ds->depth / 8));                  \
        int col;                                                        \
        const int RSS = 32 - (RSB + GSB + BSB);                         \
        const int GSS = 32 - (GSB + BSB);                               \
        const int BSS = 32 - (BSB);                                     \
        const uint32_t RSM = (~0U) << (32 - RSB);                       \
        const uint32_t GSM = (~0U) << (32 - GSB);                       \
        const uint32_t BSM = (~0U) << (32 - BSB);                       \
        const int RDS = 32 - (RDB + GDB + BDB);                         \
        const int GDS = 32 - (GDB + BDB);                               \
        const int BDS = 32 - (BDB);                                     \
        const uint32_t RDM = (~0U) << (32 - RDB);                       \
        const uint32_t GDM = (~0U) << (32 - GDB);                       \
        const uint32_t BDM = (~0U) << (32 - BDB);                       \
        for (col = x ; col < (x+w) ; col++) {                           \
            uint32_t spix = *src;                                       \
            *dst = (((spix << RSS) & RSM & RDM) >> RDS) |               \
                   (((spix << GSS) & GSM & GDM) >> GDS) |               \
                   (((spix << BSS) & BSM & BDM) >> BDS);                \
            src = (SRC_T *) ((unsigned long) src + xenfb->depth / 8);   \
            dst = (DST_T *) ((unsigned long) dst + xenfb->ds->depth / 8); \
        }                                                               \
    }


/* This copies data from the guest framebuffer region, into QEMU's copy
 * NB. QEMU's copy is stored in the pixel format of a) the local X 
 * server (SDL case) or b) the current VNC client pixel format.
 * When shifting between colour depths we preserve the MSB.
 */
static void xenfb_guest_copy(struct xenfb *xenfb, int x, int y, int w, int h)
{
    int line;

    if (!xenfb->ds->shared_buf) {
        if (xenfb->depth == xenfb->ds->depth) { /* Perfect match can use fast path */
            for (line = y ; line < (y+h) ; line++) {
                memcpy(xenfb->ds->data + (line * xenfb->ds->linesize) + (x * xenfb->ds->depth / 8),
                        xenfb->pixels + xenfb->offset + (line * xenfb->row_stride) + (x * xenfb->depth / 8),
                        w * xenfb->depth / 8);
            }
        } else { /* Mismatch requires slow pixel munging */
            /* 8 bit == r:3 g:3 b:2 */
            /* 16 bit == r:5 g:6 b:5 */
            /* 24 bit == r:8 g:8 b:8 */
            /* 32 bit == r:8 g:8 b:8 (padding:8) */
            if (xenfb->depth == 8) {
                if (xenfb->ds->depth == 16) {
                    BLT(uint8_t, uint16_t,   3, 3, 2,   5, 6, 5);
                } else if (xenfb->ds->depth == 32) {
                    BLT(uint8_t, uint32_t,   3, 3, 2,   8, 8, 8);
                }
            } else if (xenfb->depth == 16) {
                if (xenfb->ds->depth == 8) {
                    BLT(uint16_t, uint8_t,   5, 6, 5,   3, 3, 2);
                } else if (xenfb->ds->depth == 32) {
                    BLT(uint16_t, uint32_t,  5, 6, 5,   8, 8, 8);
                }
            } else if (xenfb->depth == 24 || xenfb->depth == 32) {
                if (xenfb->ds->depth == 8) {
                    BLT(uint32_t, uint8_t,   8, 8, 8,   3, 3, 2);
                } else if (xenfb->ds->depth == 16) {
                    BLT(uint32_t, uint16_t,  8, 8, 8,   5, 6, 5);
                } else if (xenfb->ds->depth == 32) {
                    BLT(uint32_t, uint32_t,  8, 8, 8,   8, 8, 8);
                }
            }
        }
    }
    dpy_update(xenfb->ds, x, y, w, h);
}

/* Periodic update of display, transmit the refresh interval to the frontend */
static void xenfb_update(void *opaque)
{
    struct xenfb *xenfb = opaque;
    int period;

    if (xenfb_queue_full(xenfb))
        return;

    if (xenfb->ds->idle)
        period = XENFB_NO_REFRESH;
    else {
        period = xenfb->ds->gui_timer_interval;
        if (!period)
            period = GUI_REFRESH_INTERVAL;
    }

    /* Will have to be disabled for frontends without feature-update */
    if (xenfb->refresh_period != period) {
        xenfb_send_refresh_period(xenfb, period);
        xenfb->refresh_period = period;
    }
}

/* QEMU display state changed, so refresh the framebuffer copy */
static void xenfb_invalidate(void *opaque)
{
    struct xenfb *xenfb = opaque;
    xenfb_guest_copy(xenfb, 0, 0, xenfb->width, xenfb->height);
}

/* Screen dump is not used in Xen, so no need to impl this....yet */
static void xenfb_screen_dump(void *opaque, const char *name) { }


/* Register a QEMU graphical console, and key/mouse handler,
 * connecting up their events to the frontend */
static int xenfb_register_console(struct xenfb *xenfb) {
	/* Register our keyboard & mouse handlers */
	qemu_add_kbd_event_handler(xenfb_key_event, xenfb);
	qemu_add_mouse_event_handler(xenfb_mouse_event, xenfb,
  				     xenfb->abs_pointer_wanted,
  				     "Xen PVFB Mouse");
  
  	/* Tell QEMU to allocate a graphical console */
	graphic_console_init(xenfb->ds,
			     xenfb_update,
			     xenfb_invalidate,
			     xenfb_screen_dump,
			     xenfb);
	dpy_colourdepth(xenfb->ds, xenfb->depth);
        dpy_resize(xenfb->ds, xenfb->width, xenfb->height, xenfb->row_stride);
	if (xenfb->ds->shared_buf)
	    dpy_setdata(xenfb->ds, xenfb->pixels);

	if (qemu_set_fd_handler2(xc_evtchn_fd(xenfb->evt_xch), NULL, xenfb_dispatch_channel, NULL, xenfb) < 0)
	        return -1;
	if (qemu_set_fd_handler2(xs_fileno(xenfb->xsh), NULL, xenfb_dispatch_store, NULL, xenfb) < 0)
		return -1;

        fprintf(stderr, "Xen Framebuffer registered\n");
        return 0;
}

#ifdef CONFIG_STUBDOM
typedef struct XenFBState {
    struct semaphore kbd_sem;
    struct kbdfront_dev *kbd_dev;
    struct fbfront_dev *fb_dev;
    void *vga_vram, *nonshared_vram;
    DisplayState *ds;
} XenFBState;

XenFBState *xs;

static char *kbd_path, *fb_path;

static unsigned char linux2scancode[KEY_MAX + 1];

int xenfb_connect_vkbd(const char *path)
{
    kbd_path = strdup(path);
    return 0;
}

int xenfb_connect_vfb(const char *path)
{
    fb_path = strdup(path);
    return 0;
}

static void xenfb_pv_update(DisplayState *ds, int x, int y, int w, int h)
{
    XenFBState *xs = ds->opaque;
    struct fbfront_dev *fb_dev = xs->fb_dev;
    if (!fb_dev)
        return;
    fbfront_update(fb_dev, x, y, w, h);
}

static void xenfb_pv_resize(DisplayState *ds, int w, int h, int linesize)
{
    XenFBState *xs = ds->opaque;
    struct fbfront_dev *fb_dev = xs->fb_dev;
    fprintf(stderr,"resize to %dx%d, %d required\n", w, h, linesize);
    ds->width = w;
    ds->height = h;
    if (!linesize)
        ds->shared_buf = 0;
    if (!ds->shared_buf)
        linesize = w * 4;
    ds->linesize = linesize;
    if (!fb_dev)
        return;
    if (ds->shared_buf) {
        ds->data = NULL;
    } else {
        ds->data = xs->nonshared_vram;
        fbfront_resize(fb_dev, w, h, linesize, ds->depth, VGA_RAM_SIZE);
    }
}

static void xenfb_pv_colourdepth(DisplayState *ds, int depth)
{
    XenFBState *xs = ds->opaque;
    struct fbfront_dev *fb_dev = xs->fb_dev;
    static int lastdepth = -1;
    if (!depth) {
        ds->shared_buf = 0;
        ds->depth = 32;
    } else {
        ds->shared_buf = 1;
        ds->depth = depth;
    }
    if (depth != lastdepth) {
        fprintf(stderr,"redepth to %d required\n", depth);
        lastdepth = depth;
    } else return;
    if (!fb_dev)
        return;
    if (ds->shared_buf) {
        ds->data = NULL;
    } else {
        ds->data = xs->nonshared_vram;
        fbfront_resize(fb_dev, ds->width, ds->height, ds->linesize, ds->depth, VGA_RAM_SIZE);
    }
}

static void xenfb_pv_setdata(DisplayState *ds, void *pixels)
{
    XenFBState *xs = ds->opaque;
    struct fbfront_dev *fb_dev = xs->fb_dev;
    int offset = pixels - xs->vga_vram;
    ds->data = pixels;
    if (!fb_dev)
        return;
    fbfront_resize(fb_dev, ds->width, ds->height, ds->linesize, ds->depth, offset);
}

static void xenfb_pv_refresh(DisplayState *ds)
{
    vga_hw_update();
}

static void xenfb_fb_handler(void *opaque)
{
#define FB_NUM_BATCH 4
    union xenfb_in_event buf[FB_NUM_BATCH];
    int n, i;
    XenFBState *xs = opaque;
    DisplayState *ds = xs->ds;

    n = fbfront_receive(xs->fb_dev, buf, FB_NUM_BATCH);
    for (i = 0; i < n; i++) {
        switch (buf[i].type) {
        case XENFB_TYPE_REFRESH_PERIOD:
            if (buf[i].refresh_period.period == XENFB_NO_REFRESH) {
                /* Sleeping interval */
                ds->idle = 1;
                ds->gui_timer_interval = 500;
            } else {
                /* Set interval */
                ds->idle = 0;
                ds->gui_timer_interval = buf[i].refresh_period.period;
            }
        default:
            /* ignore unknown events */
            break;
        }
    }
}

static void xenfb_kbd_handler(void *opaque)
{
#define KBD_NUM_BATCH 64
    union xenkbd_in_event buf[KBD_NUM_BATCH];
    int n, i;
    XenFBState *xs = opaque;
    DisplayState *s = xs->ds;
    static int buttons;
    static int x, y;

    n = kbdfront_receive(xs->kbd_dev, buf, KBD_NUM_BATCH);
    for (i = 0; i < n; i++) {
        switch (buf[i].type) {

            case XENKBD_TYPE_MOTION:
                fprintf(stderr, "FB backend sent us relative mouse motion event!\n");
                break;

            case XENKBD_TYPE_POS:
            {
                int new_x = buf[i].pos.abs_x;
                int new_y = buf[i].pos.abs_y;
                if (new_x >= s->width)
                    new_x = s->width - 1;
                if (new_y >= s->height)
                    new_y = s->height - 1;
                if (kbd_mouse_is_absolute()) {
                    kbd_mouse_event(
                            new_x * 0x7FFF / (s->width - 1),
                            new_y * 0x7FFF / (s->height - 1),
                            buf[i].pos.rel_z,
                            buttons);
                } else {
                    kbd_mouse_event(
                            new_x - x,
                            new_y - y,
                            buf[i].pos.rel_z,
                            buttons);
                }
                x = new_x;
                y = new_y;
                break;
            }

            case XENKBD_TYPE_KEY:
            {
                int keycode = buf[i].key.keycode;
                int button = 0;

                if (keycode == BTN_LEFT)
                    button = MOUSE_EVENT_LBUTTON;
                else if (keycode == BTN_RIGHT)
                    button = MOUSE_EVENT_RBUTTON;
                else if (keycode == BTN_MIDDLE)
                    button = MOUSE_EVENT_MBUTTON;

                if (button) {
                    if (buf[i].key.pressed)
                        buttons |=  button;
                    else
                        buttons &= ~button;
                    if (kbd_mouse_is_absolute())
                        kbd_mouse_event(
                                x * 0x7FFF / (s->width - 1),
                                y * 0x7FFF / (s->height - 1),
                                0,
                                buttons);
                    else
                        kbd_mouse_event(0, 0, 0, buttons);
                } else {
                    int scancode = linux2scancode[keycode];
                    if (!scancode) {
                        fprintf(stderr, "Can't convert keycode %x to scancode\n", keycode);
                        break;
                    }
                    if (scancode & 0x80) {
                        kbd_put_keycode(0xe0);
                        scancode &= 0x7f;
                    }
                    if (!buf[i].key.pressed)
                        scancode |= 0x80;
                    kbd_put_keycode(scancode);
                }
                break;
            }
        }
    }
}

static void kbdfront_thread(void *p)
{
    int scancode, keycode;
    XenFBState *xs = p;
    xs->kbd_dev = init_kbdfront(kbd_path, 1);
    if (!xs->kbd_dev) {
        fprintf(stderr,"can't open keyboard\n");
        exit(1);
    }
    up(&xs->kbd_sem);
    for (scancode = 0; scancode < 128; scancode++) {
        keycode = atkbd_set2_keycode[atkbd_unxlate_table[scancode]];
        linux2scancode[keycode] = scancode;
        keycode = atkbd_set2_keycode[atkbd_unxlate_table[scancode] | 0x80];
        linux2scancode[keycode] = scancode | 0x80;
    }
}

int xenfb_pv_display_init(DisplayState *ds)
{
    if (!fb_path || !kbd_path)
        return -1;

    xs = qemu_mallocz(sizeof(XenFBState));
    if (!xs)
        return -1;

    init_SEMAPHORE(&xs->kbd_sem, 0);
    xs->ds = ds;

    create_thread("kbdfront", kbdfront_thread, (void*) xs);

    ds->data = xs->nonshared_vram = qemu_memalign(PAGE_SIZE, VGA_RAM_SIZE);
    memset(ds->data, 0, VGA_RAM_SIZE);
    ds->opaque = xs;
    ds->depth = 32;
    ds->bgr = 0;
    ds->width = 640;
    ds->height = 400;
    ds->linesize = 640 * 4;
    ds->dpy_update = xenfb_pv_update;
    ds->dpy_resize = xenfb_pv_resize;
    ds->dpy_colourdepth = xenfb_pv_colourdepth;
    ds->dpy_setdata = xenfb_pv_setdata;
    ds->dpy_refresh = xenfb_pv_refresh;
    return 0;
}

int xenfb_pv_display_start(void *data)
{
    DisplayState *ds;
    struct fbfront_dev *fb_dev;
    int kbd_fd, fb_fd;
    int offset = 0;
    unsigned long *mfns;
    int n = VGA_RAM_SIZE / PAGE_SIZE;
    int i;

    if (!fb_path || !kbd_path)
        return 0;

    ds = xs->ds;
    xs->vga_vram = data;
    mfns = malloc(2 * n * sizeof(*mfns));
    for (i = 0; i < n; i++)
        mfns[i] = virtual_to_mfn(xs->vga_vram + i * PAGE_SIZE);
    for (i = 0; i < n; i++)
        mfns[n + i] = virtual_to_mfn(xs->nonshared_vram + i * PAGE_SIZE);

    fb_dev = init_fbfront(fb_path, mfns, ds->width, ds->height, ds->depth, ds->linesize, 2 * n);
    free(mfns);
    if (!fb_dev) {
        fprintf(stderr,"can't open frame buffer\n");
        exit(1);
    }
    free(fb_path);

    if (ds->shared_buf) {
        offset = (void*) ds->data - xs->vga_vram;
    } else {
        offset = VGA_RAM_SIZE;
        ds->data = xs->nonshared_vram;
    }
    if (offset)
        fbfront_resize(fb_dev, ds->width, ds->height, ds->linesize, ds->depth, offset);

    down(&xs->kbd_sem);
    free(kbd_path);

    kbd_fd = kbdfront_open(xs->kbd_dev);
    qemu_set_fd_handler(kbd_fd, xenfb_kbd_handler, NULL, xs);

    fb_fd = fbfront_open(fb_dev);
    qemu_set_fd_handler(fb_fd, xenfb_fb_handler, NULL, xs);

    xs->fb_dev = fb_dev;
    return 0;
}
#endif

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
