/*
 * QEMU Xen PV Machine
 *
 * Copyright (c) 2007 Red Hat
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "vl.h"
#include "xenfb.h"
#include <linux/input.h>

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

/* A convenient function for munging pixels between different depths */
#define BLT(SRC_T,DST_T,RLS,GLS,BLS,RRS,GRS,BRS,RM,GM,BM)               \
    for (line = y ; line < h ; line++) {                                \
        SRC_T *src = (SRC_T *)(xenfb->pixels                            \
                               + (line * xenfb->row_stride)             \
                               + (x * xenfb->depth / 8));               \
        DST_T *dst = (DST_T *)(ds->data                                 \
                               + (line * ds->linesize)                  \
                               + (x * ds->depth / 8));                  \
        int col;                                                        \
        for (col = x ; col < w ; col++) {                               \
            *dst = (((*src >> RRS) & RM) << RLS) |                      \
                (((*src >> GRS) & GM) << GLS) |                         \
                (((*src >> GRS) & BM) << BLS);                          \
            src++;                                                      \
            dst++;                                                      \
        }                                                               \
    }

/* This copies data from the guest framebuffer region, into QEMU's copy
 * NB. QEMU's copy is stored in the pixel format of a) the local X 
 * server (SDL case) or b) the current VNC client pixel format.
 */
static void xen_pvfb_guest_copy(struct xenfb *xenfb, int x, int y, int w, int h)
{
    DisplayState *ds = (DisplayState *)xenfb->user_data;
    int line;

    if (xenfb->depth == ds->depth) { /* Perfect match can use fast path */
        for (line = y ; line < (y+h) ; line++) {
            memcpy(ds->data + (line * ds->linesize) + (x * ds->depth / 8),
                   xenfb->pixels + (line * xenfb->row_stride) + (x * xenfb->depth / 8),
                   w * xenfb->depth / 8);
        }
    } else { /* Mismatch requires slow pixel munging */
        if (xenfb->depth == 8) {
            /* 8 bit source == r:3 g:3 b:2 */
            if (ds->depth == 16) {
                BLT(uint8_t, uint16_t,   5, 2, 0,   11, 5, 0,   7, 7, 3);
            } else if (ds->depth == 32) {
                BLT(uint8_t, uint32_t,   5, 2, 0,   16, 8, 0,   7, 7, 3);
            }
        } else if (xenfb->depth == 16) {
            /* 16 bit source == r:5 g:6 b:5 */
            if (ds->depth == 8) {
                BLT(uint16_t, uint8_t,    11, 5, 0,   5, 2, 0,    31, 63, 31);
            } else if (ds->depth == 32) {
                BLT(uint16_t, uint32_t,   11, 5, 0,   16, 8, 0,   31, 63, 31);
            }
        } else if (xenfb->depth == 32) {
            /* 32 bit source == r:8 g:8 b:8 (padding:8) */
            if (ds->depth == 8) {
                BLT(uint32_t, uint8_t,    16, 8, 0,   5, 2, 0,    255, 255, 255);
            } else if (ds->depth == 16) {
                BLT(uint32_t, uint16_t,   16, 8, 0,   11, 5, 0,   255, 255, 255);
            }
        }
    }
    dpy_update(ds, x, y, w, h);
}

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
static void xen_pvfb_key_event(void *opaque, int scancode)
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
static void xen_pvfb_mouse_event(void *opaque,
                                 int dx, int dy, int dz, int button_state)
{
    static int old_state = 0;
    int i;
    struct xenfb *xenfb = opaque;
    DisplayState *ds = (DisplayState *)xenfb->user_data;
    if (xenfb->abs_pointer_wanted)
        xenfb_send_position(xenfb,
                            dx * ds->width / 0x7fff,
                            dy * ds->height / 0x7fff);
    else
        xenfb_send_motion(xenfb, dx, dy);

	for (i = 0 ; i < 8 ; i++) {
		int lastDown = old_state & (1 << i);
		int down = button_state & (1 << i);
		if (down == lastDown)
			continue;

		if (xenfb_send_key(xenfb, down, BTN_LEFT+i) < 0)
			return;
	}
    old_state = button_state;
}

/* QEMU display state changed, so refresh the framebuffer copy */
/* XXX - can we optimize this, or the next func at all ? */ 
void xen_pvfb_update(void *opaque)
{
    struct xenfb *xenfb = opaque;
    xen_pvfb_guest_copy(xenfb, 0, 0, xenfb->width, xenfb->height);
}

/* QEMU display state changed, so refresh the framebuffer copy */
void xen_pvfb_invalidate(void *opaque)
{
    xen_pvfb_update(opaque);
}

/* Screen dump is not used in Xen, so no need to impl this ? */
void xen_pvfb_screen_dump(void *opaque, const char *name) { }

void xen_pvfb_dispatch_store(void *opaque) {
    int ret;
    if ((ret = xenfb_dispatch_store(opaque)) < 0) {
        fprintf(stderr, "Failure while dispatching store: %d\n", ret);
        exit(1);
    }
}

void xen_pvfb_dispatch_channel(void *opaque) {
    int ret;
    if ((ret = xenfb_dispatch_channel(opaque)) < 0) {
        fprintf(stderr, "Failure while dispatching store: %d\n", ret);
        exit(1);
    }
}

/* The Xen PV machine currently provides
 *   - a virtual framebuffer
 *   - ....
 */
static void xen_init_pv(uint64_t ram_size, int vga_ram_size, char *boot_device,
			DisplayState *ds, const char **fd_filename,
			int snapshot,
			const char *kernel_filename,
			const char *kernel_cmdline,
			const char *initrd_filename)
{
    struct xenfb *xenfb;
    extern int domid;
    int fd, i;

    /* Prepare scancode mapping table */
	for (i = 0; i < 128; i++) {
		scancode2linux[i] = atkbd_set2_keycode[atkbd_unxlate_table[i]];
		scancode2linux[i | 0x80] = 
			atkbd_set2_keycode[atkbd_unxlate_table[i] | 0x80];
	}

    /* Prepare PVFB state */
    xenfb = xenfb_new();
    if (xenfb == NULL) {
        fprintf(stderr, "Could not create framebuffer (%s)\n",
                strerror(errno));
        exit(1);
    }

    /* Talk to the guest */
    if (xenfb_attach_dom(xenfb, domid) < 0) {
        fprintf(stderr, "Could not connect to domain (%s)\n",
                strerror(errno));
        exit(1);
    }
    xenfb->update = xen_pvfb_guest_copy;
    xenfb->user_data = ds;

    /* Tell QEMU to allocate a graphical console */
    graphic_console_init(ds,
                         xen_pvfb_update,
                         xen_pvfb_invalidate,
                         xen_pvfb_screen_dump,
                         xenfb);

    /* Register our keyboard & mouse handlers */
    qemu_add_kbd_event_handler(xen_pvfb_key_event, xenfb);
    qemu_add_mouse_event_handler(xen_pvfb_mouse_event, xenfb,
                                 xenfb->abs_pointer_wanted,
                                 "Xen PVFB Mouse");

    /* Listen for events from xenstore */
    fd = xenfb_get_store_fd(xenfb);
    if (qemu_set_fd_handler2(fd, NULL, xen_pvfb_dispatch_store, NULL, xenfb) < 0) {
        fprintf(stderr, "Could not register event handler (%s)\n",
                strerror(errno));
    }

    /* Listen for events from the event channel */
    fd = xenfb_get_channel_fd(xenfb);
    if (qemu_set_fd_handler2(fd, NULL, xen_pvfb_dispatch_channel, NULL, xenfb) < 0) {
        fprintf(stderr, "Could not register event handler (%s)\n",
                strerror(errno));
    }

    /* Setup QEMU display */
    dpy_resize(ds, xenfb->width, xenfb->height);
}

QEMUMachine xenpv_machine = {
    "xenpv",
    "Xen Para-virtualized PC",
    xen_init_pv,
};

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
