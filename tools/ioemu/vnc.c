/*
 * QEMU VNC display driver
 * 
 * Copyright (C) 2006 Anthony Liguori <anthony@codemonkey.ws>
 * Copyright (C) 2006 Fabrice Bellard
 * Copyright (C) 2006 Christian Limpach <Christian.Limpach@xensource.com>
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
#include "qemu_socket.h"
#include <assert.h>

/* The refresh interval starts at BASE.  If we scan the buffer and
   find no change, we increase by INC, up to MAX.  If the mouse moves
   or we get a keypress, the interval is set back to BASE.  If we find
   an update, halve the interval.

   All times in milliseconds. */
#define VNC_REFRESH_INTERVAL_BASE 30
#define VNC_REFRESH_INTERVAL_INC  50
#define VNC_REFRESH_INTERVAL_MAX  2000

/* Wait at most one second between updates, so that we can detect a
   minimised vncviewer reasonably quickly. */
#define VNC_MAX_UPDATE_INTERVAL   5000

#include "vnc_keysym.h"
#include "keymaps.c"
#include "d3des.h"

#define XK_MISCELLANY
#define XK_LATIN1
#include <X11/keysymdef.h>

typedef struct Buffer
{
    size_t capacity;
    size_t offset;
    uint8_t *buffer;
} Buffer;

typedef struct VncState VncState;

typedef int VncReadEvent(VncState *vs, uint8_t *data, size_t len);

typedef void VncWritePixels(VncState *vs, void *data, int size);

typedef void VncSendHextileTile(VncState *vs,
                                int x, int y, int w, int h,
                                uint32_t *last_bg, 
                                uint32_t *last_fg,
                                int *has_bg, int *has_fg);

#if 0
#define VNC_MAX_WIDTH 2048
#define VNC_MAX_HEIGHT 2048
#define VNC_DIRTY_WORDS (VNC_MAX_WIDTH / (16 * 32))
#endif

struct VncState
{
    QEMUTimer *timer;
    int timer_interval;
    int64_t last_update_time;
    int lsock;
    int csock;
    DisplayState *ds;
    int width;
    int height;
    uint64_t *dirty_row;	/* screen regions which are possibly dirty */
    int dirty_pixel_shift;
    uint64_t *update_row;	/* outstanding updates */
    int has_update;		/* there's outstanding updates in the
				 * visible area */
    uint8_t *old_data;
    int depth; /* internal VNC frame buffer byte per pixel */
    int has_resize;
    int has_hextile;
    Buffer output;
    Buffer input;
    kbd_layout_t *kbd_layout;
    /* current output mode information */
    VncWritePixels *write_pixels;
    VncSendHextileTile *send_hextile_tile;
    int pix_bpp, pix_big_endian;
    int red_shift, red_max, red_shift1;
    int green_shift, green_max, green_shift1;
    int blue_shift, blue_max, blue_shift1;

    VncReadEvent *read_handler;
    size_t read_handler_expect;

    int visible_x;
    int visible_y;
    int visible_w;
    int visible_h;

    int ctl_keys;               /* Ctrl+Alt starts calibration */
    int shift_keys;             /* Shift / CapsLock keys */
    int numlock;
};

#define DIRTY_PIXEL_BITS 64
#define X2DP_DOWN(vs, x) ((x) >> (vs)->dirty_pixel_shift)
#define X2DP_UP(vs, x) \
  (((x) + (1ULL << (vs)->dirty_pixel_shift) - 1) >> (vs)->dirty_pixel_shift)
#define DP2X(vs, x) ((x) << (vs)->dirty_pixel_shift)

/* TODO
   1) Get the queue working for IO.
   2) there is some weirdness when using the -S option (the screen is grey
      and not totally invalidated
*/

static void vnc_write(VncState *vs, const void *data, size_t len);
static void vnc_write_u32(VncState *vs, uint32_t value);
static void vnc_write_s32(VncState *vs, int32_t value);
static void vnc_write_u16(VncState *vs, uint16_t value);
static void vnc_write_u8(VncState *vs, uint8_t value);
static void vnc_flush(VncState *vs);
static void _vnc_update_client(void *opaque);
static void vnc_update_client(void *opaque);
static void vnc_client_read(void *opaque);
static void framebuffer_set_updated(VncState *vs, int x, int y, int w, int h);
static int make_challenge(unsigned char *random, int size);
static void set_seed(unsigned int *seedp);
static void get_random(int len, unsigned char *buf);

#if 0
static inline void vnc_set_bit(uint32_t *d, int k)
{
    d[k >> 5] |= 1 << (k & 0x1f);
}

static inline void vnc_clear_bit(uint32_t *d, int k)
{
    d[k >> 5] &= ~(1 << (k & 0x1f));
}

static inline void vnc_set_bits(uint32_t *d, int n, int nb_words)
{
    int j;

    j = 0;
    while (n >= 32) {
        d[j++] = -1;
        n -= 32;
    }
    if (n > 0) 
        d[j++] = (1 << n) - 1;
    while (j < nb_words)
        d[j++] = 0;
}

static inline int vnc_get_bit(const uint32_t *d, int k)
{
    return (d[k >> 5] >> (k & 0x1f)) & 1;
}

static inline int vnc_and_bits(const uint32_t *d1, const uint32_t *d2, 
                               int nb_words)
{
    int i;
    for(i = 0; i < nb_words; i++) {
        if ((d1[i] & d2[i]) != 0)
            return 1;
    }
    return 0;
}
#endif

static void set_bits_in_row(VncState *vs, uint64_t *row,
			    int x, int y, int w, int h)
{
    int x1, x2;
    uint64_t mask;

    if (w == 0)
	return;

    x1 = X2DP_DOWN(vs, x);
    x2 = X2DP_UP(vs, x + w);

    if (X2DP_UP(vs, w) != DIRTY_PIXEL_BITS)
	mask = ((1ULL << (x2 - x1)) - 1) << x1;
    else
	mask = ~(0ULL);

    h += y;
    if (h > vs->ds->height)
        h = vs->ds->height;
    for (; y < h; y++)
	row[y] |= mask;
}

static void vnc_dpy_update(DisplayState *ds, int x, int y, int w, int h)
{
    VncState *vs = ds->opaque;

    set_bits_in_row(vs, vs->dirty_row, x, y, w, h);
}

static void vnc_framebuffer_update(VncState *vs, int x, int y, int w, int h,
				   int32_t encoding)
{
    vnc_write_u16(vs, x);
    vnc_write_u16(vs, y);
    vnc_write_u16(vs, w);
    vnc_write_u16(vs, h);

    vnc_write_s32(vs, encoding);
}

static void vnc_dpy_resize(DisplayState *ds, int w, int h)
{
    VncState *vs = ds->opaque;
    int o;

    ds->data = realloc(ds->data, w * h * vs->depth);
    vs->old_data = realloc(vs->old_data, w * h * vs->depth);
    vs->dirty_row = realloc(vs->dirty_row, h * sizeof(vs->dirty_row[0]));
    vs->update_row = realloc(vs->update_row, h * sizeof(vs->dirty_row[0]));

    if (ds->data == NULL || vs->old_data == NULL ||
	vs->dirty_row == NULL || vs->update_row == NULL) {
	fprintf(stderr, "vnc: memory allocation failed\n");
	exit(1);
    }

    if (ds->depth != vs->depth * 8) {
        ds->depth = vs->depth * 8;
        set_color_table(ds);
    }
    ds->width = w;
    ds->height = h;
    ds->linesize = w * vs->depth;
    if (vs->csock != -1 && vs->has_resize) {
	vnc_write_u8(vs, 0);  /* msg id */
	vnc_write_u8(vs, 0);
	vnc_write_u16(vs, 1); /* number of rects */
	vnc_framebuffer_update(vs, 0, 0, ds->width, ds->height, -223);
	vnc_flush(vs);
	vs->width = ds->width;
	vs->height = ds->height;
    }
    vs->dirty_pixel_shift = 0;
    for (o = DIRTY_PIXEL_BITS; o < ds->width; o *= 2)
	vs->dirty_pixel_shift++;
    framebuffer_set_updated(vs, 0, 0, ds->width, ds->height);
}

/* fastest code */
static void vnc_write_pixels_copy(VncState *vs, void *pixels, int size)
{
    vnc_write(vs, pixels, size);
}

/* slowest but generic code. */
static void vnc_convert_pixel(VncState *vs, uint8_t *buf, uint32_t v)
{
    unsigned int r, g, b;

    r = (v >> vs->red_shift1) & vs->red_max;
    g = (v >> vs->green_shift1) & vs->green_max;
    b = (v >> vs->blue_shift1) & vs->blue_max;
    v = (r << vs->red_shift) | 
        (g << vs->green_shift) | 
        (b << vs->blue_shift);
    switch(vs->pix_bpp) {
    case 1:
        buf[0] = v;
        break;
    case 2:
        if (vs->pix_big_endian) {
            buf[0] = v >> 8;
            buf[1] = v;
        } else {
            buf[1] = v >> 8;
            buf[0] = v;
        }
        break;
    default:
    case 4:
        if (vs->pix_big_endian) {
            buf[0] = v >> 24;
            buf[1] = v >> 16;
            buf[2] = v >> 8;
            buf[3] = v;
        } else {
            buf[3] = v >> 24;
            buf[2] = v >> 16;
            buf[1] = v >> 8;
            buf[0] = v;
        }
        break;
    }
}

static void vnc_write_pixels_generic(VncState *vs, void *pixels1, int size)
{
    uint32_t *pixels = pixels1;
    uint8_t buf[4];
    int n, i;

    n = size >> 2;
    for(i = 0; i < n; i++) {
        vnc_convert_pixel(vs, buf, pixels[i]);
        vnc_write(vs, buf, vs->pix_bpp);
    }
}

static void send_framebuffer_update_raw(VncState *vs, int x, int y, int w, int h)
{
    int i;
    uint8_t *row;

    vnc_framebuffer_update(vs, x, y, w, h, 0);

    row = vs->ds->data + y * vs->ds->linesize + x * vs->depth;
    for (i = 0; i < h; i++) {
	vs->write_pixels(vs, row, w * vs->depth);
	row += vs->ds->linesize;
    }
}

static void hextile_enc_cord(uint8_t *ptr, int x, int y, int w, int h)
{
    ptr[0] = ((x & 0x0F) << 4) | (y & 0x0F);
    ptr[1] = (((w - 1) & 0x0F) << 4) | ((h - 1) & 0x0F);
}

#define BPP 8
#include "vnchextile.h"
#undef BPP

#define BPP 16
#include "vnchextile.h"
#undef BPP

#define BPP 32
#include "vnchextile.h"
#undef BPP

#define GENERIC
#define BPP 32
#include "vnchextile.h"
#undef BPP
#undef GENERIC

static void send_framebuffer_update_hextile(VncState *vs, int x, int y, int w, int h)
{
    int i, j;
    int has_fg, has_bg;
    uint32_t last_fg32, last_bg32;

    vnc_framebuffer_update(vs, x, y, w, h, 5);

    has_fg = has_bg = 0;
    for (j = y; j < (y + h); j += 16) {
	for (i = x; i < (x + w); i += 16) {
            vs->send_hextile_tile(vs, i, j, 
                                  MIN(16, x + w - i), MIN(16, y + h - j),
                                  &last_bg32, &last_fg32, &has_bg, &has_fg);
	}
    }
}

static void send_framebuffer_update(VncState *vs, int x, int y, int w, int h)
{
	if (vs->has_hextile)
	    send_framebuffer_update_hextile(vs, x, y, w, h);
	else
	    send_framebuffer_update_raw(vs, x, y, w, h);
}

static void vnc_copy(DisplayState *ds, int src_x, int src_y, int dst_x, int dst_y, int w, int h)
{
    int src, dst;
    uint8_t *src_row;
    uint8_t *dst_row;
    uint8_t *old_row;
    int y = 0;
    int pitch = ds->linesize;
    VncState *vs = ds->opaque;
    int updating_client = 1;

    if (src_x < vs->visible_x || src_y < vs->visible_y ||
	dst_x < vs->visible_x || dst_y < vs->visible_y ||
	(src_x + w) > (vs->visible_x + vs->visible_w) ||
	(src_y + h) > (vs->visible_y + vs->visible_h) ||
	(dst_x + w) > (vs->visible_x + vs->visible_w) ||
	(dst_y + h) > (vs->visible_y + vs->visible_h))
	updating_client = 0;

    if (updating_client)
	_vnc_update_client(vs);

    if (dst_y > src_y) {
	y = h - 1;
	pitch = -pitch;
    }

    src = (ds->linesize * (src_y + y) + vs->depth * src_x);
    dst = (ds->linesize * (dst_y + y) + vs->depth * dst_x);

    src_row = ds->data + src;
    dst_row = ds->data + dst;
    old_row = vs->old_data + dst;

    for (y = 0; y < h; y++) {
	memmove(old_row, src_row, w * vs->depth);
	memmove(dst_row, src_row, w * vs->depth);
	src_row += pitch;
	dst_row += pitch;
	old_row += pitch;
    }

    if (updating_client && vs->csock != -1 && !vs->has_update) {
	vnc_write_u8(vs, 0);  /* msg id */
	vnc_write_u8(vs, 0);
	vnc_write_u16(vs, 1); /* number of rects */
	vnc_framebuffer_update(vs, dst_x, dst_y, w, h, 1);
	vnc_write_u16(vs, src_x);
	vnc_write_u16(vs, src_y);
	vnc_flush(vs);
    } else
	framebuffer_set_updated(vs, dst_x, dst_y, w, h);
}

static int find_update_height(VncState *vs, int y, int maxy, int last_x, int x)
{
    int h;

    for (h = 1; y + h < maxy; h++) {
	int tmp_x;
	if (!(vs->update_row[y + h] & (1ULL << last_x)))
	    break;
	for (tmp_x = last_x; tmp_x < x; tmp_x++)
	    vs->update_row[y + h] &= ~(1ULL << tmp_x);
    }

    return h;
}

static void _vnc_update_client(void *opaque)
{
    VncState *vs = opaque;
    int64_t now;
    int y;
    uint8_t *row;
    uint8_t *old_row;
    uint64_t width_mask;
    int n_rectangles;
    int saved_offset;
    int maxx, maxy;
    int tile_bytes = vs->depth * DP2X(vs, 1);

    if (vs->csock == -1)
	return;

    now = qemu_get_clock(rt_clock);

    if (vs->width != DP2X(vs, DIRTY_PIXEL_BITS))
	width_mask = (1ULL << X2DP_UP(vs, vs->ds->width)) - 1;
    else
	width_mask = ~(0ULL);

    /* Walk through the dirty map and eliminate tiles that really
       aren't dirty */
    row = vs->ds->data;
    old_row = vs->old_data;

    for (y = 0; y < vs->ds->height; y++) {
	if (vs->dirty_row[y] & width_mask) {
	    int x;
	    uint8_t *ptr, *old_ptr;

	    ptr = row;
	    old_ptr = old_row;

	    for (x = 0; x < X2DP_UP(vs, vs->ds->width); x++) {
		if (vs->dirty_row[y] & (1ULL << x)) {
		    if (memcmp(old_ptr, ptr, tile_bytes)) {
			vs->has_update = 1;
			vs->update_row[y] |= (1ULL << x);
			memcpy(old_ptr, ptr, tile_bytes);
		    }
		    vs->dirty_row[y] &= ~(1ULL << x);
		}

		ptr += tile_bytes;
		old_ptr += tile_bytes;
	    }
	}
  
	row += vs->ds->linesize;
	old_row += vs->ds->linesize;
    }

    if (!vs->has_update || vs->visible_y >= vs->ds->height ||
	vs->visible_x >= vs->ds->width)
	goto backoff;

    /* Count rectangles */
    n_rectangles = 0;
    vnc_write_u8(vs, 0);  /* msg id */
    vnc_write_u8(vs, 0);
    saved_offset = vs->output.offset;
    vnc_write_u16(vs, 0);
    
    maxy = vs->visible_y + vs->visible_h;
    if (maxy > vs->ds->height)
	maxy = vs->ds->height;
    maxx = vs->visible_x + vs->visible_w;
    if (maxx > vs->ds->width)
	maxx = vs->ds->width;

    for (y = vs->visible_y; y < maxy; y++) {
	int x;
	int last_x = -1;
	for (x = X2DP_DOWN(vs, vs->visible_x);
	     x < X2DP_UP(vs, maxx); x++) {
	    if (vs->update_row[y] & (1ULL << x)) {
		if (last_x == -1)
		    last_x = x;
		vs->update_row[y] &= ~(1ULL << x);
	    } else {
		if (last_x != -1) {
		    int h = find_update_height(vs, y, maxy, last_x, x);
		    if (h != 0) {
			send_framebuffer_update(vs, DP2X(vs, last_x), y,
						DP2X(vs, (x - last_x)), h);
			n_rectangles++;
		    }
		}
		last_x = -1;
	    }
	}
	if (last_x != -1) {
	    int h = find_update_height(vs, y, maxy, last_x, x);
	    if (h != 0) {
		send_framebuffer_update(vs, DP2X(vs, last_x), y,
					DP2X(vs, (x - last_x)), h);
		n_rectangles++;
	    }
	}
    }
    vs->output.buffer[saved_offset] = (n_rectangles >> 8) & 0xFF;
    vs->output.buffer[saved_offset + 1] = n_rectangles & 0xFF;

    if (n_rectangles == 0)
	goto backoff;

    vs->has_update = 0;
    vnc_flush(vs);
    vs->last_update_time = now;

    vs->timer_interval /= 2;
    if (vs->timer_interval < VNC_REFRESH_INTERVAL_BASE)
	vs->timer_interval = VNC_REFRESH_INTERVAL_BASE;

    return;

 backoff:
    /* No update -> back off a bit */
    vs->timer_interval += VNC_REFRESH_INTERVAL_INC;
    if (vs->timer_interval > VNC_REFRESH_INTERVAL_MAX) {
	vs->timer_interval = VNC_REFRESH_INTERVAL_MAX;
	if (now - vs->last_update_time >= VNC_MAX_UPDATE_INTERVAL) {
	    /* Send a null update.  If the client is no longer
	       interested (e.g. minimised) it'll ignore this, and we
	       can stop scanning the buffer until it sends another
	       update request. */
	    /* It turns out that there's a bug in realvncviewer 4.1.2
	       which means that if you send a proper null update (with
	       no update rectangles), it gets a bit out of sync and
	       never sends any further requests, regardless of whether
	       it needs one or not.  Fix this by sending a single 1x1
	       update rectangle instead. */
	    vnc_write_u8(vs, 0);
	    vnc_write_u8(vs, 0);
	    vnc_write_u16(vs, 1);
	    send_framebuffer_update(vs, 0, 0, 1, 1);
	    vnc_flush(vs);
	    vs->last_update_time = now;
	    return;
	}
    }
    qemu_mod_timer(vs->timer, now + vs->timer_interval);
    return;
}

static void vnc_update_client(void *opaque)
{
    VncState *vs = opaque;

    vs->ds->dpy_refresh(vs->ds);
    _vnc_update_client(vs);
}

static void vnc_timer_init(VncState *vs)
{
    if (vs->timer == NULL) {
	vs->timer = qemu_new_timer(rt_clock, vnc_update_client, vs);
	vs->timer_interval = VNC_REFRESH_INTERVAL_BASE;
    }
}

static void vnc_dpy_refresh(DisplayState *ds)
{
    vga_hw_update();
}

static int vnc_listen_poll(void *opaque)
{
    VncState *vs = opaque;
    if (vs->csock == -1)
	return 1;
    return 0;
}

static void buffer_reserve(Buffer *buffer, size_t len)
{
    if ((buffer->capacity - buffer->offset) < len) {
	buffer->capacity += (len + 1024);
	buffer->buffer = realloc(buffer->buffer, buffer->capacity);
	if (buffer->buffer == NULL) {
	    fprintf(stderr, "vnc: out of memory\n");
	    exit(1);
	}
    }
}

static int buffer_empty(Buffer *buffer)
{
    return buffer->offset == 0;
}

static uint8_t *buffer_end(Buffer *buffer)
{
    return buffer->buffer + buffer->offset;
}

static void buffer_reset(Buffer *buffer)
{
    buffer->offset = 0;
}

static void buffer_append(Buffer *buffer, const void *data, size_t len)
{
    memcpy(buffer->buffer + buffer->offset, data, len);
    buffer->offset += len;
}

static int vnc_client_io_error(VncState *vs, int ret, int last_errno)
{
    if (ret == 0 || ret == -1) {
	if (ret == -1 && (last_errno == EINTR || last_errno == EAGAIN))
	    return 0;

	qemu_set_fd_handler2(vs->csock, NULL, NULL, NULL, NULL);
	closesocket(vs->csock);
	vs->csock = -1;
	buffer_reset(&vs->input);
	buffer_reset(&vs->output);
	return 0;
    }
    return ret;
}

static void vnc_client_error(VncState *vs)
{
    vnc_client_io_error(vs, -1, EINVAL);
}

static void vnc_client_write(void *opaque)
{
    long ret;
    VncState *vs = opaque;

    ret = send(vs->csock, vs->output.buffer, vs->output.offset, 0);
    ret = vnc_client_io_error(vs, ret, socket_error());
    if (!ret)
	return;

    memmove(vs->output.buffer, vs->output.buffer + ret,
	    vs->output.offset - ret);
    vs->output.offset -= ret;

    if (vs->output.offset == 0)
	qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, NULL, vs);
}

static void vnc_read_when(VncState *vs, VncReadEvent *func, size_t expecting)
{
    vs->read_handler = func;
    vs->read_handler_expect = expecting;
}

static void vnc_client_read(void *opaque)
{
    VncState *vs = opaque;
    long ret;

    buffer_reserve(&vs->input, 4096);

    ret = recv(vs->csock, buffer_end(&vs->input), 4096, 0);
    ret = vnc_client_io_error(vs, ret, socket_error());
    if (!ret)
	return;

    vs->input.offset += ret;

    while (vs->read_handler && vs->input.offset >= vs->read_handler_expect) {
	size_t len = vs->read_handler_expect;
	int ret;

	ret = vs->read_handler(vs, vs->input.buffer, len);
	if (vs->csock == -1)
	    return;

	if (!ret) {
	    memmove(vs->input.buffer, vs->input.buffer + len,
		    vs->input.offset - len);
	    vs->input.offset -= len;
	} else {
	    assert(ret > vs->read_handler_expect);
	    vs->read_handler_expect = ret;
	}
    }
}

static void vnc_write(VncState *vs, const void *data, size_t len)
{
    buffer_reserve(&vs->output, len);

    if (buffer_empty(&vs->output))
	qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read,
			     vnc_client_write, vs);

    buffer_append(&vs->output, data, len);
}

static void vnc_write_s32(VncState *vs, int32_t value)
{
    vnc_write_u32(vs, *(uint32_t *)&value);
}

static void vnc_write_u32(VncState *vs, uint32_t value)
{
    uint8_t buf[4];

    buf[0] = (value >> 24) & 0xFF;
    buf[1] = (value >> 16) & 0xFF;
    buf[2] = (value >>  8) & 0xFF;
    buf[3] = value & 0xFF;

    vnc_write(vs, buf, 4);
}

static void vnc_write_u16(VncState *vs, uint16_t value)
{
    uint8_t buf[2];

    buf[0] = (value >> 8) & 0xFF;
    buf[1] = value & 0xFF;

    vnc_write(vs, buf, 2);
}

static void vnc_write_u8(VncState *vs, uint8_t value)
{
    vnc_write(vs, &value, 1);
}

static void vnc_flush(VncState *vs)
{
    if (vs->output.offset)
	vnc_client_write(vs);
}

static uint8_t read_u8(uint8_t *data, size_t offset)
{
    return data[offset];
}

static uint16_t read_u16(uint8_t *data, size_t offset)
{
    return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
}

static int32_t read_s32(uint8_t *data, size_t offset)
{
    return (int32_t)((data[offset] << 24) | (data[offset + 1] << 16) |
		     (data[offset + 2] << 8) | data[offset + 3]);
}

static uint32_t read_u32(uint8_t *data, size_t offset)
{
    return ((data[offset] << 24) | (data[offset + 1] << 16) |
	    (data[offset + 2] << 8) | data[offset + 3]);
}

static void client_cut_text(VncState *vs, size_t len, char *text)
{
}

static void pointer_event(VncState *vs, int button_mask, int x, int y)
{
    int buttons = 0;
    int dz = 0;

    if (button_mask & 0x01)
	buttons |= MOUSE_EVENT_LBUTTON;
    if (button_mask & 0x02)
	buttons |= MOUSE_EVENT_MBUTTON;
    if (button_mask & 0x04)
	buttons |= MOUSE_EVENT_RBUTTON;
    if (button_mask & 0x08)
	dz = -1;
    if (button_mask & 0x10)
	dz = 1;
	    
    if (kbd_mouse_is_absolute()) {
	kbd_mouse_event(x * 0x7FFF / vs->ds->width,
			y * 0x7FFF / vs->ds->height,
			dz, buttons);
    } else {
	static int last_x = -1;
	static int last_y = -1;

	if (last_x != -1)
	    kbd_mouse_event(x - last_x, y - last_y, dz, buttons);

	last_x = x;
	last_y = y;
    }
}

static void press_key(VncState *vs, int keycode)
{
    kbd_put_keycode(keysym2scancode(vs->kbd_layout, keycode) & 0x7f);
    kbd_put_keycode(keysym2scancode(vs->kbd_layout, keycode) | 0x80);
}

static void do_key_event(VncState *vs, int down, uint32_t sym)
{
    sym &= 0xFFFF;

    if (is_graphic_console()) {
	int keycode;
	int numlock;

	keycode = keysym2scancode(vs->kbd_layout, sym);
	numlock = keysym2numlock(vs->kbd_layout, sym);

        /* If the numlock state needs to change then simulate an additional
           keypress before sending this one.  This will happen if the user
           toggles numlock away from the VNC window.
        */
	if (numlock == 1) {
	    if (!vs->numlock) {
		vs->numlock = 1;
		press_key(vs, XK_Num_Lock);
	    }
	}
	else if (numlock == -1) {
	    if (vs->numlock) {
		vs->numlock = 0;
		press_key(vs, XK_Num_Lock);
	    }
        }

	if (keycode & 0x80)
	    kbd_put_keycode(0xe0);
	if (down)
	    kbd_put_keycode(keycode & 0x7f);
	else
	    kbd_put_keycode(keycode | 0x80);
    } else if (down) {
	int qemu_keysym = 0;

	if (sym <= 128) { /* normal ascii */
	    int shifted = vs->shift_keys == 1 || vs->shift_keys == 2;
	    qemu_keysym = sym;
	    if (sym >= 'a' && sym <= 'z' && shifted)
	        qemu_keysym -= 'a' - 'A';
	} else {
	    switch (sym) {
	    case XK_Up: qemu_keysym = QEMU_KEY_UP; break;
	    case XK_Down: qemu_keysym = QEMU_KEY_DOWN; break;
	    case XK_Left: qemu_keysym = QEMU_KEY_LEFT; break;
	    case XK_Right: qemu_keysym = QEMU_KEY_RIGHT; break;
	    case XK_Home: qemu_keysym = QEMU_KEY_HOME; break;
	    case XK_End: qemu_keysym = QEMU_KEY_END; break;
	    case XK_Page_Up: qemu_keysym = QEMU_KEY_PAGEUP; break;
	    case XK_Page_Down: qemu_keysym = QEMU_KEY_PAGEDOWN; break;
	    case XK_BackSpace: qemu_keysym = QEMU_KEY_BACKSPACE; break;
	    case XK_Delete: qemu_keysym = QEMU_KEY_DELETE; break;
	    case XK_Return:
	    case XK_Linefeed: qemu_keysym = sym; break;
	    default: break;
	    }
	}
	if (qemu_keysym != 0)
	    kbd_put_keysym(qemu_keysym);
    }

    if (down) {
	switch (sym) {
	case XK_Control_L:
	    vs->ctl_keys |= 1;
	    break;

	case XK_Alt_L:
	    vs->ctl_keys |= 2;
	    break;

	case XK_Shift_L:
	    vs->shift_keys |= 1;
	    break;

	default:
	    break;
	}
    } else {
	switch (sym) {
	case XK_Control_L:
	    vs->ctl_keys &= ~1;
	    break;

	case XK_Alt_L:
	    vs->ctl_keys &= ~2;
	    break;

	case XK_Shift_L:
	    vs->shift_keys &= ~1;
	    break;

	case XK_Caps_Lock:
	    vs->shift_keys ^= 2;
	    break;

	case XK_Num_Lock:
	    vs->numlock = !vs->numlock;
	    break;

	case XK_1 ... XK_9:
	    if ((vs->ctl_keys & 3) != 3)
		break;

	    console_select(sym - XK_1);
	    if (is_graphic_console()) {
		/* tell the vga console to redisplay itself */
		vga_hw_invalidate();
		vnc_dpy_update(vs->ds, 0, 0, vs->ds->width, vs->ds->height);
	    }
	    break;
	}
    }
}

static void key_event(VncState *vs, int down, uint32_t sym)
{
    if (sym >= 'A' && sym <= 'Z')
	sym = sym - 'A' + 'a';
    do_key_event(vs, down, sym);
}

static void framebuffer_set_updated(VncState *vs, int x, int y, int w, int h)
{

    set_bits_in_row(vs, vs->update_row, x, y, w, h);

    vs->has_update = 1;
}

static void framebuffer_update_request(VncState *vs, int incremental,
				       int x_position, int y_position,
				       int w, int h)
{
    if (!incremental)
	framebuffer_set_updated(vs, x_position, y_position, w, h);
    vs->visible_x = x_position;
    vs->visible_y = y_position;
    vs->visible_w = w;
    vs->visible_h = h;

    qemu_mod_timer(vs->timer, qemu_get_clock(rt_clock));
}

static void set_encodings(VncState *vs, int32_t *encodings, size_t n_encodings)
{
    int i;

    vs->has_hextile = 0;
    vs->has_resize = 0;
    vs->ds->dpy_copy = NULL;

    for (i = n_encodings - 1; i >= 0; i--) {
	switch (encodings[i]) {
	case 0: /* Raw */
	    vs->has_hextile = 0;
	    break;
	case 1: /* CopyRect */
	    vs->ds->dpy_copy = vnc_copy;
	    break;
	case 5: /* Hextile */
	    vs->has_hextile = 1;
	    break;
	case -223: /* DesktopResize */
	    vs->has_resize = 1;
	    break;
	default:
	    break;
	}
    }
}

static int compute_nbits(unsigned int val)
{
    int n;
    n = 0;
    while (val != 0) {
        n++;
        val >>= 1;
    }
    return n;
}

static void set_pixel_format(VncState *vs,
			     int bits_per_pixel, int depth,
			     int big_endian_flag, int true_color_flag,
			     int red_max, int green_max, int blue_max,
			     int red_shift, int green_shift, int blue_shift)
{
    int host_big_endian_flag;

#ifdef WORDS_BIGENDIAN
    host_big_endian_flag = 1;
#else
    host_big_endian_flag = 0;
#endif
    if (!true_color_flag) {
    fail:
	vnc_client_error(vs);
        return;
    }
    if (bits_per_pixel == 32 && 
        host_big_endian_flag == big_endian_flag &&
        red_max == 0xff && green_max == 0xff && blue_max == 0xff &&
        red_shift == 16 && green_shift == 8 && blue_shift == 0) {
        vs->depth = 4;
        vs->write_pixels = vnc_write_pixels_copy;
        vs->send_hextile_tile = send_hextile_tile_32;
    } else 
    if (bits_per_pixel == 16 && 
        host_big_endian_flag == big_endian_flag &&
        red_max == 31 && green_max == 63 && blue_max == 31 &&
        red_shift == 11 && green_shift == 5 && blue_shift == 0) {
        vs->depth = 2;
        vs->write_pixels = vnc_write_pixels_copy;
        vs->send_hextile_tile = send_hextile_tile_16;
    } else 
    if (bits_per_pixel == 8 && 
        red_max == 7 && green_max == 7 && blue_max == 3 &&
        red_shift == 5 && green_shift == 2 && blue_shift == 0) {
        vs->depth = 1;
        vs->write_pixels = vnc_write_pixels_copy;
        vs->send_hextile_tile = send_hextile_tile_8;
    } else 
    {
        /* generic and slower case */
        if (bits_per_pixel != 8 &&
            bits_per_pixel != 16 &&
            bits_per_pixel != 32)
            goto fail;
        vs->depth = 4;
        vs->red_shift = red_shift;
        vs->red_max = red_max;
        vs->red_shift1 = 24 - compute_nbits(red_max);
        vs->green_shift = green_shift;
        vs->green_max = green_max;
        vs->green_shift1 = 16 - compute_nbits(green_max);
        vs->blue_shift = blue_shift;
        vs->blue_max = blue_max;
        vs->blue_shift1 = 8 - compute_nbits(blue_max);
        vs->pix_bpp = bits_per_pixel / 8;
        vs->pix_big_endian = big_endian_flag;
        vs->write_pixels = vnc_write_pixels_generic;
        vs->send_hextile_tile = send_hextile_tile_generic;
    }

    vnc_dpy_resize(vs->ds, vs->ds->width, vs->ds->height);

    vga_hw_invalidate();
    vga_hw_update();
}

static int protocol_client_msg(VncState *vs, uint8_t *data, size_t len)
{
    int i;
    uint16_t limit;

    switch (data[0]) {
    case 0:
	if (len == 1)
	    return 20;

	set_pixel_format(vs, read_u8(data, 4), read_u8(data, 5),
			 read_u8(data, 6), read_u8(data, 7),
			 read_u16(data, 8), read_u16(data, 10),
			 read_u16(data, 12), read_u8(data, 14),
			 read_u8(data, 15), read_u8(data, 16));
	break;
    case 2:
	if (len == 1)
	    return 4;

	if (len == 4) {
	    uint16_t v;
	    v = read_u16(data, 2);
	    if (v)
		return 4 + v * 4;
	}

	limit = read_u16(data, 2);
	for (i = 0; i < limit; i++) {
	    int32_t val = read_s32(data, 4 + (i * 4));
	    memcpy(data + 4 + (i * 4), &val, sizeof(val));
	}

	set_encodings(vs, (int32_t *)(data + 4), limit);
	break;
    case 3:
	if (len == 1)
	    return 10;

	framebuffer_update_request(vs,
				   read_u8(data, 1), read_u16(data, 2), read_u16(data, 4),
				   read_u16(data, 6), read_u16(data, 8));
	break;
    case 4:
	if (len == 1)
	    return 8;

	vs->timer_interval = VNC_REFRESH_INTERVAL_BASE;
	qemu_advance_timer(vs->timer,
			   qemu_get_clock(rt_clock) + vs->timer_interval);
	key_event(vs, read_u8(data, 1), read_u32(data, 4));
	break;
    case 5:
	if (len == 1)
	    return 6;

	vs->timer_interval = VNC_REFRESH_INTERVAL_BASE;
	qemu_advance_timer(vs->timer,
			   qemu_get_clock(rt_clock) + vs->timer_interval);
	pointer_event(vs, read_u8(data, 1), read_u16(data, 2), read_u16(data, 4));
	break;
    case 6:
	if (len == 1)
	    return 8;

	if (len == 8) {
	    uint32_t v;
	    v = read_u32(data, 4);
	    if (v)
		return 8 + v;
	}

	client_cut_text(vs, read_u32(data, 4), (char *)(data + 8));
	break;
    default:
	printf("Msg: %d\n", data[0]);
	vnc_client_error(vs);
	break;
    }
	
    vnc_read_when(vs, protocol_client_msg, 1);
    return 0;
}

static int protocol_client_init(VncState *vs, uint8_t *data, size_t len)
{
    size_t l;
    char pad[3] = { 0, 0, 0 };

    vga_hw_update();

    vs->width = vs->ds->width;
    vs->height = vs->ds->height;
    vnc_write_u16(vs, vs->ds->width);
    vnc_write_u16(vs, vs->ds->height);

    vnc_write_u8(vs, vs->depth * 8); /* bits-per-pixel */
    vnc_write_u8(vs, vs->depth * 8); /* depth */
#ifdef WORDS_BIGENDIAN
    vnc_write_u8(vs, 1);             /* big-endian-flag */
#else
    vnc_write_u8(vs, 0);             /* big-endian-flag */
#endif
    vnc_write_u8(vs, 1);             /* true-color-flag */
    if (vs->depth == 4) {
	vnc_write_u16(vs, 0xFF);     /* red-max */
	vnc_write_u16(vs, 0xFF);     /* green-max */
	vnc_write_u16(vs, 0xFF);     /* blue-max */
	vnc_write_u8(vs, 16);        /* red-shift */
	vnc_write_u8(vs, 8);         /* green-shift */
	vnc_write_u8(vs, 0);         /* blue-shift */
        vs->send_hextile_tile = send_hextile_tile_32;
    } else if (vs->depth == 2) {
	vnc_write_u16(vs, 31);       /* red-max */
	vnc_write_u16(vs, 63);       /* green-max */
	vnc_write_u16(vs, 31);       /* blue-max */
	vnc_write_u8(vs, 11);        /* red-shift */
	vnc_write_u8(vs, 5);         /* green-shift */
	vnc_write_u8(vs, 0);         /* blue-shift */
        vs->send_hextile_tile = send_hextile_tile_16;
    } else if (vs->depth == 1) {
        /* XXX: change QEMU pixel 8 bit pixel format to match the VNC one ? */
	vnc_write_u16(vs, 7);        /* red-max */
	vnc_write_u16(vs, 7);        /* green-max */
	vnc_write_u16(vs, 3);        /* blue-max */
	vnc_write_u8(vs, 5);         /* red-shift */
	vnc_write_u8(vs, 2);         /* green-shift */
	vnc_write_u8(vs, 0);         /* blue-shift */
        vs->send_hextile_tile = send_hextile_tile_8;
    }
    vs->write_pixels = vnc_write_pixels_copy;
	
    vnc_write(vs, pad, 3);           /* padding */

    l = strlen(domain_name); 
    vnc_write_u32(vs, l);        
    vnc_write(vs, domain_name, l);

    vnc_flush(vs);

    vnc_read_when(vs, protocol_client_msg, 1);

    return 0;
}

static int protocol_response(VncState *vs, uint8_t *client_response, size_t len)
{
    extern char vncpasswd[64];
    extern unsigned char challenge[AUTHCHALLENGESIZE];
    unsigned char cryptchallenge[AUTHCHALLENGESIZE];
    unsigned char key[8];
    int passwdlen, i, j;

    memcpy(cryptchallenge, challenge, AUTHCHALLENGESIZE);

    /* Calculate the sent challenge */
    passwdlen = strlen(vncpasswd);
    for (i=0; i<8; i++)
	key[i] = i<passwdlen ? vncpasswd[i] : 0;
    deskey(key, EN0);
    for (j = 0; j < AUTHCHALLENGESIZE; j += 8)
	des(cryptchallenge+j, cryptchallenge+j);

    /* Check the actual response */
    if (memcmp(cryptchallenge, client_response, AUTHCHALLENGESIZE) != 0) {
	/* password error */
	vnc_write_u32(vs, 1);
	vnc_write_u32(vs, 22);
	vnc_write(vs, "Authentication failure", 22);
	vnc_flush(vs);
	fprintf(stderr, "VNC Password error.\n");
	vnc_client_error(vs);
	return 0;
    }

    vnc_write_u32(vs, 0);
    vnc_flush(vs);

    vnc_read_when(vs, protocol_client_init, 1);

    return 0;
}

static int protocol_version(VncState *vs, uint8_t *version, size_t len)
{
    extern char vncpasswd[64];
    extern unsigned char challenge[AUTHCHALLENGESIZE];
    char local[13];
    int  support, maj, min;

    memcpy(local, version, 12);
    local[12] = 0;

    /* protocol version check */
    if (sscanf(local, "RFB %03d.%03d\n", &maj, &min) != 2) {
	fprintf(stderr, "Protocol version error.\n");
	vnc_client_error(vs);
	return 0;
    }


    support = 0;
    if (maj == 3) {
	if (min == 3 || min ==4) {
	    support = 1;
	}
    }

    if (! support) {
	fprintf(stderr, "Client uses unsupported protocol version %d.%d.\n",
		maj, min);
	vnc_client_error(vs);
	return 0;
    }

    if (*vncpasswd == '\0') {
	/* AuthType is None */
	vnc_write_u32(vs, 1);
	vnc_flush(vs);
	vnc_read_when(vs, protocol_client_init, 1);
    } else {
	/* AuthType is VncAuth */
	vnc_write_u32(vs, 2);

	/* Challenge-Responce authentication */
	/* Send Challenge */
	make_challenge(challenge, AUTHCHALLENGESIZE);
	vnc_write(vs, challenge, AUTHCHALLENGESIZE);
	vnc_flush(vs);
	vnc_read_when(vs, protocol_response, AUTHCHALLENGESIZE);
    }

    return 0;
}

static void vnc_listen_read(void *opaque)
{
    VncState *vs = opaque;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    vs->csock = accept(vs->lsock, (struct sockaddr *)&addr, &addrlen);
    if (vs->csock != -1) {
        socket_set_nonblock(vs->csock);
	qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, NULL, opaque);
	vnc_write(vs, "RFB 003.003\n", 12);
	vnc_flush(vs);
	vnc_read_when(vs, protocol_version, 12);
	framebuffer_set_updated(vs, 0, 0, vs->ds->width, vs->ds->height);
	vs->has_resize = 0;
	vs->has_hextile = 0;
	vs->ds->dpy_copy = NULL;
	vnc_timer_init(vs);
    }
}

int vnc_display_init(DisplayState *ds, int display, int find_unused, struct sockaddr_in *addr)
{
    int reuse_addr, ret;
    VncState *vs;

    vs = qemu_mallocz(sizeof(VncState));
    if (!vs)
	exit(1);

    ds->opaque = vs;

    vs->lsock = -1;
    vs->csock = -1;
    vs->depth = 4;
    vs->numlock = 0;

    vs->ds = ds;

    if (!keyboard_layout)
	keyboard_layout = "en-us";

    vs->kbd_layout = init_keyboard_layout(keyboard_layout);
    if (!vs->kbd_layout)
	exit(1);

    vs->lsock = socket(PF_INET, SOCK_STREAM, 0);
    if (vs->lsock == -1) {
	fprintf(stderr, "Could not create socket\n");
	exit(1);
    }

    reuse_addr = 1;
    ret = setsockopt(vs->lsock, SOL_SOCKET, SO_REUSEADDR,
		     (const char *)&reuse_addr, sizeof(reuse_addr));
    if (ret == -1) {
	fprintf(stderr, "setsockopt() failed\n");
	exit(1);
    }

 retry:
    addr->sin_family = AF_INET;
    addr->sin_port = htons(5900 + display);

    if (bind(vs->lsock, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == -1) {
	if (find_unused && errno == EADDRINUSE) {
	    display++;
	    goto retry;
	}
	fprintf(stderr, "bind() failed\n");
	exit(1);
    }

    if (listen(vs->lsock, 1) == -1) {
	fprintf(stderr, "listen() failed\n");
	exit(1);
    }

    ret = qemu_set_fd_handler2(vs->lsock, vnc_listen_poll, vnc_listen_read,
			       NULL, vs);
    if (ret == -1)
	exit(1);

    vs->ds->data = NULL;
    vs->ds->dpy_update = vnc_dpy_update;
    vs->ds->dpy_resize = vnc_dpy_resize;
    vs->ds->dpy_refresh = vnc_dpy_refresh;

    vnc_dpy_resize(vs->ds, 640, 400);

    return display;
}

int vnc_start_viewer(int port)
{
    int pid, i, open_max;
    char s[16];

    sprintf(s, ":%d", port);

    switch (pid = fork()) {
    case -1:
	fprintf(stderr, "vncviewer failed fork\n");
	exit(1);

    case 0:	/* child */
	open_max = sysconf(_SC_OPEN_MAX);
	for (i = 0; i < open_max; i++)
	    if (i != STDIN_FILENO &&
		i != STDOUT_FILENO &&
		i != STDERR_FILENO)
		close(i);
	execlp("vncviewer", "vncviewer", s, NULL);
	fprintf(stderr, "vncviewer execlp failed\n");
	exit(1);

    default:
	return pid;
    }
}

unsigned int seed;

static int make_challenge(unsigned char *random, int size)
{
 
    set_seed(&seed);
    get_random(size, random);

    return 0;
}

static void set_seed(unsigned int *seedp)
{
    *seedp += (unsigned int)(time(NULL)+getpid()+getpid()*987654+rand());
    srand(*seedp);

    return;
}

static void get_random(int len, unsigned char *buf)
{
    int i;

    for (i=0; i<len; i++)
	buf[i] = (int) (256.0*rand()/(RAND_MAX+1.0));

    return;
}
