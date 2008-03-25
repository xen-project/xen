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

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "vl.h"
#include "qemu_socket.h"
#include <assert.h>
#ifdef CONFIG_STUBDOM
#include <netfront.h>
#endif

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

#if CONFIG_VNC_TLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif /* CONFIG_VNC_TLS */

// #define _VNC_DEBUG 1

#if _VNC_DEBUG
#define VNC_DEBUG(fmt, ...) do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)

#if CONFIG_VNC_TLS && _VNC_DEBUG >= 2
/* Very verbose, so only enabled for _VNC_DEBUG >= 2 */
static void vnc_debug_gnutls_log(int level, const char* str) {
    VNC_DEBUG("%d %s", level, str);
}
#endif /* CONFIG_VNC_TLS && _VNC_DEBUG */
#else
#define VNC_DEBUG(fmt, ...) do { } while (0)
#endif


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
                                void *last_bg, 
                                void *last_fg,
                                int *has_bg, int *has_fg);

#if 0
#define VNC_MAX_WIDTH 2048
#define VNC_MAX_HEIGHT 2048
#define VNC_DIRTY_WORDS (VNC_MAX_WIDTH / (16 * 32))
#endif

#define VNC_AUTH_CHALLENGE_SIZE 16

enum {
    VNC_AUTH_INVALID = 0,
    VNC_AUTH_NONE = 1,
    VNC_AUTH_VNC = 2,
    VNC_AUTH_RA2 = 5,
    VNC_AUTH_RA2NE = 6,
    VNC_AUTH_TIGHT = 16,
    VNC_AUTH_ULTRA = 17,
    VNC_AUTH_TLS = 18,
    VNC_AUTH_VENCRYPT = 19
};

#if CONFIG_VNC_TLS
enum {
    VNC_WIREMODE_CLEAR,
    VNC_WIREMODE_TLS,
};

enum {
    VNC_AUTH_VENCRYPT_PLAIN = 256,
    VNC_AUTH_VENCRYPT_TLSNONE = 257,
    VNC_AUTH_VENCRYPT_TLSVNC = 258,
    VNC_AUTH_VENCRYPT_TLSPLAIN = 259,
    VNC_AUTH_VENCRYPT_X509NONE = 260,
    VNC_AUTH_VENCRYPT_X509VNC = 261,
    VNC_AUTH_VENCRYPT_X509PLAIN = 262,
};

#if CONFIG_VNC_TLS
#define X509_CA_CERT_FILE "ca-cert.pem"
#define X509_CA_CRL_FILE "ca-crl.pem"
#define X509_SERVER_KEY_FILE "server-key.pem"
#define X509_SERVER_CERT_FILE "server-cert.pem"
#endif

#endif /* CONFIG_VNC_TLS */

#define QUEUE_ALLOC_UNIT 10

typedef struct _QueueItem
{
    int x, y, w, h;
    int32_t enc;
    struct _QueueItem *next;
} QueueItem;

typedef struct _Queue
{
    QueueItem *queue_start;
    int start_count;
    QueueItem *queue_end;
    int end_count;
} Queue;

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

    int update_requested;       /* the client requested an update */

    uint8_t *old_data;
    int depth; /* internal VNC frame buffer byte per pixel */
    int has_resize;
    int has_hextile;
    int has_pointer_type_change;
    int has_WMVi;
    int absolute;
    int last_x;
    int last_y;

    int major;
    int minor;

    char *display;
    char *password;
    int auth;
#if CONFIG_VNC_TLS
    int subauth;
    int x509verify;

    char *x509cacert;
    char *x509cacrl;
    char *x509cert;
    char *x509key;
#endif
    char challenge[VNC_AUTH_CHALLENGE_SIZE];

#if CONFIG_VNC_TLS
    int wiremode;
    gnutls_session_t tls_session;
#endif

    Buffer output;
    Buffer input;
    
    Queue upqueue;

    kbd_layout_t *kbd_layout;
    /* current output mode information */
    VncWritePixels *write_pixels;
    VncSendHextileTile *send_hextile_tile;
    int pix_bpp, pix_big_endian;
    int red_shift, red_max, red_shift1, red_max1;
    int green_shift, green_max, green_shift1, green_max1;
    int blue_shift, blue_max, blue_shift1, blue_max1;

    VncReadEvent *read_handler;
    size_t read_handler_expect;

    int visible_x;
    int visible_y;
    int visible_w;
    int visible_h;

    /* input */
    uint8_t modifiers_state[256];
};

static VncState *vnc_state; /* needed for info vnc */

#define DIRTY_PIXEL_BITS 64
#define X2DP_DOWN(vs, x) ((x) >> (vs)->dirty_pixel_shift)
#define X2DP_UP(vs, x) \
  (((x) + (1ULL << (vs)->dirty_pixel_shift) - 1) >> (vs)->dirty_pixel_shift)
#define DP2X(vs, x) ((x) << (vs)->dirty_pixel_shift)

void do_info_vnc(void)
{
    if (vnc_state == NULL)
	term_printf("VNC server disabled\n");
    else {
	term_printf("VNC server active on: ");
	term_print_filename(vnc_state->display);
	term_printf("\n");

	if (vnc_state->csock == -1)
	    term_printf("No client connected\n");
	else
	    term_printf("Client connected\n");
    }
}

/* TODO
   1) Get the queue working for IO.
   2) there is some weirdness when using the -S option (the screen is grey
      and not totally invalidated
   3) resolutions > 1024
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
static void pixel_format_message (VncState *vs);
static void enqueue_framebuffer_update(VncState *vs, int x, int y, int w, int h, int32_t encoding);
static void dequeue_framebuffer_update(VncState *vs);
static int is_empty_queue(VncState *vs);
static void free_queue(VncState *vs);

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

static void vnc_dpy_resize(DisplayState *ds, int w, int h, int linesize)
{
    static int allocated;
    int size_changed;
    VncState *vs = ds->opaque;
    int o;

    if (!ds->shared_buf) {
        ds->linesize = w * vs->depth;
        if (allocated)
            ds->data = realloc(ds->data,  h * ds->linesize);
        else
            ds->data = malloc(h * ds->linesize);
        allocated = 1;
    } else {
        ds->linesize = linesize;
        if (allocated) {
            free(ds->data);
            allocated = 0;
        }
    }
    vs->old_data = realloc(vs->old_data, h * ds->linesize);
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
    size_changed = ds->width != w || ds->height != h;
    ds->width = w;
    ds->height = h;
    if (vs->csock != -1 && vs->has_resize && size_changed) {
        vs->width = ds->width;
        vs->height = ds->height;
        if (vs->update_requested) {
	    vnc_write_u8(vs, 0);  /* msg id */
	    vnc_write_u8(vs, 0);
	    vnc_write_u16(vs, 1); /* number of rects */
	    vnc_framebuffer_update(vs, 0, 0, ds->width, ds->height, -223);
	    vnc_flush(vs);
            vs->update_requested--;
        } else {
            enqueue_framebuffer_update(vs, 0, 0, ds->width, ds->height, -223);
        }
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
    uint8_t r, g, b;

    r = ((v >> vs->red_shift1) & vs->red_max1) * (vs->red_max + 1) / (vs->red_max1 + 1);
    g = ((v >> vs->green_shift1) & vs->green_max1) * (vs->green_max + 1) / (vs->green_max1 + 1);
    b = ((v >> vs->blue_shift1) & vs->blue_max1) * (vs->blue_max + 1) / (vs->blue_max1 + 1);
    switch(vs->pix_bpp) {
    case 1:
        buf[0] = (r << vs->red_shift) | (g << vs->green_shift) | (b << vs->blue_shift);
        break;
    case 2:
    {
        uint16_t *p = (uint16_t *) buf;
        *p = (r << vs->red_shift) | (g << vs->green_shift) | (b << vs->blue_shift);
        if (vs->pix_big_endian) {
            *p = htons(*p);
        }
    }
        break;
    default:
    case 4:
    {
        uint32_t *p = (uint32_t *) buf;
        *p = (r << vs->red_shift) | (g << vs->green_shift) | (b << vs->blue_shift);
        if (vs->pix_big_endian) {
            *p = htonl(*p);
        }
        break;
    }
    }
}

static void vnc_write_pixels_generic(VncState *vs, void *pixels1, int size)
{
    uint8_t buf[4];

    if (vs->depth == 4) {
        uint32_t *pixels = pixels1;
        int n, i;
        n = size >> 2;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->pix_bpp);
        }
    } else if (vs->depth == 2) {
        uint16_t *pixels = pixels1;
        int n, i;
        n = size >> 1;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->pix_bpp);
        }
    } else if (vs->depth == 1) {
        uint8_t *pixels = pixels1;
        int n, i;
        n = size;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->pix_bpp);
        }
    } else {
        fprintf(stderr, "vnc_write_pixels_generic: VncState color depth not supported\n");
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
#define BPP 8
#include "vnchextile.h"
#undef BPP
#undef GENERIC

#define GENERIC
#define BPP 16
#include "vnchextile.h"
#undef BPP
#undef GENERIC

#define GENERIC
#define BPP 32
#include "vnchextile.h"
#undef BPP
#undef GENERIC

static void send_framebuffer_update_hextile(VncState *vs, int x, int y, int w, int h)
{
    int i, j;
    int has_fg, has_bg;
    void *last_fg, *last_bg;

    vnc_framebuffer_update(vs, x, y, w, h, 5);

    last_fg = (void *) malloc(vs->depth);
    last_bg = (void *) malloc(vs->depth);
    has_fg = has_bg = 0;
    for (j = y; j < (y + h); j += 16) {
	for (i = x; i < (x + w); i += 16) {
            vs->send_hextile_tile(vs, i, j, 
                                  MIN(16, x + w - i), MIN(16, y + h - j),
                                  last_bg, last_fg, &has_bg, &has_fg);
	}
    }
    free(last_fg);
    free(last_bg);    
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

    if (ds->shared_buf) {
        framebuffer_set_updated(vs, dst_x, dst_y, w, h);
        return;
    }

    if (!vs->update_requested ||
        src_x < vs->visible_x || src_y < vs->visible_y ||
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
        vs->update_requested--;
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

    if (!vs->update_requested || vs->csock == -1)
	return;
    while (!is_empty_queue(vs) && vs->update_requested) {
        int enc = vs->upqueue.queue_end->enc; 
        dequeue_framebuffer_update(vs);
        switch (enc) {
            case 0x574D5669:
                pixel_format_message(vs);
                break;
            default:
                break;
        }
        vs->update_requested--;
    }
    if (!vs->update_requested) return;

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

    if (n_rectangles == 0) {
        vs->output.offset = saved_offset - 2;
	goto backoff;
    } else
        vs->update_requested--;

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
	if (now - vs->last_update_time >= VNC_MAX_UPDATE_INTERVAL &&
            vs->update_requested) {
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
            vs->update_requested--;
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

static void enqueue_framebuffer_update(VncState *vs, int x, int y, int w, int h,
                                   int32_t encoding)
{
    Queue *q = &vs->upqueue; 
    if (q->queue_end != NULL) {
        if (q->queue_end != q->queue_start || q->start_count != q->end_count) {
            if (q->queue_end->next == NULL) {
                q->queue_end->next = (QueueItem *) qemu_mallocz (sizeof(QueueItem) * QUEUE_ALLOC_UNIT);
                q->end_count = QUEUE_ALLOC_UNIT;
            }
            q->queue_end = q->queue_end->next;
        }
    } else {
        q->queue_end = (QueueItem *) qemu_mallocz (sizeof(QueueItem) * QUEUE_ALLOC_UNIT);
        q->queue_start = q->queue_end;
        q->start_count = QUEUE_ALLOC_UNIT;
        q->end_count = QUEUE_ALLOC_UNIT;
    }
    q->end_count--;

    q->queue_end->x = x;
    q->queue_end->y = y;
    q->queue_end->w = w;
    q->queue_end->h = h;
    q->queue_end->enc = encoding;
    q->queue_end->next = (q->end_count > 0) ? (q->queue_end + 1) : NULL;
}

static void dequeue_framebuffer_update(VncState *vs)
{
    Queue *q = &vs->upqueue;
    if (q->queue_start == NULL || 
            (q->queue_end == q->queue_start && q->start_count == q->end_count))
        return;

    vnc_write_u8(vs, 0);
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1);
    vnc_framebuffer_update(vs, q->queue_start->x, q->queue_start->y,
            q->queue_start->w, q->queue_start->h, q->queue_start->enc);

    q->start_count--;
    if (q->queue_end != q->queue_start) {
        if (!q->start_count) {
            QueueItem *i = q->queue_start;
            q->queue_start = q->queue_start->next;
            q->start_count = QUEUE_ALLOC_UNIT;
            free (i - QUEUE_ALLOC_UNIT + 1);
        } else
            q->queue_start = q->queue_start->next;
    } else {
        q->queue_end = q->queue_end - QUEUE_ALLOC_UNIT + q->end_count + 1;
        q->queue_start = q->queue_end;
        q->end_count = QUEUE_ALLOC_UNIT;
        q->start_count = QUEUE_ALLOC_UNIT;
    }
}

static int is_empty_queue(VncState *vs)
{
    Queue *q = &vs->upqueue;
    if (q->queue_end == NULL) return 1;
    if (q->queue_end == q->queue_start && q->start_count == q->end_count) return 1;
    return 0;
}

static void free_queue(VncState *vs)
{
    Queue *q = &vs->upqueue;
    while (q->queue_start != NULL) {
        QueueItem *i;
        q->queue_start = q->queue_start + q->start_count - 1;
        i = q->queue_start;
        q->queue_start = q->queue_start->next;
        free(i - QUEUE_ALLOC_UNIT + 1);
        q->start_count = QUEUE_ALLOC_UNIT;
    }
    q->queue_end = NULL;
    q->start_count = 0;
    q->end_count = 0;
}

static int vnc_client_io_error(VncState *vs, int ret, int last_errno)
{
    if (ret == 0 || ret == -1) {
	if (ret == -1 && (last_errno == EINTR || last_errno == EAGAIN))
	    return 0;

	VNC_DEBUG("Closing down client sock %d %d\n", ret, ret < 0 ? last_errno : 0);
	qemu_set_fd_handler2(vs->csock, NULL, NULL, NULL, NULL);
	closesocket(vs->csock);
	vs->csock = -1;
	buffer_reset(&vs->input);
	buffer_reset(&vs->output);
        free_queue(vs);
        vs->update_requested = 0;
#if CONFIG_VNC_TLS
	if (vs->tls_session) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	}
	vs->wiremode = VNC_WIREMODE_CLEAR;
#endif /* CONFIG_VNC_TLS */
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

#if CONFIG_VNC_TLS
    if (vs->tls_session) {
	ret = gnutls_write(vs->tls_session, vs->output.buffer, vs->output.offset);
	if (ret < 0) {
	    if (ret == GNUTLS_E_AGAIN)
		errno = EAGAIN;
	    else
		errno = EIO;
	    ret = -1;
	}
    } else
#endif /* CONFIG_VNC_TLS */
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

#if CONFIG_VNC_TLS
    if (vs->tls_session) {
	ret = gnutls_read(vs->tls_session, buffer_end(&vs->input), 4096);
	if (ret < 0) {
	    if (ret == GNUTLS_E_AGAIN)
		errno = EAGAIN;
	    else
		errno = EIO;
	    ret = -1;
	}
    } else
#endif /* CONFIG_VNC_TLS */
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

#if CONFIG_VNC_TLS
ssize_t vnc_tls_push(gnutls_transport_ptr_t transport,
		     const void *data,
		     size_t len) {
    struct VncState *vs = (struct VncState *)transport;
    int ret;

 retry:
    ret = send(vs->csock, data, len, 0);
    if (ret < 0) {
	if (errno == EINTR)
	    goto retry;
	return -1;
    }
    return ret;
}


ssize_t vnc_tls_pull(gnutls_transport_ptr_t transport,
		     void *data,
		     size_t len) {
    struct VncState *vs = (struct VncState *)transport;
    int ret;

 retry:
    ret = recv(vs->csock, data, len, 0);
    if (ret < 0) {
	if (errno == EINTR)
	    goto retry;
	return -1;
    }
    return ret;
}
#endif /* CONFIG_VNC_TLS */

static void client_cut_text(VncState *vs, size_t len, char *text)
{
}

static void check_pointer_type_change(VncState *vs, int absolute)
{
    if (vs->has_pointer_type_change && vs->absolute != absolute) {
        if (vs->update_requested) {
	    vnc_write_u8(vs, 0);
	    vnc_write_u8(vs, 0);
	    vnc_write_u16(vs, 1);
	    vnc_framebuffer_update(vs, absolute, 0,
			       vs->ds->width, vs->ds->height, -257);
	    vnc_flush(vs);
            vs->update_requested--;
        } else {
            enqueue_framebuffer_update(vs, absolute, 0,
                               vs->ds->width, vs->ds->height, -257);
        }
    }
    vs->absolute = absolute;
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

    if (vs->absolute) {
        kbd_mouse_event(x * 0x7FFF / (vs->ds->width - 1),
                        y * 0x7FFF / (vs->ds->height - 1),
			dz, buttons);
    } else if (vs->has_pointer_type_change) {
	x -= 0x7FFF;
	y -= 0x7FFF;

	kbd_mouse_event(x, y, dz, buttons);
    } else {
	if (vs->last_x != -1)
	    kbd_mouse_event(x - vs->last_x,
			    y - vs->last_y,
			    dz, buttons);
	vs->last_x = x;
	vs->last_y = y;
    }

    check_pointer_type_change(vs, kbd_mouse_is_absolute());
}

static void reset_keys(VncState *vs)
{
    int i;
    for(i = 0; i < 256; i++) {
        if (vs->modifiers_state[i]) {
            if (i & 0x80)
                kbd_put_keycode(0xe0);
            kbd_put_keycode(i | 0x80);
            vs->modifiers_state[i] = 0;
        }
    }
}

static void press_key(VncState *vs, int keysym)
{
    kbd_put_keycode(keysym2scancode(vs->kbd_layout, keysym) & 0x7f);
    kbd_put_keycode(keysym2scancode(vs->kbd_layout, keysym) | 0x80);
}

static void press_key_shift_down(VncState *vs, int down, int keycode)
{
    if (down)
        kbd_put_keycode(0x2a & 0x7f);

    if (keycode & 0x80)
        kbd_put_keycode(0xe0);
    if (down)
        kbd_put_keycode(keycode & 0x7f);
    else
        kbd_put_keycode(keycode | 0x80);

    if (!down)
        kbd_put_keycode(0x2a | 0x80);
}

static void press_key_shift_up(VncState *vs, int down, int keycode)
{
    if (down) {
        if (vs->modifiers_state[0x2a])
            kbd_put_keycode(0x2a | 0x80);
        if (vs->modifiers_state[0x36]) 
            kbd_put_keycode(0x36 | 0x80);
    }

    if (keycode & 0x80)
        kbd_put_keycode(0xe0);
    if (down)
        kbd_put_keycode(keycode & 0x7f);
    else
        kbd_put_keycode(keycode | 0x80);

    if (!down) {
        if (vs->modifiers_state[0x2a])
            kbd_put_keycode(0x2a & 0x7f);
        if (vs->modifiers_state[0x36]) 
            kbd_put_keycode(0x36 & 0x7f);
    }
}

static void do_key_event(VncState *vs, int down, uint32_t sym)
{
    int keycode;
    int shift_keys = 0;
    int shift = 0;

    if (is_graphic_console()) {
        if (sym >= 'A' && sym <= 'Z') {
            sym = sym - 'A' + 'a';
            shift = 1;
        }
        else {
            shift = keysymIsShift(vs->kbd_layout, sym & 0xFFFF);
        }
    }
    shift_keys = vs->modifiers_state[0x2a] | vs->modifiers_state[0x36];

    keycode = keysym2scancode(vs->kbd_layout, sym & 0xFFFF);
    if (keycode == 0) {
        fprintf(stderr, "Key lost : keysym=0x%x(%d)\n", sym, sym);
        return;
    }

    /* QEMU console switch */
    switch(keycode) {
    case 0x2a:                          /* Left Shift */
    case 0x36:                          /* Right Shift */
    case 0x1d:                          /* Left CTRL */
    case 0x9d:                          /* Right CTRL */
    case 0x38:                          /* Left ALT */
    case 0xb8:                          /* Right ALT */
        if (down) {
            vs->modifiers_state[keycode] = 1;
            kbd_put_keycode(keycode & 0x7f);
        }
        else {
            vs->modifiers_state[keycode] = 0;
            kbd_put_keycode(keycode | 0x80);
        }
        return;
    case 0x02 ... 0x0a: /* '1' to '9' keys */ 
        if (down && vs->modifiers_state[0x1d] && vs->modifiers_state[0x38]) {
            /* Reset the modifiers sent to the current console */
            reset_keys(vs);
            console_select(keycode - 0x02);
            return;
        }
        break;
    case 0x45:			/* NumLock */
	if (down) {
            kbd_put_keycode(keycode & 0x7f);
        }
        else {	
	    vs->modifiers_state[keycode] ^= 1;
            kbd_put_keycode(keycode | 0x80);
        }
	return;
    }

    if (keycodeIsKeypad(vs->kbd_layout, keycode)) {
        /* If the numlock state needs to change then simulate an additional
           keypress before sending this one.  This will happen if the user
           toggles numlock away from the VNC window.
        */
        if (keysymIsNumlock(vs->kbd_layout, sym & 0xFFFF)) {
	    if (!vs->modifiers_state[0x45]) {
		vs->modifiers_state[0x45] = 1;
		press_key(vs, 0xff7f);
	    }
	} else {
	    if (vs->modifiers_state[0x45]) {
		vs->modifiers_state[0x45] = 0;
		press_key(vs, 0xff7f);
	    }
        }
    }

    if (is_graphic_console()) {
        /*  If the shift state needs to change then simulate an additional
            keypress before sending this one.
        */
        if (shift && !shift_keys) {
            press_key_shift_down(vs, down, keycode);
            return;
        }
        else if (!shift && shift_keys) {
            press_key_shift_up(vs, down, keycode);
            return;
        }

        if (keycode & 0x80)
            kbd_put_keycode(0xe0);
        if (down)
            kbd_put_keycode(keycode & 0x7f);
        else
            kbd_put_keycode(keycode | 0x80);
    } else {
        /* QEMU console emulation */
        if (down) {
            switch (keycode) {
            case 0x2a:                          /* Left Shift */
            case 0x36:                          /* Right Shift */
            case 0x1d:                          /* Left CTRL */
            case 0x9d:                          /* Right CTRL */
            case 0x38:                          /* Left ALT */
            case 0xb8:                          /* Right ALT */
                break;
            case 0xc8:
                kbd_put_keysym(QEMU_KEY_UP);
                break;
            case 0xd0:
                kbd_put_keysym(QEMU_KEY_DOWN);
                break;
            case 0xcb:
                kbd_put_keysym(QEMU_KEY_LEFT);
                break;
            case 0xcd:
                kbd_put_keysym(QEMU_KEY_RIGHT);
                break;
            case 0xd3:
                kbd_put_keysym(QEMU_KEY_DELETE);
                break;
            case 0xc7:
                kbd_put_keysym(QEMU_KEY_HOME);
                break;
            case 0xcf:
                kbd_put_keysym(QEMU_KEY_END);
                break;
            case 0xc9:
                kbd_put_keysym(QEMU_KEY_PAGEUP);
                break;
            case 0xd1:
                kbd_put_keysym(QEMU_KEY_PAGEDOWN);
                break;
            default:
                kbd_put_keysym(sym);
                break;
            }
        }
    }
}

static void key_event(VncState *vs, int down, uint32_t sym)
{
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

    vs->update_requested++;
    qemu_mod_timer(vs->timer, qemu_get_clock(rt_clock));
}

static void set_encodings(VncState *vs, int32_t *encodings, size_t n_encodings)
{
    int i;

    vs->has_hextile = 0;
    vs->has_resize = 0;
    vs->has_pointer_type_change = 0;
    vs->has_WMVi = 0;
    vs->absolute = -1;
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
	case -257:
	    vs->has_pointer_type_change = 1;
	    break;
        case 0x574D5669:
            vs->has_WMVi = 1;
	default:
	    break;
	}
    }

    check_pointer_type_change(vs, kbd_mouse_is_absolute());
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
        bits_per_pixel == vs->depth * 8 && 
        host_big_endian_flag == big_endian_flag &&
        red_max == 0xff && green_max == 0xff && blue_max == 0xff &&
        red_shift == 16 && green_shift == 8 && blue_shift == 0) {
        vs->write_pixels = vnc_write_pixels_copy;
        vs->send_hextile_tile = send_hextile_tile_32;
    } else 
    if (bits_per_pixel == 16 &&
        bits_per_pixel == vs->depth * 8 && 
        host_big_endian_flag == big_endian_flag &&
        red_max == 31 && green_max == 63 && blue_max == 31 &&
        red_shift == 11 && green_shift == 5 && blue_shift == 0) {
        vs->write_pixels = vnc_write_pixels_copy;
        vs->send_hextile_tile = send_hextile_tile_16;
    } else 
    if (bits_per_pixel == 8 && 
        bits_per_pixel == vs->depth * 8 &&
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
        if (vs->depth == 4) {
            vs->send_hextile_tile = send_hextile_tile_generic_32;
        } else if (vs->depth == 2) {
            vs->send_hextile_tile = send_hextile_tile_generic_16;
        } else {
            vs->send_hextile_tile = send_hextile_tile_generic_8;
        }
            
        vs->pix_big_endian = big_endian_flag;
        vs->write_pixels = vnc_write_pixels_generic;
    }
 
    vs->red_shift = red_shift;
    vs->red_max = red_max;
    vs->green_shift = green_shift;
    vs->green_max = green_max;
    vs->blue_shift = blue_shift;
    vs->blue_max = blue_max;
    vs->pix_bpp = bits_per_pixel / 8;
}

static void pixel_format_message (VncState *vs) {
    char pad[3] = { 0, 0, 0 };

    vnc_write_u8(vs, vs->depth * 8); /* bits-per-pixel */
    if (vs->depth == 4) vnc_write_u8(vs, 24); /* depth */
    else vnc_write_u8(vs, vs->depth * 8); /* depth */

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
    vs->red_max = vs->red_max1;
    vs->green_max = vs->green_max1;
    vs->blue_max = vs->blue_max1;
    vs->red_shift = vs->red_shift1;
    vs->green_shift = vs->green_shift1;
    vs->blue_shift = vs->blue_shift1;
    vs->pix_bpp = vs->depth * 8;
    vs->write_pixels = vnc_write_pixels_copy;
        
    vnc_write(vs, pad, 3);           /* padding */
}

static void vnc_dpy_setdata(DisplayState *ds, void *pixels)
{
    ds->data = pixels;
}

static void vnc_dpy_colourdepth(DisplayState *ds, int depth)
{
    int host_big_endian_flag;
    struct VncState *vs = ds->opaque;

    switch (depth) {
        case 24:
            ds->shared_buf = 0;
            if (ds->depth == 32) return;
            depth = 32;
            break;
        case 0:
            ds->shared_buf = 0;
            return;
        default:
            ds->shared_buf = 1;
            break;
    }

#ifdef WORDS_BIGENDIAN
    host_big_endian_flag = 1;
#else
    host_big_endian_flag = 0;
#endif   
    
    switch (depth) {
        case 8:
            vs->depth = depth / 8;
            vs->red_max1 = 7;
            vs->green_max1 = 7;
            vs->blue_max1 = 3;
            vs->red_shift1 = 5;
            vs->green_shift1 = 2;
            vs->blue_shift1 = 0;
            break;
        case 16:
            vs->depth = depth / 8;
            vs->red_max1 = 31;
            vs->green_max1 = 63;
            vs->blue_max1 = 31;
            vs->red_shift1 = 11;
            vs->green_shift1 = 5;
            vs->blue_shift1 = 0;
            break;
        case 32:
            vs->depth = 4;
            vs->red_max1 = 255;
            vs->green_max1 = 255;
            vs->blue_max1 = 255;
            vs->red_shift1 = 16;
            vs->green_shift1 = 8;
            vs->blue_shift1 = 0;
            break;
        default:
            return;
    }
    if (ds->switchbpp) {
        vnc_client_error(vs);
    } else if (vs->csock != -1 && vs->has_WMVi) {
        /* Sending a WMVi message to notify the client*/
        if (vs->update_requested) {
            vnc_write_u8(vs, 0);  /* msg id */
            vnc_write_u8(vs, 0);
            vnc_write_u16(vs, 1); /* number of rects */
            vnc_framebuffer_update(vs, 0, 0, ds->width, ds->height, 0x574D5669);
            pixel_format_message(vs);
            vnc_flush(vs);
            vs->update_requested--;
        } else {
            enqueue_framebuffer_update(vs, 0, 0, ds->width, ds->height, 0x574D5669);
        }
    } else {
        if (vs->pix_bpp == 4 && vs->depth == 4 &&
            host_big_endian_flag == vs->pix_big_endian &&
            vs->red_max == 0xff && vs->green_max == 0xff && vs->blue_max == 0xff &&
            vs->red_shift == 16 && vs->green_shift == 8 && vs->blue_shift == 0) {
            vs->write_pixels = vnc_write_pixels_copy;
            vs->send_hextile_tile = send_hextile_tile_32;
        } else if (vs->pix_bpp == 2 && vs->depth == 2 &&
            host_big_endian_flag == vs->pix_big_endian &&
            vs->red_max == 31 && vs->green_max == 63 && vs->blue_max == 31 &&
            vs->red_shift == 11 && vs->green_shift == 5 && vs->blue_shift == 0) {
            vs->write_pixels = vnc_write_pixels_copy;
            vs->send_hextile_tile = send_hextile_tile_16;
        } else if (vs->pix_bpp == 1 && vs->depth == 1 &&
            host_big_endian_flag == vs->pix_big_endian &&
            vs->red_max == 7 && vs->green_max == 7 && vs->blue_max == 3 &&
            vs->red_shift == 5 && vs->green_shift == 2 && vs->blue_shift == 0) {
            vs->write_pixels = vnc_write_pixels_copy;
            vs->send_hextile_tile = send_hextile_tile_8;
        } else {
            if (vs->depth == 4) {
                vs->send_hextile_tile = send_hextile_tile_generic_32;
            } else if (vs->depth == 2) {
                vs->send_hextile_tile = send_hextile_tile_generic_16;
            } else {
                vs->send_hextile_tile = send_hextile_tile_generic_8;
            }
            vs->write_pixels = vnc_write_pixels_generic;
        }
    }

    vnc_dpy_resize(ds, ds->width, ds->height, ds->linesize);
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

    vga_hw_update();

    vs->width = vs->ds->width;
    vs->height = vs->ds->height;
    vnc_write_u16(vs, vs->ds->width);
    vnc_write_u16(vs, vs->ds->height);

    pixel_format_message(vs);

    l = strlen(domain_name); 
    vnc_write_u32(vs, l);        
    vnc_write(vs, domain_name, l);

    vnc_flush(vs);

    vnc_read_when(vs, protocol_client_msg, 1);

    return 0;
}


static void make_challenge(VncState *vs)
{
    int i;

    srand(time(NULL)+getpid()+getpid()*987654+rand());

    for (i = 0 ; i < sizeof(vs->challenge) ; i++)
        vs->challenge[i] = (int) (256.0*rand()/(RAND_MAX+1.0));
}

static int protocol_client_auth_vnc(VncState *vs, char *data, size_t len)
{
    char response[VNC_AUTH_CHALLENGE_SIZE];
    int i, j, pwlen;
    char key[8];

    if (!vs->password || !vs->password[0]) {
	VNC_DEBUG("No password configured on server");
	vnc_write_u32(vs, 1); /* Reject auth */
	if (vs->minor >= 8) {
	    static const char err[] = "Authentication failed";
	    vnc_write_u32(vs, sizeof(err));
	    vnc_write(vs, err, sizeof(err));
	}
	vnc_flush(vs);
	vnc_client_error(vs);
	return 0;
    }

    memcpy(response, vs->challenge, VNC_AUTH_CHALLENGE_SIZE);

    /* Calculate the expected challenge response */
    pwlen = strlen(vs->password);
    for (i=0; i<sizeof(key); i++)
        key[i] = i<pwlen ? vs->password[i] : 0;
    deskey(key, EN0);
    for (j = 0; j < VNC_AUTH_CHALLENGE_SIZE; j += 8)
        des(response+j, response+j);

    /* Compare expected vs actual challenge response */
    if (memcmp(response, data, VNC_AUTH_CHALLENGE_SIZE) != 0) {
	VNC_DEBUG("Client challenge reponse did not match\n");
	vnc_write_u32(vs, 1); /* Reject auth */
	if (vs->minor >= 8) {
	    static const char err[] = "Authentication failed";
	    vnc_write_u32(vs, sizeof(err));
	    vnc_write(vs, err, sizeof(err));
	}
	vnc_flush(vs);
	vnc_client_error(vs);
    } else {
	VNC_DEBUG("Accepting VNC challenge response\n");
	vnc_write_u32(vs, 0); /* Accept auth */
	vnc_flush(vs);

	vnc_read_when(vs, protocol_client_init, 1);
    }
    return 0;
}

static int start_auth_vnc(VncState *vs)
{
    make_challenge(vs);
    /* Send client a 'random' challenge */
    vnc_write(vs, vs->challenge, sizeof(vs->challenge));
    vnc_flush(vs);

    vnc_read_when(vs, protocol_client_auth_vnc, sizeof(vs->challenge));
    return 0;
}


#if CONFIG_VNC_TLS
#define DH_BITS 1024
static gnutls_dh_params_t dh_params;

static int vnc_tls_initialize(void)
{
    static int tlsinitialized = 0;

    if (tlsinitialized)
	return 1;

    if (gnutls_global_init () < 0)
	return 0;

    /* XXX ought to re-generate diffie-hellmen params periodically */
    if (gnutls_dh_params_init (&dh_params) < 0)
	return 0;
    if (gnutls_dh_params_generate2 (dh_params, DH_BITS) < 0)
	return 0;

#if _VNC_DEBUG == 2
    gnutls_global_set_log_level(10);
    gnutls_global_set_log_function(vnc_debug_gnutls_log);
#endif

    tlsinitialized = 1;

    return 1;
}

static gnutls_anon_server_credentials vnc_tls_initialize_anon_cred(void)
{
    gnutls_anon_server_credentials anon_cred;
    int ret;

    if ((ret = gnutls_anon_allocate_server_credentials(&anon_cred)) < 0) {
	VNC_DEBUG("Cannot allocate credentials %s\n", gnutls_strerror(ret));
	return NULL;
    }

    gnutls_anon_set_server_dh_params(anon_cred, dh_params);

    return anon_cred;
}


static gnutls_certificate_credentials_t vnc_tls_initialize_x509_cred(VncState *vs)
{
    gnutls_certificate_credentials_t x509_cred;
    int ret;

    if (!vs->x509cacert) {
	VNC_DEBUG("No CA x509 certificate specified\n");
	return NULL;
    }
    if (!vs->x509cert) {
	VNC_DEBUG("No server x509 certificate specified\n");
	return NULL;
    }
    if (!vs->x509key) {
	VNC_DEBUG("No server private key specified\n");
	return NULL;
    }

    if ((ret = gnutls_certificate_allocate_credentials(&x509_cred)) < 0) {
	VNC_DEBUG("Cannot allocate credentials %s\n", gnutls_strerror(ret));
	return NULL;
    }
    if ((ret = gnutls_certificate_set_x509_trust_file(x509_cred,
						      vs->x509cacert,
						      GNUTLS_X509_FMT_PEM)) < 0) {
	VNC_DEBUG("Cannot load CA certificate %s\n", gnutls_strerror(ret));
	gnutls_certificate_free_credentials(x509_cred);
	return NULL;
    }

    if ((ret = gnutls_certificate_set_x509_key_file (x509_cred,
						     vs->x509cert,
						     vs->x509key,
						     GNUTLS_X509_FMT_PEM)) < 0) {
	VNC_DEBUG("Cannot load certificate & key %s\n", gnutls_strerror(ret));
	gnutls_certificate_free_credentials(x509_cred);
	return NULL;
    }

    if (vs->x509cacrl) {
	if ((ret = gnutls_certificate_set_x509_crl_file(x509_cred,
							vs->x509cacrl,
							GNUTLS_X509_FMT_PEM)) < 0) {
	    VNC_DEBUG("Cannot load CRL %s\n", gnutls_strerror(ret));
	    gnutls_certificate_free_credentials(x509_cred);
	    return NULL;
	}
    }

    gnutls_certificate_set_dh_params (x509_cred, dh_params);

    return x509_cred;
}

static int vnc_validate_certificate(struct VncState *vs)
{
    int ret;
    unsigned int status;
    const gnutls_datum_t *certs;
    unsigned int nCerts, i;
    time_t now;

    VNC_DEBUG("Validating client certificate\n");
    if ((ret = gnutls_certificate_verify_peers2 (vs->tls_session, &status)) < 0) {
	VNC_DEBUG("Verify failed %s\n", gnutls_strerror(ret));
	return -1;
    }

    if ((now = time(NULL)) == ((time_t)-1)) {
	return -1;
    }

    if (status != 0) {
	if (status & GNUTLS_CERT_INVALID)
	    VNC_DEBUG("The certificate is not trusted.\n");

	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
	    VNC_DEBUG("The certificate hasn't got a known issuer.\n");

	if (status & GNUTLS_CERT_REVOKED)
	    VNC_DEBUG("The certificate has been revoked.\n");

	if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
	    VNC_DEBUG("The certificate uses an insecure algorithm\n");

	return -1;
    } else {
	VNC_DEBUG("Certificate is valid!\n");
    }

    /* Only support x509 for now */
    if (gnutls_certificate_type_get(vs->tls_session) != GNUTLS_CRT_X509)
	return -1;

    if (!(certs = gnutls_certificate_get_peers(vs->tls_session, &nCerts)))
	return -1;

    for (i = 0 ; i < nCerts ; i++) {
	gnutls_x509_crt_t cert;
	VNC_DEBUG ("Checking certificate chain %d\n", i);
	if (gnutls_x509_crt_init (&cert) < 0)
	    return -1;

	if (gnutls_x509_crt_import(cert, &certs[i], GNUTLS_X509_FMT_DER) < 0) {
	    gnutls_x509_crt_deinit (cert);
	    return -1;
	}

	if (gnutls_x509_crt_get_expiration_time (cert) < now) {
	    VNC_DEBUG("The certificate has expired\n");
	    gnutls_x509_crt_deinit (cert);
	    return -1;
	}

	if (gnutls_x509_crt_get_activation_time (cert) > now) {
	    VNC_DEBUG("The certificate is not yet activated\n");
	    gnutls_x509_crt_deinit (cert);
	    return -1;
	}

	if (gnutls_x509_crt_get_activation_time (cert) > now) {
	    VNC_DEBUG("The certificate is not yet activated\n");
	    gnutls_x509_crt_deinit (cert);
	    return -1;
	}

	gnutls_x509_crt_deinit (cert);
    }

    return 0;
}


static int start_auth_vencrypt_subauth(VncState *vs)
{
    switch (vs->subauth) {
    case VNC_AUTH_VENCRYPT_TLSNONE:
    case VNC_AUTH_VENCRYPT_X509NONE:
       VNC_DEBUG("Accept TLS auth none\n");
       vnc_write_u32(vs, 0); /* Accept auth completion */
       vnc_read_when(vs, protocol_client_init, 1);
       break;

    case VNC_AUTH_VENCRYPT_TLSVNC:
    case VNC_AUTH_VENCRYPT_X509VNC:
       VNC_DEBUG("Start TLS auth VNC\n");
       return start_auth_vnc(vs);

    default: /* Should not be possible, but just in case */
       VNC_DEBUG("Reject auth %d\n", vs->auth);
       vnc_write_u8(vs, 1);
       if (vs->minor >= 8) {
           static const char err[] = "Unsupported authentication type";
           vnc_write_u32(vs, sizeof(err));
           vnc_write(vs, err, sizeof(err));
       }
       vnc_client_error(vs);
    }

    return 0;
}

static void vnc_handshake_io(void *opaque);

static int vnc_continue_handshake(struct VncState *vs) {
    int ret;

    if ((ret = gnutls_handshake(vs->tls_session)) < 0) {
       if (!gnutls_error_is_fatal(ret)) {
           VNC_DEBUG("Handshake interrupted (blocking)\n");
           if (!gnutls_record_get_direction(vs->tls_session))
               qemu_set_fd_handler(vs->csock, vnc_handshake_io, NULL, vs);
           else
               qemu_set_fd_handler(vs->csock, NULL, vnc_handshake_io, vs);
           return 0;
       }
       VNC_DEBUG("Handshake failed %s\n", gnutls_strerror(ret));
       vnc_client_error(vs);
       return -1;
    }

    if (vs->x509verify) {
	if (vnc_validate_certificate(vs) < 0) {
	    VNC_DEBUG("Client verification failed\n");
	    vnc_client_error(vs);
	    return -1;
	} else {
	    VNC_DEBUG("Client verification passed\n");
	}
    }

    VNC_DEBUG("Handshake done, switching to TLS data mode\n");
    vs->wiremode = VNC_WIREMODE_TLS;
    qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, vnc_client_write, vs);

    return start_auth_vencrypt_subauth(vs);
}

static void vnc_handshake_io(void *opaque) {
    struct VncState *vs = (struct VncState *)opaque;

    VNC_DEBUG("Handshake IO continue\n");
    vnc_continue_handshake(vs);
}

#define NEED_X509_AUTH(vs)			      \
    ((vs)->subauth == VNC_AUTH_VENCRYPT_X509NONE ||   \
     (vs)->subauth == VNC_AUTH_VENCRYPT_X509VNC ||    \
     (vs)->subauth == VNC_AUTH_VENCRYPT_X509PLAIN)


static int vnc_start_tls(struct VncState *vs) {
    static const int cert_type_priority[] = { GNUTLS_CRT_X509, 0 };
    static const int protocol_priority[]= { GNUTLS_TLS1_1, GNUTLS_TLS1_0, GNUTLS_SSL3, 0 };
    static const int kx_anon[] = {GNUTLS_KX_ANON_DH, 0};
    static const int kx_x509[] = {GNUTLS_KX_DHE_DSS, GNUTLS_KX_RSA, GNUTLS_KX_DHE_RSA, GNUTLS_KX_SRP, 0};

    VNC_DEBUG("Do TLS setup\n");
    if (vnc_tls_initialize() < 0) {
	VNC_DEBUG("Failed to init TLS\n");
	vnc_client_error(vs);
	return -1;
    }
    if (vs->tls_session == NULL) {
	if (gnutls_init(&vs->tls_session, GNUTLS_SERVER) < 0) {
	    vnc_client_error(vs);
	    return -1;
	}

	if (gnutls_set_default_priority(vs->tls_session) < 0) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	    vnc_client_error(vs);
	    return -1;
	}

	if (gnutls_kx_set_priority(vs->tls_session, NEED_X509_AUTH(vs) ? kx_x509 : kx_anon) < 0) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	    vnc_client_error(vs);
	    return -1;
	}

	if (gnutls_certificate_type_set_priority(vs->tls_session, cert_type_priority) < 0) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	    vnc_client_error(vs);
	    return -1;
	}

	if (gnutls_protocol_set_priority(vs->tls_session, protocol_priority) < 0) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	    vnc_client_error(vs);
	    return -1;
	}

	if (NEED_X509_AUTH(vs)) {
	    gnutls_certificate_server_credentials x509_cred = vnc_tls_initialize_x509_cred(vs);
	    if (!x509_cred) {
		gnutls_deinit(vs->tls_session);
		vs->tls_session = NULL;
		vnc_client_error(vs);
		return -1;
	    }
	    if (gnutls_credentials_set(vs->tls_session, GNUTLS_CRD_CERTIFICATE, x509_cred) < 0) {
		gnutls_deinit(vs->tls_session);
		vs->tls_session = NULL;
		gnutls_certificate_free_credentials(x509_cred);
		vnc_client_error(vs);
		return -1;
	    }
	    if (vs->x509verify) {
		VNC_DEBUG("Requesting a client certificate\n");
		gnutls_certificate_server_set_request (vs->tls_session, GNUTLS_CERT_REQUEST);
	    }

	} else {
	    gnutls_anon_server_credentials anon_cred = vnc_tls_initialize_anon_cred();
	    if (!anon_cred) {
		gnutls_deinit(vs->tls_session);
		vs->tls_session = NULL;
		vnc_client_error(vs);
		return -1;
	    }
	    if (gnutls_credentials_set(vs->tls_session, GNUTLS_CRD_ANON, anon_cred) < 0) {
		gnutls_deinit(vs->tls_session);
		vs->tls_session = NULL;
		gnutls_anon_free_server_credentials(anon_cred);
		vnc_client_error(vs);
		return -1;
	    }
	}

	gnutls_transport_set_ptr(vs->tls_session, (gnutls_transport_ptr_t)vs);
	gnutls_transport_set_push_function(vs->tls_session, vnc_tls_push);
	gnutls_transport_set_pull_function(vs->tls_session, vnc_tls_pull);
    }

    VNC_DEBUG("Start TLS handshake process\n");
    return vnc_continue_handshake(vs);
}

static int protocol_client_vencrypt_auth(VncState *vs, char *data, size_t len)
{
    int auth = read_u32(data, 0);

    if (auth != vs->subauth) {
	VNC_DEBUG("Rejecting auth %d\n", auth);
	vnc_write_u8(vs, 0); /* Reject auth */
	vnc_flush(vs);
	vnc_client_error(vs);
    } else {
	VNC_DEBUG("Accepting auth %d, starting handshake\n", auth);
	vnc_write_u8(vs, 1); /* Accept auth */
	vnc_flush(vs);

	if (vnc_start_tls(vs) < 0) {
	    VNC_DEBUG("Failed to complete TLS\n");
	    return 0;
	}

	if (vs->wiremode == VNC_WIREMODE_TLS) {
	    VNC_DEBUG("Starting VeNCrypt subauth\n");
	    return start_auth_vencrypt_subauth(vs);
	} else {
	    VNC_DEBUG("TLS handshake blocked\n");
	    return 0;
	}
    }
    return 0;
}

static int protocol_client_vencrypt_init(VncState *vs, char *data, size_t len)
{
    if (data[0] != 0 ||
	data[1] != 2) {
	VNC_DEBUG("Unsupported VeNCrypt protocol %d.%d\n", (int)data[0], (int)data[1]);
	vnc_write_u8(vs, 1); /* Reject version */
	vnc_flush(vs);
	vnc_client_error(vs);
    } else {
	VNC_DEBUG("Sending allowed auth %d\n", vs->subauth);
	vnc_write_u8(vs, 0); /* Accept version */
	vnc_write_u8(vs, 1); /* Number of sub-auths */
	vnc_write_u32(vs, vs->subauth); /* The supported auth */
	vnc_flush(vs);
	vnc_read_when(vs, protocol_client_vencrypt_auth, 4);
    }
    return 0;
}

static int start_auth_vencrypt(VncState *vs)
{
    /* Send VeNCrypt version 0.2 */
    vnc_write_u8(vs, 0);
    vnc_write_u8(vs, 2);

    vnc_read_when(vs, protocol_client_vencrypt_init, 2);
    return 0;
}
#endif /* CONFIG_VNC_TLS */

static int protocol_client_auth(VncState *vs, char *data, size_t len)
{
    /* We only advertise 1 auth scheme at a time, so client
     * must pick the one we sent. Verify this */
    if (data[0] != vs->auth) { /* Reject auth */
       VNC_DEBUG("Reject auth %d\n", (int)data[0]);
       vnc_write_u32(vs, 1);
       if (vs->minor >= 8) {
           static const char err[] = "Authentication failed";
           vnc_write_u32(vs, sizeof(err));
           vnc_write(vs, err, sizeof(err));
       }
       vnc_client_error(vs);
    } else { /* Accept requested auth */
       VNC_DEBUG("Client requested auth %d\n", (int)data[0]);
       switch (vs->auth) {
       case VNC_AUTH_NONE:
           VNC_DEBUG("Accept auth none\n");
           if (vs->minor >= 8) {
               vnc_write_u32(vs, 0); /* Accept auth completion */
               vnc_flush(vs);
           }
           vnc_read_when(vs, protocol_client_init, 1);
           break;

       case VNC_AUTH_VNC:
           VNC_DEBUG("Start VNC auth\n");
           return start_auth_vnc(vs);

#if CONFIG_VNC_TLS
       case VNC_AUTH_VENCRYPT:
           VNC_DEBUG("Accept VeNCrypt auth\n");;
           return start_auth_vencrypt(vs);
#endif /* CONFIG_VNC_TLS */

       default: /* Should not be possible, but just in case */
           VNC_DEBUG("Reject auth %d\n", vs->auth);
           vnc_write_u8(vs, 1);
           if (vs->minor >= 8) {
               static const char err[] = "Authentication failed";
               vnc_write_u32(vs, sizeof(err));
               vnc_write(vs, err, sizeof(err));
           }
           vnc_client_error(vs);
       }
    }
    return 0;
}

static int protocol_version(VncState *vs, char *version, size_t len)
{
    char local[13];

    memcpy(local, version, 12);
    local[12] = 0;

    if (sscanf(local, "RFB %03d.%03d\n", &vs->major, &vs->minor) != 2) {
	VNC_DEBUG("Malformed protocol version %s\n", local);
	vnc_client_error(vs);
	return 0;
    }
    VNC_DEBUG("Client request protocol version %d.%d\n", vs->major, vs->minor);
    if (vs->major != 3 ||
	(vs->minor != 3 &&
	 vs->minor != 4 &&
	 vs->minor != 5 &&
	 vs->minor != 7 &&
	 vs->minor != 8)) {
	VNC_DEBUG("Unsupported client version\n");
	vnc_write_u32(vs, VNC_AUTH_INVALID);
	vnc_flush(vs);
	vnc_client_error(vs);
	return 0;
    }
    /* Some broken clients report v3.4 or v3.5, which spec requires to be treated
     * as equivalent to v3.3 by servers
     */
    if (vs->minor == 4 || vs->minor == 5)
	vs->minor = 3;

    if (vs->minor == 3) {
	if (vs->auth == VNC_AUTH_NONE) {
            VNC_DEBUG("Tell client auth none\n");
            vnc_write_u32(vs, vs->auth);
            vnc_flush(vs);
            vnc_read_when(vs, protocol_client_init, 1);
       } else if (vs->auth == VNC_AUTH_VNC) {
            VNC_DEBUG("Tell client VNC auth\n");
            vnc_write_u32(vs, vs->auth);
            vnc_flush(vs);
            start_auth_vnc(vs);
       } else {
            VNC_DEBUG("Unsupported auth %d for protocol 3.3\n", vs->auth);
            vnc_write_u32(vs, VNC_AUTH_INVALID);
            vnc_flush(vs);
            vnc_client_error(vs);
       }
    } else {
	VNC_DEBUG("Telling client we support auth %d\n", vs->auth);
	vnc_write_u8(vs, 1); /* num auth */
	vnc_write_u8(vs, vs->auth);
	vnc_read_when(vs, protocol_client_auth, 1);
	vnc_flush(vs);
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
	VNC_DEBUG("New client on socket %d\n", vs->csock);
        socket_set_nonblock(vs->csock);
	qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, NULL, opaque);
	vnc_write(vs, "RFB 003.008\n", 12);
	vnc_flush(vs);
	vnc_read_when(vs, protocol_version, 12);
	framebuffer_set_updated(vs, 0, 0, vs->ds->width, vs->ds->height);
	vs->has_resize = 0;
	vs->has_hextile = 0;
        vs->update_requested = 0;
	vs->ds->dpy_copy = NULL;
	vnc_timer_init(vs);
    }
}

extern int parse_host_port(struct sockaddr_in *saddr, const char *str);

void vnc_display_init(DisplayState *ds)
{
    VncState *vs;

    vs = qemu_mallocz(sizeof(VncState));
    if (!vs)
	exit(1);

    ds->opaque = vs;
    vnc_state = vs;
    vs->display = NULL;
    vs->password = NULL;

    vs->lsock = -1;
    vs->csock = -1;
    vs->last_x = -1;
    vs->last_y = -1;

    vs->ds = ds;

    if (!keyboard_layout)
	keyboard_layout = "en-us";

    vs->kbd_layout = init_keyboard_layout(keyboard_layout);
    if (!vs->kbd_layout)
	exit(1);
    vs->modifiers_state[0x45] = 1; /* NumLock on - on boot */

    vs->ds->data = NULL;
    vs->ds->dpy_update = vnc_dpy_update;
    vs->ds->dpy_resize = vnc_dpy_resize;
    vs->ds->dpy_colourdepth = vnc_dpy_colourdepth;
    vs->ds->dpy_setdata = vnc_dpy_setdata;
    vs->ds->dpy_refresh = vnc_dpy_refresh;

    vs->ds->width = 640;
    vs->ds->height = 400;
    vs->ds->linesize = 640 * 4;
    vnc_dpy_colourdepth(vs->ds, 24);
}

#if CONFIG_VNC_TLS
static int vnc_set_x509_credential(VncState *vs,
				   const char *certdir,
				   const char *filename,
				   char **cred,
				   int ignoreMissing)
{
    struct stat sb;

    if (*cred) {
	qemu_free(*cred);
	*cred = NULL;
    }

    if (!(*cred = qemu_malloc(strlen(certdir) + strlen(filename) + 2)))
	return -1;

    strcpy(*cred, certdir);
    strcat(*cred, "/");
    strcat(*cred, filename);

    VNC_DEBUG("Check %s\n", *cred);
    if (stat(*cred, &sb) < 0) {
	qemu_free(*cred);
	*cred = NULL;
	if (ignoreMissing && errno == ENOENT)
	    return 0;
	return -1;
    }

    return 0;
}

static int vnc_set_x509_credential_dir(VncState *vs,
				       const char *certdir)
{
    if (vnc_set_x509_credential(vs, certdir, X509_CA_CERT_FILE, &vs->x509cacert, 0) < 0)
	goto cleanup;
    if (vnc_set_x509_credential(vs, certdir, X509_CA_CRL_FILE, &vs->x509cacrl, 1) < 0)
	goto cleanup;
    if (vnc_set_x509_credential(vs, certdir, X509_SERVER_CERT_FILE, &vs->x509cert, 0) < 0)
	goto cleanup;
    if (vnc_set_x509_credential(vs, certdir, X509_SERVER_KEY_FILE, &vs->x509key, 0) < 0)
	goto cleanup;

    return 0;

 cleanup:
    qemu_free(vs->x509cacert);
    qemu_free(vs->x509cacrl);
    qemu_free(vs->x509cert);
    qemu_free(vs->x509key);
    vs->x509cacert = vs->x509cacrl = vs->x509cert = vs->x509key = NULL;
    return -1;
}
#endif /* CONFIG_VNC_TLS */

void vnc_display_close(DisplayState *ds)
{
    VncState *vs = ds ? (VncState *)ds->opaque : vnc_state;

    if (vs->display) {
	qemu_free(vs->display);
	vs->display = NULL;
    }
    if (vs->lsock != -1) {
	qemu_set_fd_handler2(vs->lsock, NULL, NULL, NULL, NULL);
	close(vs->lsock);
	vs->lsock = -1;
    }
    if (vs->csock != -1) {
	qemu_set_fd_handler2(vs->csock, NULL, NULL, NULL, NULL);
	closesocket(vs->csock);
	vs->csock = -1;
	buffer_reset(&vs->input);
	buffer_reset(&vs->output);
        free_queue(vs);
        vs->update_requested = 0;
#if CONFIG_VNC_TLS
	if (vs->tls_session) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	}
	vs->wiremode = VNC_WIREMODE_CLEAR;
#endif /* CONFIG_VNC_TLS */
    }
    vs->auth = VNC_AUTH_INVALID;
#if CONFIG_VNC_TLS
    vs->subauth = VNC_AUTH_INVALID;
    vs->x509verify = 0;
#endif
}

int parse_host_port(struct sockaddr_in *saddr, const char *str);



int vnc_display_password(DisplayState *ds, const char *password)
{
    VncState *vs = ds ? (VncState *)ds->opaque : vnc_state;

    if (vs->password) {
	qemu_free(vs->password);
	vs->password = NULL;
    }
    if (password && password[0]) {
	if (!(vs->password = qemu_strdup(password)))
	    return -1;
    }

    return 0;
}

int vnc_display_open(DisplayState *ds, const char *display, int find_unused)
{
    struct sockaddr *addr;
    struct sockaddr_in iaddr;
#ifndef NO_UNIX_SOCKETS
    struct sockaddr_un uaddr;
#endif
#ifndef CONFIG_STUBDOM
    int reuse_addr, ret;
#endif
    socklen_t addrlen;
    const char *p;
    VncState *vs = ds ? (VncState *)ds->opaque : vnc_state;
    const char *options;
    int password = 0;
#if CONFIG_VNC_TLS
    int tls = 0, x509 = 0;
#endif

    if (display == NULL)
	display = "localhost:0";

    vnc_display_close(ds);
    if (strcmp(display, "none") == 0)
        return 0;

    if (!(vs->display = strdup(display)))
        return -1;

    options = display;
    while ((options = strchr(options, ','))) {
	options++;
	if (strncmp(options, "password", 8) == 0) {
	    password = 1; /* Require password auth */
        } else if (strncmp(options, "switchbpp", 9) == 0) {
            ds->switchbpp = 1;
#if CONFIG_VNC_TLS
	} else if (strncmp(options, "tls", 3) == 0) {
	    tls = 1; /* Require TLS */
	} else if (strncmp(options, "x509", 4) == 0) {
	    char *start, *end;
	    x509 = 1; /* Require x509 certificates */
	    if (strncmp(options, "x509verify", 10) == 0)
	        vs->x509verify = 1; /* ...and verify client certs */

	    /* Now check for 'x509=/some/path' postfix
	     * and use that to setup x509 certificate/key paths */
	    start = strchr(options, '=');
	    end = strchr(options, ',');
	    if (start && (!end || (start < end))) {
		int len = end ? end-(start+1) : strlen(start+1);
		char *path = qemu_malloc(len+1);
		strncpy(path, start+1, len);
		path[len] = '\0';
		VNC_DEBUG("Trying certificate path '%s'\n", path);
		if (vnc_set_x509_credential_dir(vs, path) < 0) {
		    fprintf(stderr, "Failed to find x509 certificates/keys in %s\n", path);
		    qemu_free(path);
		    qemu_free(vs->display);
		    vs->display = NULL;
		    return -1;
		}
		qemu_free(path);
	    } else {
		fprintf(stderr, "No certificate path provided\n");
		qemu_free(vs->display);
		vs->display = NULL;
		return -1;
	    }
#endif
	}
    }

    if (password) {
#if CONFIG_VNC_TLS
	if (tls) {
	    vs->auth = VNC_AUTH_VENCRYPT;
	    if (x509) {
		VNC_DEBUG("Initializing VNC server with x509 password auth\n");
		vs->subauth = VNC_AUTH_VENCRYPT_X509VNC;
	    } else {
		VNC_DEBUG("Initializing VNC server with TLS password auth\n");
		vs->subauth = VNC_AUTH_VENCRYPT_TLSVNC;
	    }
	} else {
#endif
	    VNC_DEBUG("Initializing VNC server with password auth\n");
	    vs->auth = VNC_AUTH_VNC;
#if CONFIG_VNC_TLS
	    vs->subauth = VNC_AUTH_INVALID;
	}
#endif
    } else {
#if CONFIG_VNC_TLS
	if (tls) {
	    vs->auth = VNC_AUTH_VENCRYPT;
	    if (x509) {
		VNC_DEBUG("Initializing VNC server with x509 no auth\n");
		vs->subauth = VNC_AUTH_VENCRYPT_X509NONE;
	    } else {
		VNC_DEBUG("Initializing VNC server with TLS no auth\n");
		vs->subauth = VNC_AUTH_VENCRYPT_TLSNONE;
	    }
	} else {
#endif
	    VNC_DEBUG("Initializing VNC server with no auth\n");
	    vs->auth = VNC_AUTH_NONE;
#if CONFIG_VNC_TLS
	    vs->subauth = VNC_AUTH_INVALID;
	}
#endif
    }
#ifndef NO_UNIX_SOCKETS
    if (strstart(display, "unix:", &p)) {
	addr = (struct sockaddr *)&uaddr;
	addrlen = sizeof(uaddr);

	vs->lsock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (vs->lsock == -1) {
	    fprintf(stderr, "Could not create socket\n");
	    free(vs->display);
	    vs->display = NULL;
	    return -1;
	}

	uaddr.sun_family = AF_UNIX;
	memset(uaddr.sun_path, 0, 108);
	snprintf(uaddr.sun_path, 108, "%s", p);

	unlink(uaddr.sun_path);
    } else
#endif
    {
	addr = (struct sockaddr *)&iaddr;
	addrlen = sizeof(iaddr);

	if (parse_host_port(&iaddr, display) < 0) {
	    fprintf(stderr, "Could not parse VNC address\n");
	    free(vs->display);
	    vs->display = NULL;
	    return -1;
	}

#ifdef CONFIG_STUBDOM
        {
            struct ip_addr ipaddr = { iaddr.sin_addr.s_addr };
            struct ip_addr netmask = { 0 };
            struct ip_addr gw = { 0 };
            networking_set_addr(&ipaddr, &netmask, &gw);
        }
#endif

	iaddr.sin_port = htons(ntohs(iaddr.sin_port) + 5900);

	vs->lsock = socket(PF_INET, SOCK_STREAM, 0);
	if (vs->lsock == -1) {
	    fprintf(stderr, "Could not create socket\n");
	    free(vs->display);
	    vs->display = NULL;
	    return -1;
	}

#ifndef CONFIG_STUBDOM
	reuse_addr = 1;
	ret = setsockopt(vs->lsock, SOL_SOCKET, SO_REUSEADDR,
			 (const char *)&reuse_addr, sizeof(reuse_addr));
	if (ret == -1) {
	    fprintf(stderr, "setsockopt() failed\n");
	    close(vs->lsock);
	    vs->lsock = -1;
	    free(vs->display);
	    vs->display = NULL;
	    return -1;
	}
#endif
    }

    while (bind(vs->lsock, addr, addrlen) == -1) {
	if (find_unused && errno == EADDRINUSE) {
	    iaddr.sin_port = htons(ntohs(iaddr.sin_port) + 1);
	    continue;
	}
	fprintf(stderr, "bind() failed\n");
	close(vs->lsock);
	vs->lsock = -1;
	free(vs->display);
	vs->display = NULL;
	return -1;
    }

    if (listen(vs->lsock, 1) == -1) {
	fprintf(stderr, "listen() failed\n");
	close(vs->lsock);
	vs->lsock = -1;
	free(vs->display);
	vs->display = NULL;
	return -1;
    }

    if (qemu_set_fd_handler2(vs->lsock, vnc_listen_poll, vnc_listen_read, NULL, vs) < 0)
	return -1;

    return ntohs(iaddr.sin_port);
}

#ifndef CONFIG_STUBDOM
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
#endif

