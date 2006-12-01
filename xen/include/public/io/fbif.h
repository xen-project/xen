/*
 * fbif.h -- Xen virtual frame buffer device
 *
 * Copyright (C) 2005 Anthony Liguori <aliguori@us.ibm.com>
 * Copyright (C) 2006 Red Hat, Inc., Markus Armbruster <armbru@redhat.com>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License. See the file COPYING in the main directory of this archive for
 *  more details.
 */

#ifndef __XEN_PUBLIC_IO_FBIF_H__
#define __XEN_PUBLIC_IO_FBIF_H__

#include <asm/types.h>

/* Out events (frontend -> backend) */

/*
 * Out events may be sent only when requested by backend, and receipt
 * of an unknown out event is an error.
 */

/* Event type 1 currently not used */
/*
 * Framebuffer update notification event
 * Capable frontend sets feature-update in xenstore.
 * Backend requests it by setting request-update in xenstore.
 */
#define XENFB_TYPE_UPDATE 2

struct xenfb_update
{
	__u8 type;		/* XENFB_TYPE_UPDATE */
	__s32 x;		/* source x */
	__s32 y;		/* source y */
	__s32 width;		/* rect width */
	__s32 height;		/* rect height */
};

#define XENFB_OUT_EVENT_SIZE 40

union xenfb_out_event
{
	__u8 type;
	struct xenfb_update update;
	char pad[XENFB_OUT_EVENT_SIZE];
};

/* In events (backend -> frontend) */

/*
 * Frontends should ignore unknown in events.
 * No in events currently defined.
 */

#define XENFB_IN_EVENT_SIZE 40

union xenfb_in_event
{
	__u8 type;
	char pad[XENFB_IN_EVENT_SIZE];
};

/* shared page */

#define XENFB_IN_RING_SIZE 1024
#define XENFB_IN_RING_LEN (XENFB_IN_RING_SIZE / XENFB_IN_EVENT_SIZE)
#define XENFB_IN_RING_OFFS 1024
#define XENFB_IN_RING(page) \
    ((union xenfb_in_event *)((char *)(page) + XENFB_IN_RING_OFFS))
#define XENFB_IN_RING_REF(page, idx) \
    (XENFB_IN_RING((page))[(idx) % XENFB_IN_RING_LEN])

#define XENFB_OUT_RING_SIZE 2048
#define XENFB_OUT_RING_LEN (XENFB_OUT_RING_SIZE / XENFB_OUT_EVENT_SIZE)
#define XENFB_OUT_RING_OFFS (XENFB_IN_RING_OFFS + XENFB_IN_RING_SIZE)
#define XENFB_OUT_RING(page) \
    ((union xenfb_out_event *)((char *)(page) + XENFB_OUT_RING_OFFS))
#define XENFB_OUT_RING_REF(page, idx) \
    (XENFB_OUT_RING((page))[(idx) % XENFB_OUT_RING_LEN])

struct xenfb_page
{
	__u32 in_cons, in_prod;
	__u32 out_cons, out_prod;

	__s32 width;         /* the width of the framebuffer (in pixels) */
	__s32 height;        /* the height of the framebuffer (in pixels) */
	__u32 line_length;   /* the length of a row of pixels (in bytes) */
	__u32 mem_length;    /* the length of the framebuffer (in bytes) */
	__u8 depth;          /* the depth of a pixel (in bits) */

	/*
	 * Framebuffer page directory
	 *
	 * Each directory page holds PAGE_SIZE / sizeof(*pd)
	 * framebuffer pages, and can thus map up to PAGE_SIZE *
	 * PAGE_SIZE / sizeof(*pd) bytes.  With PAGE_SIZE == 4096 and
	 * sizeof(unsigned long) == 4, that's 4 Megs.  Two directory
	 * pages should be enough for a while.
	 */
	unsigned long pd[2];
};

/*
 * Wart: xenkbd needs to know resolution.  Put it here until a better
 * solution is found, but don't leak it to the backend.
 */
#ifdef __KERNEL__
#define XENFB_WIDTH 800
#define XENFB_HEIGHT 600
#define XENFB_DEPTH 32
#endif

#endif
