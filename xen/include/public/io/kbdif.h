/*
 * kbdif.h -- Xen virtual keyboard/mouse
 *
 * Copyright (C) 2005 Anthony Liguori <aliguori@us.ibm.com>
 * Copyright (C) 2006 Red Hat, Inc., Markus Armbruster <armbru@redhat.com>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License. See the file COPYING in the main directory of this archive for
 *  more details.
 */

#ifndef __XEN_PUBLIC_IO_KBDIF_H__
#define __XEN_PUBLIC_IO_KBDIF_H__

#include <asm/types.h>

/* In events (backend -> frontend) */

/*
 * Frontends should ignore unknown in events.
 */

/* Pointer movement event */
#define XENKBD_TYPE_MOTION  1
/* Event type 2 currently not used */
/* Key event (includes pointer buttons) */
#define XENKBD_TYPE_KEY     3
/*
 * Pointer position event
 * Capable backend sets feature-abs-pointer in xenstore.
 * Frontend requests ot instead of XENKBD_TYPE_MOTION by setting
 * request-abs-update in xenstore.
 */
#define XENKBD_TYPE_POS     4

struct xenkbd_motion
{
	__u8 type;         /* XENKBD_TYPE_MOTION */
	__s32 rel_x;       /* relative X motion */
	__s32 rel_y;       /* relative Y motion */
};

struct xenkbd_key
{
	__u8 type;         /* XENKBD_TYPE_KEY */
	__u8 pressed;      /* 1 if pressed; 0 otherwise */
	__u32 keycode;     /* KEY_* from linux/input.h */
};

struct xenkbd_position
{
	__u8 type;         /* XENKBD_TYPE_POS */
	__s32 abs_x;       /* absolute X position (in FB pixels) */
	__s32 abs_y;       /* absolute Y position (in FB pixels) */
};

#define XENKBD_IN_EVENT_SIZE 40

union xenkbd_in_event
{
	__u8 type;
	struct xenkbd_motion motion;
	struct xenkbd_key key;
	struct xenkbd_position pos;
	char pad[XENKBD_IN_EVENT_SIZE];
};

/* Out events (frontend -> backend) */

/*
 * Out events may be sent only when requested by backend, and receipt
 * of an unknown out event is an error.
 * No out events currently defined.
 */

#define XENKBD_OUT_EVENT_SIZE 40

union xenkbd_out_event
{
	__u8 type;
	char pad[XENKBD_OUT_EVENT_SIZE];
};

/* shared page */

#define XENKBD_IN_RING_SIZE 2048
#define XENKBD_IN_RING_LEN (XENKBD_IN_RING_SIZE / XENKBD_IN_EVENT_SIZE)
#define XENKBD_IN_RING_OFFS 1024
#define XENKBD_IN_RING(page) \
    ((union xenkbd_in_event *)((char *)(page) + XENKBD_IN_RING_OFFS))
#define XENKBD_IN_RING_REF(page, idx) \
    (XENKBD_IN_RING((page))[(idx) % XENKBD_IN_RING_LEN])

#define XENKBD_OUT_RING_SIZE 1024
#define XENKBD_OUT_RING_LEN (XENKBD_OUT_RING_SIZE / XENKBD_OUT_EVENT_SIZE)
#define XENKBD_OUT_RING_OFFS (XENKBD_IN_RING_OFFS + XENKBD_IN_RING_SIZE)
#define XENKBD_OUT_RING(page) \
    ((union xenkbd_out_event *)((char *)(page) + XENKBD_OUT_RING_OFFS))
#define XENKBD_OUT_RING_REF(page, idx) \
    (XENKBD_OUT_RING((page))[(idx) % XENKBD_OUT_RING_LEN])

struct xenkbd_page
{
	__u32 in_cons, in_prod;
	__u32 out_cons, out_prod;
};

#endif
