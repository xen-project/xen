/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef _MCTELEM_H

#define	_MCTELEM_H

#include <xen/init.h>
#include <xen/smp.h>
#include <asm/traps.h>

/* Helper functions used for collecting error telemetry.
 *
 * mctelem_init preallocates a number of data areas for use during
 * machine check data "logout".  Two classes are distinguished -
 * urgent uses, intended for use from machine check exception handlers,
 * and non-urgent uses intended for use from error pollers.
 * Associated with each logout entry of whatever class is a data area
 * sized per the single argument to mctelem_init.  mctelem_init should be
 * called from MCA init code before anybody has the chance to change the
 * machine check vector with mcheck_mca_logout or to use mcheck_mca_logout.
 *
 * To reserve an entry of a given class for use in logout, call
 * mctelem_reserve (or use the common handler functions which do all this
 * for you).  This returns an opaque cookie, or NULL if no elements are
 * available.  Elements are reserved with an atomic operation so no deadlock
 * will occur if, for example, a machine check exception interrupts a
 * scheduled error poll.  The implementation will raid free non-urgent
 * entries if all urgent entries are in use when an urgent request is received.
 * Once an entry is reserved the caller must eventually perform exactly
 * one of two actions: mctelem_commit or mctelem_dismiss.
 *
 * On mctelem_commit the entry is appended to a processing list; mctelem_dismiss
 * frees the element without processing.  After either call the cookie
 * must not be referenced again.
 *
 * To consume committed telemetry call mctelem_consume_oldest_begin
 * which will return a cookie referencing the oldest (first committed)
 * entry of the requested class.  Access the associated data using
 * mctelem_dataptr and when finished use mctelem_consume_oldest_end - in the
 * begin .. end bracket you are guaranteed that the entry can't be freed
 * even if it is ack'd elsewhere).  Once the ultimate consumer of the
 * telemetry has processed it to stable storage it should acknowledge
 * the telemetry quoting the cookie id, at which point we will free
 * the element from the processing list.
 */

typedef struct mctelem_cookie *mctelem_cookie_t;

typedef enum mctelem_class {
	MC_URGENT,
	MC_NONURGENT
} mctelem_class_t;

extern void mctelem_init(unsigned int);
extern mctelem_cookie_t mctelem_reserve(mctelem_class_t);
extern void *mctelem_dataptr(mctelem_cookie_t);
extern void mctelem_commit(mctelem_cookie_t);
extern void mctelem_dismiss(mctelem_cookie_t);
extern mctelem_cookie_t mctelem_consume_oldest_begin(mctelem_class_t);
extern void mctelem_consume_oldest_end(mctelem_cookie_t);
extern void mctelem_ack(mctelem_class_t, mctelem_cookie_t);
extern void mctelem_defer(mctelem_cookie_t);
extern void mctelem_process_deferred(unsigned int,
    int (*)(mctelem_cookie_t));
int mctelem_has_deferred(unsigned int);

#endif
