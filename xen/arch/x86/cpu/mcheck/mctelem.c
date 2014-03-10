/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

/*
 * mctelem.c - x86 Machine Check Telemetry Transport
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/config.h>
#include <xen/smp.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/cpumask.h>
#include <xen/event.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"

struct mctelem_ent {
	struct mctelem_ent *mcte_next;	/* next in chronological order */
	struct mctelem_ent *mcte_prev;	/* previous in chronological order */
	uint32_t mcte_flags;		/* See MCTE_F_* below */
	uint32_t mcte_refcnt;		/* Reference count */
	void *mcte_data;		/* corresponding data payload */
};

#define	MCTE_F_CLASS_URGENT		0x0001U /* in use - urgent errors */
#define	MCTE_F_CLASS_NONURGENT		0x0002U /* in use - nonurgent errors */
#define	MCTE_F_STATE_FREE		0x0010U	/* on a freelist */
#define	MCTE_F_STATE_UNCOMMITTED	0x0020U	/* reserved; on no list */
#define	MCTE_F_STATE_COMMITTED		0x0040U	/* on a committed list */
#define	MCTE_F_STATE_PROCESSING		0x0080U	/* on a processing list */

#define	MCTE_F_MASK_CLASS	(MCTE_F_CLASS_URGENT | MCTE_F_CLASS_NONURGENT)
#define	MCTE_F_MASK_STATE	(MCTE_F_STATE_FREE | \
				MCTE_F_STATE_UNCOMMITTED | \
				MCTE_F_STATE_COMMITTED | \
				MCTE_F_STATE_PROCESSING)

#define	MCTE_CLASS(tep) ((tep)->mcte_flags & MCTE_F_MASK_CLASS)
#define	MCTE_SET_CLASS(tep, new) do { \
    (tep)->mcte_flags &= ~MCTE_F_MASK_CLASS; \
    (tep)->mcte_flags |= MCTE_F_CLASS_##new; } while (0)

#define	MCTE_STATE(tep) ((tep)->mcte_flags & MCTE_F_MASK_STATE)
#define	MCTE_TRANSITION_STATE(tep, old, new) do { \
    BUG_ON(MCTE_STATE(tep) != (MCTE_F_STATE_##old)); \
    (tep)->mcte_flags &= ~MCTE_F_MASK_STATE; \
    (tep)->mcte_flags |= (MCTE_F_STATE_##new); } while (0)

#define	MC_URGENT_NENT		10
#define	MC_NONURGENT_NENT	20

#define MC_NENT (MC_URGENT_NENT + MC_NONURGENT_NENT)

#define	MC_NCLASSES		(MC_NONURGENT + 1)

#define	COOKIE2MCTE(c)		((struct mctelem_ent *)(c))
#define	MCTE2COOKIE(tep)	((mctelem_cookie_t)(tep))

static struct mc_telem_ctl {
	/* Linked lists that thread the array members together.
	 *
	 * The free lists is a bit array where bit 1 means free.
	 * This as element number is quite small and is easy to
	 * atomically allocate that way.
	 *
	 * The committed list grows at the head and we do not maintain a
	 * tail pointer; insertions are performed atomically.  The head
	 * thus has the most-recently committed telemetry, i.e. the
	 * list is in reverse chronological order.  The committed list
	 * is singly-linked via mcte_prev pointers, and mcte_next is NULL.
	 * When we move telemetry from the committed list to the processing
	 * list we atomically unlink the committed list and keep a pointer
	 * to the head of that list;  we then traverse the list following
	 * mcte_prev and fill in mcte_next to doubly-link the list, and then
	 * append the tail of the list onto the processing list.  If we panic
	 * during this manipulation of the committed list we still have
	 * the pointer to its head so we can recover all entries during
	 * the panic flow (albeit in reverse chronological order).
	 *
	 * The processing list is updated in a controlled context, and
	 * we can lock it for updates.  The head of the processing list
	 * always has the oldest telemetry, and we append (as above)
	 * at the tail of the processing list. */
	DECLARE_BITMAP(mctc_free, MC_NENT);
	struct mctelem_ent *mctc_committed[MC_NCLASSES];
	struct mctelem_ent *mctc_processing_head[MC_NCLASSES];
	struct mctelem_ent *mctc_processing_tail[MC_NCLASSES];
	/*
	 * Telemetry array
	 */
	struct mctelem_ent *mctc_elems;
} mctctl;

struct mc_telem_cpu_ctl {
	/*
	 * Per-CPU processing lists, used for deferred (softirq)
	 * processing of telemetry. @pending is indexed by the
	 * CPU that the telemetry belongs to. @processing is indexed
	 * by the CPU that is processing the telemetry.
	 */
	struct mctelem_ent *pending;
	struct mctelem_ent *processing;
};
static DEFINE_PER_CPU(struct mc_telem_cpu_ctl, mctctl);

/* Lock protecting all processing lists */
static DEFINE_SPINLOCK(processing_lock);

static void mctelem_xchg_head(struct mctelem_ent **headp,
				struct mctelem_ent **linkp,
				struct mctelem_ent *new)
{
	for (;;) {
		struct mctelem_ent *old;

		*linkp = old = *headp;
		if (cmpxchgptr(headp, old, new) == old)
			break;
	}
}


void mctelem_defer(mctelem_cookie_t cookie)
{
	struct mctelem_ent *tep = COOKIE2MCTE(cookie);

	mctelem_xchg_head(&this_cpu(mctctl.pending), &tep->mcte_next, tep);
}

void mctelem_process_deferred(unsigned int cpu,
			      int (*fn)(mctelem_cookie_t))
{
	struct mctelem_ent *tep;
	struct mctelem_ent *head, *prev;
	int ret;

	/*
	 * First, unhook the list of telemetry structures, and	
	 * hook it up to the processing list head for this CPU.
	 */
	mctelem_xchg_head(&per_cpu(mctctl.pending, cpu),
			  &this_cpu(mctctl.processing), NULL);

	head = this_cpu(mctctl.processing);

	/*
	 * Then, fix up the list to include prev pointers, to make
	 * things a little easier, as the list must be traversed in
	 * chronological order, which is backward from the order they
	 * are in.
	 */
	for (tep = head, prev = NULL; tep != NULL; tep = tep->mcte_next) {
		tep->mcte_prev = prev;
		prev = tep;
	}

	/*
	 * Now walk the list of telemetry structures, handling each
	 * one of them. Unhooking the structure here does not need to
	 * be atomic, as this list is only accessed from a softirq
	 * context; the MCE handler does not touch it.
	 */
	for (tep = prev; tep != NULL; tep = prev) {
		prev = tep->mcte_prev;
		tep->mcte_next = tep->mcte_prev = NULL;

		ret = fn(MCTE2COOKIE(tep));
		if (prev != NULL)
			prev->mcte_next = NULL;
		tep->mcte_prev = tep->mcte_next = NULL;
		if (ret != 0)
			mctelem_commit(MCTE2COOKIE(tep));
		else
			mctelem_dismiss(MCTE2COOKIE(tep));
	}
}

int mctelem_has_deferred(unsigned int cpu)
{
	if (per_cpu(mctctl.pending, cpu) != NULL)
		return 1;
	return 0;
}

/* Free an entry to its native free list; the entry must not be linked on
 * any list.
 */
static void mctelem_free(struct mctelem_ent *tep)
{
	BUG_ON(tep->mcte_refcnt != 0);
	BUG_ON(MCTE_STATE(tep) != MCTE_F_STATE_FREE);

	tep->mcte_prev = NULL;
	tep->mcte_next = NULL;

	/* set free in array */
	set_bit(tep - mctctl.mctc_elems, mctctl.mctc_free);
}

/* Increment the reference count of an entry that is not linked on to
 * any list and which only the caller has a pointer to.
 */
static void mctelem_hold(struct mctelem_ent *tep)
{
	tep->mcte_refcnt++;
}

/* Increment the reference count on an entry that is linked at the head of
 * a processing list.  The caller is responsible for locking the list.
 */
static void mctelem_processing_hold(struct mctelem_ent *tep)
{
	int which = MCTE_CLASS(tep) == MCTE_F_CLASS_URGENT ?
	    MC_URGENT : MC_NONURGENT;

	BUG_ON(tep != mctctl.mctc_processing_head[which]);
	tep->mcte_refcnt++;
}

/* Decrement the reference count on an entry that is linked at the head of
 * a processing list.  The caller is responsible for locking the list.
 */
static void mctelem_processing_release(struct mctelem_ent *tep)
{
	int which = MCTE_CLASS(tep) == MCTE_F_CLASS_URGENT ?
	    MC_URGENT : MC_NONURGENT;

	BUG_ON(tep != mctctl.mctc_processing_head[which]);
	if (--tep->mcte_refcnt == 0) {
		MCTE_TRANSITION_STATE(tep, PROCESSING, FREE);
		mctctl.mctc_processing_head[which] = tep->mcte_next;
		mctelem_free(tep);
	}
}

void __init mctelem_init(unsigned int datasz)
{
	char *datarr;
	unsigned int i;
	
	BUILD_BUG_ON(MC_URGENT != 0 || MC_NONURGENT != 1 || MC_NCLASSES != 2);

	datasz = (datasz & ~0xf) + 0x10;	/* 16 byte roundup */

	if ((mctctl.mctc_elems = xmalloc_array(struct mctelem_ent,
	    MC_NENT)) == NULL ||
	    (datarr = xmalloc_bytes(MC_NENT * datasz)) == NULL) {
		if (mctctl.mctc_elems)
			xfree(mctctl.mctc_elems);
		printk("Allocations for MCA telemetry failed\n");
		return;
	}

	for (i = 0; i < MC_NENT; i++) {
		struct mctelem_ent *tep;

		tep = mctctl.mctc_elems + i;
		tep->mcte_flags = MCTE_F_STATE_FREE;
		tep->mcte_refcnt = 0;
		tep->mcte_data = datarr + i * datasz;

		__set_bit(i, mctctl.mctc_free);
		tep->mcte_next = NULL;
		tep->mcte_prev = NULL;
	}
}

/* incremented non-atomically when reserve fails */
static int mctelem_drop_count;

/* Reserve a telemetry entry, or return NULL if none available.
 * If we return an entry then the caller must subsequently call exactly one of
 * mctelem_dismiss or mctelem_commit for that entry.
 */
mctelem_cookie_t mctelem_reserve(mctelem_class_t which)
{
	unsigned bit;
	unsigned start_bit = (which == MC_URGENT) ? 0 : MC_URGENT_NENT;

	for (;;) {
		bit = find_next_bit(mctctl.mctc_free, MC_NENT, start_bit);

		if (bit >= MC_NENT) {
			mctelem_drop_count++;
			return (NULL);
		}

		/* try to allocate, atomically clear free bit */
		if (test_and_clear_bit(bit, mctctl.mctc_free)) {
			/* return element we got */
			struct mctelem_ent *tep = mctctl.mctc_elems + bit;

			mctelem_hold(tep);
			MCTE_TRANSITION_STATE(tep, FREE, UNCOMMITTED);
			tep->mcte_next = NULL;
			tep->mcte_prev = NULL;
			if (which == MC_URGENT)
				MCTE_SET_CLASS(tep, URGENT);
			else
				MCTE_SET_CLASS(tep, NONURGENT);
			return MCTE2COOKIE(tep);
		}
	}
}

void *mctelem_dataptr(mctelem_cookie_t cookie)
{
	struct mctelem_ent *tep = COOKIE2MCTE(cookie);

	return tep->mcte_data;
}

/* Release a previously reserved entry back to the freelist without
 * submitting it for logging.  The entry must not be linked on to any
 * list - that's how mctelem_reserve handed it out.
 */
void mctelem_dismiss(mctelem_cookie_t cookie)
{
	struct mctelem_ent *tep = COOKIE2MCTE(cookie);

	tep->mcte_refcnt--;
	MCTE_TRANSITION_STATE(tep, UNCOMMITTED, FREE);
	mctelem_free(tep);
}

/* Commit an entry with completed telemetry for logging.  The caller must
 * not reference the entry after this call.  Note that we add entries
 * at the head of the committed list, so that list therefore has entries
 * in reverse chronological order.
 */
void mctelem_commit(mctelem_cookie_t cookie)
{
	struct mctelem_ent *tep = COOKIE2MCTE(cookie);
	mctelem_class_t target = MCTE_CLASS(tep) == MCTE_F_CLASS_URGENT ?
	    MC_URGENT : MC_NONURGENT;

	BUG_ON(tep->mcte_next != NULL || tep->mcte_prev != NULL);
	MCTE_TRANSITION_STATE(tep, UNCOMMITTED, COMMITTED);

	mctelem_xchg_head(&mctctl.mctc_committed[target], &tep->mcte_prev, tep);
}

/* Move telemetry from committed list to processing list, reversing the
 * list into chronological order.  The processing list has been
 * locked by the caller, and may be non-empty.  We append the
 * reversed committed list on to the tail of the processing list.
 * The committed list may grow even while we run, so use atomic
 * operations to swap NULL to the freelist head.
 *
 * Note that "chronological order" means the order in which producers
 * won additions to the processing list, which may not reflect the
 * strict chronological order of the associated events if events are
 * closely spaced in time and contend for the processing list at once.
 */

static struct mctelem_ent *dangling[MC_NCLASSES];

static void mctelem_append_processing(mctelem_class_t which)
{
	mctelem_class_t target = which == MC_URGENT ?
	    MC_URGENT : MC_NONURGENT;
	struct mctelem_ent **commlp = &mctctl.mctc_committed[target];
	struct mctelem_ent **proclhp = &mctctl.mctc_processing_head[target];
	struct mctelem_ent **procltp = &mctctl.mctc_processing_tail[target];
	struct mctelem_ent *tep, *ltep;

	/* Check for an empty list; no race since we hold the processing lock */
	if (*commlp == NULL)
		return;

	/* Atomically unlink the committed list, and keep a pointer to
	 * the list we unlink in a well-known location so it can be
	 * picked up in panic code should we panic between this unlink
	 * and the append to the processing list. */
	mctelem_xchg_head(commlp, &dangling[target], NULL);

	if (dangling[target] == NULL)
		return;

	/* Traverse the list following the previous pointers (reverse
	 * chronological order).  For each entry fill in the next pointer
	 * and transition the element state.  */
	for (tep = dangling[target], ltep = NULL; tep != NULL;
	    tep = tep->mcte_prev) {
		MCTE_TRANSITION_STATE(tep, COMMITTED, PROCESSING);
		tep->mcte_next = ltep;
		ltep = tep;
	}

	/* ltep points to the head of a chronologically ordered linked
	 * list of telemetry entries ending at the most recent entry
	 * dangling[target] if mcte_next is followed; tack this on to
	 * the processing list.
	 */
	if (*proclhp == NULL) {
		*proclhp = ltep;
		*procltp = dangling[target];
	} else {
		(*procltp)->mcte_next = ltep;
		ltep->mcte_prev = *procltp;
		*procltp = dangling[target];
	}
	wmb();
	dangling[target] = NULL;
	wmb();
}

mctelem_cookie_t mctelem_consume_oldest_begin(mctelem_class_t which)
{
	mctelem_class_t target = (which == MC_URGENT) ?
	    MC_URGENT : MC_NONURGENT;
	struct mctelem_ent *tep;

	spin_lock(&processing_lock);
	mctelem_append_processing(target);
	if ((tep = mctctl.mctc_processing_head[target]) == NULL) {
		spin_unlock(&processing_lock);
		return NULL;
	}

	mctelem_processing_hold(tep);
	wmb();
	spin_unlock(&processing_lock);
	return MCTE2COOKIE(tep);
}

void mctelem_consume_oldest_end(mctelem_cookie_t cookie)
{
	struct mctelem_ent *tep = COOKIE2MCTE(cookie);

	spin_lock(&processing_lock);
	mctelem_processing_release(tep);
	wmb();
	spin_unlock(&processing_lock);
}

void mctelem_ack(mctelem_class_t which, mctelem_cookie_t cookie)
{
	mctelem_class_t target = (which == MC_URGENT) ?
	    MC_URGENT : MC_NONURGENT;
	struct mctelem_ent *tep = COOKIE2MCTE(cookie);

	if (tep == NULL)
		return;

	spin_lock(&processing_lock);
	if (tep == mctctl.mctc_processing_head[target])
		mctelem_processing_release(tep);
	wmb();
	spin_unlock(&processing_lock);
}
