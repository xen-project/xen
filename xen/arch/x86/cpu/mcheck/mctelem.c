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
	 * processing of telemetry.
	 *
	 * The two pending lists @lmce_pending and @pending grow at
	 * the head in the reverse chronological order.
	 *
	 * @pending and @lmce_pending on the same CPU are mutually
	 * exclusive, i.e. deferred MCE on a CPU are either all in
	 * @lmce_pending or all in @pending. In the former case, all
	 * deferred MCE are LMCE. In the latter case, both LMCE and
	 * non-local MCE can be in @pending, and @pending contains at
	 * least one non-local MCE if it's not empty.
	 *
	 * Changes to @pending and @lmce_pending should be performed
	 * via mctelem_process_deferred() and mctelem_defer(), in order
	 * to guarantee the above mutual exclusivity.
	 */
	struct mctelem_ent *pending, *lmce_pending;
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

/**
 * Append a telemetry of deferred MCE to a per-cpu pending list,
 * either @pending or @lmce_pending, according to rules below:
 *  - if @pending is not empty, then the new telemetry will be
 *    appended to @pending;
 *  - if @pending is empty and the new telemetry is for a deferred
 *    LMCE, then the new telemetry will be appended to @lmce_pending;
 *  - if @pending is empty and the new telemetry is for a deferred
 *    non-local MCE, all existing telemetries in @lmce_pending will be
 *    moved to @pending and then the new telemetry will be appended to
 *    @pending.
 *
 * This function must be called with MCIP bit set, so that it does not
 * need to worry about MC# re-occurring in this function.
 *
 * As a result, this function can preserve the mutual exclusivity
 * between @pending and @lmce_pending (see their comments in struct
 * mc_telem_cpu_ctl).
 *
 * Parameters:
 *  @cookie: telemetry of the deferred MCE
 *  @lmce:   indicate whether the telemetry is for LMCE
 */
void mctelem_defer(mctelem_cookie_t cookie, bool lmce)
{
	struct mctelem_ent *tep = COOKIE2MCTE(cookie);
	struct mc_telem_cpu_ctl *mctctl = &this_cpu(mctctl);

	ASSERT(mctctl->pending == NULL || mctctl->lmce_pending == NULL);

	if (mctctl->pending)
		mctelem_xchg_head(&mctctl->pending, &tep->mcte_next, tep);
	else if (lmce)
		mctelem_xchg_head(&mctctl->lmce_pending, &tep->mcte_next, tep);
	else {
		/*
		 * LMCE is supported on Skylake-server and later CPUs, on
		 * which mce_broadcast is always true. Therefore, non-empty
		 * mctctl->lmce_pending in this branch implies a broadcasting
		 * MC# is being handled, every CPU is in the exception
		 * context, and no one is consuming mctctl->pending at this
		 * moment. As a result, the following two exchanges together
		 * can be treated as atomic.
		 */
		if (mctctl->lmce_pending)
			mctelem_xchg_head(&mctctl->lmce_pending,
					  &mctctl->pending, NULL);
		mctelem_xchg_head(&mctctl->pending, &tep->mcte_next, tep);
	}
}

/**
 * Move telemetries of deferred MCE from the per-cpu pending list on
 * this or another CPU to the per-cpu processing list on this CPU, and
 * then process all deferred MCE on the processing list.
 *
 * This function can be called with MCIP bit set (e.g. from MC#
 * handler) or cleared (from MCE softirq handler). In the latter case,
 * MC# may re-occur in this function.
 *
 * Parameters:
 *  @cpu:  indicate the CPU where the pending list is
 *  @fn:   the function to handle the deferred MCE
 *  @lmce: indicate which pending list on @cpu is handled
 */
void mctelem_process_deferred(unsigned int cpu,
			      int (*fn)(mctelem_cookie_t),
			      bool lmce)
{
	struct mctelem_ent *tep;
	struct mctelem_ent *head, *prev;
	struct mc_telem_cpu_ctl *mctctl = &per_cpu(mctctl, cpu);
	int ret;

	/*
	 * First, unhook the list of telemetry structures, and
	 * hook it up to the processing list head for this CPU.
	 *
	 * If @lmce is true and a non-local MC# occurs before the
	 * following atomic exchange, @lmce will not hold after
	 * resumption, because all telemetries in @lmce_pending on
	 * @cpu are moved to @pending on @cpu in mcheck_cmn_handler().
	 * In such a case, no telemetries will be handled in this
	 * function after resumption. Another round of MCE softirq,
	 * which was raised by above mcheck_cmn_handler(), will handle
	 * those moved telemetries in @pending on @cpu.
	 *
	 * Any MC# occurring after the following atomic exchange will be
	 * handled by another round of MCE softirq.
	 */
	mctelem_xchg_head(lmce ? &mctctl->lmce_pending : &mctctl->pending,
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

bool mctelem_has_deferred(unsigned int cpu)
{
	if (per_cpu(mctctl.pending, cpu) != NULL)
		return true;
	return false;
}

bool mctelem_has_deferred_lmce(unsigned int cpu)
{
	return per_cpu(mctctl.lmce_pending, cpu) != NULL;
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
	smp_wmb();
	dangling[target] = NULL;
	smp_wmb();
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
	spin_unlock(&processing_lock);
	return MCTE2COOKIE(tep);
}

void mctelem_consume_oldest_end(mctelem_cookie_t cookie)
{
	struct mctelem_ent *tep = COOKIE2MCTE(cookie);

	spin_lock(&processing_lock);
	mctelem_processing_release(tep);
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
	spin_unlock(&processing_lock);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * tab-width: 8
 * End:
 */
