/*
 * Smp timebase synchronization for ppc.
 *
 * Copyright (C) 2003 Samuel Rydh (samuel@ibrium.se)
 *
 */
/* XXX Xen hacks ... */
#define get_tb() get_timebase()
#define set_tb(u,l) set_timebase(u,l)
#define kmalloc(s,f) xmalloc_bytes(s);
#define kfree(p) xfree(p)
#define abs(x) ({				\
		int __x = (x);			\
		(__x < 0) ? -__x : __x;		\
	})

#include <xen/kernel.h>
#include <xen/sched.h>
#include <xen/smp.h>
#ifndef __XEN__ 
#include <linux/unistd.h>
#endif
#include <xen/init.h>
#include <asm/atomic.h>
#include <asm/smp.h>
#include <asm/time.h>


/* don't mess with IRQs */
#define local_irq_enable()
#define local_irq_disable()

#define NUM_ITER		300

#undef DEBUG
#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
#else
#define DBG(fmt...)
#endif

enum {
	kExit=0, kSetAndTest, kTest
};

static struct {
	volatile u64		tb;
	volatile u64		mark;
	volatile int		cmd;
	volatile int		handshake;
	int			filler[2];

	volatile int		ack;
	int			filler2[7];

	volatile int		race_result;
} *tbsync;

static volatile int		running;

static void __devinit enter_contest(u64 mark, long add)
{
	while (get_tb() < mark)
		tbsync->race_result = add;
}

void __devinit smp_generic_take_timebase(void)
{
	int cmd;
	u64 tb;

	local_irq_disable();
	while (!running)
		barrier();
	rmb();

	for (;;) {
		tbsync->ack = 1;
		while (!tbsync->handshake)
			barrier();
		rmb();

		cmd = tbsync->cmd;
		tb = tbsync->tb;
		mb();
		tbsync->ack = 0;
		if (cmd == kExit)
			break;

		while (tbsync->handshake)
			barrier();
		if (cmd == kSetAndTest)
			set_tb(tb >> 32, tb & 0xfffffffful);
		enter_contest(tbsync->mark, -1);
	}
	local_irq_enable();
}

static int __devinit start_contest(int cmd, long offset, int num)
{
	int i, score=0;
	u64 tb;
	long mark;

	tbsync->cmd = cmd;

	local_irq_disable();
	for (i = -3; i < num; ) {
		tb = get_tb() + 400;
		tbsync->tb = tb + offset;
		tbsync->mark = mark = tb + 400;

		wmb();

		tbsync->handshake = 1;
		while (tbsync->ack)
			barrier();

		while (get_tb() <= tb)
			barrier();
		tbsync->handshake = 0;
		enter_contest(mark, 1);

		while (!tbsync->ack)
			barrier();

		if (i++ > 0)
			score += tbsync->race_result;
	}
	local_irq_enable();
	return score;
}

void __devinit smp_generic_give_timebase(void)
{
	int i, score, score2, old, min=0, max=5000, offset=1000;

	printk("Synchronizing timebase...\n");

	/* if this fails then this kernel won't work anyway... */
	tbsync = kmalloc( sizeof(*tbsync), GFP_KERNEL );
	memset( tbsync, 0, sizeof(*tbsync) );
	mb();
	running = 1;

	while (!tbsync->ack)
		barrier();

	DBG("Got ack\n");

	/* binary search */
	for (old = -1; old != offset ; offset = (min+max) / 2) {
		score = start_contest(kSetAndTest, offset, NUM_ITER);

		DBG("score %d, offset %d\n", score, offset );

		if( score > 0 )
			max = offset;
		else
			min = offset;
		old = offset;
	}
	score = start_contest(kSetAndTest, min, NUM_ITER);
	score2 = start_contest(kSetAndTest, max, NUM_ITER);

	DBG("Min %d (score %d), Max %d (score %d)\n",
	       min, score, max, score2);
	score = abs(score);
	score2 = abs(score2);
	offset = (score < score2) ? min : max;

	/* guard against inaccurate mttb */
	for (i = 0; i < 10; i++) {
		start_contest(kSetAndTest, offset, NUM_ITER/10);

		if ((score2 = start_contest(kTest, offset, NUM_ITER)) < 0)
			score2 = -score2;
		if (score2 <= score || score2 < 20)
			break;
	}
	DBG("Final offset: %d (%d/%d)\n", offset, score2, NUM_ITER );

	/* exiting */
	tbsync->cmd = kExit;
	wmb();
	tbsync->handshake = 1;
	while (tbsync->ack)
		barrier();
	tbsync->handshake = 0;
	kfree(tbsync);
	tbsync = NULL;
	running = 0;
}
