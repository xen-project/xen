/*
 *  linux/kernel/timer.c
 *
 *  Kernel internal timers, kernel timekeeping, basic process system calls
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  1997-01-28  Modified by Finn Arne Gangstad to make timers scale better.
 *
 *  1997-09-10  Updated NTP code according to technical memorandum Jan '96
 *              "A Kernel Model for Precision Timekeeping" by Dave Mills
 *  1998-12-24  Fixed a xtime SMP race (we need the xtime_lock rw spinlock to
 *              serialize accesses to xtime/lost_ticks).
 *                              Copyright (C) 1998  Andrea Arcangeli
 *  1999-03-10  Improved NTP compatibility by Ulrich Windl
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/tqueue.h>
#include <linux/delay.h>
#include <linux/interrupt.h>

#include <xeno/event.h>

#include <asm/uaccess.h>

struct timeval xtime __attribute__ ((aligned (16)));
unsigned long volatile jiffies;

/*
 * Event timer code
 */
#define TVN_BITS 6
#define TVR_BITS 8
#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_MASK (TVN_SIZE - 1)
#define TVR_MASK (TVR_SIZE - 1)

struct timer_vec {
    int index;
    struct list_head vec[TVN_SIZE];
};

struct timer_vec_root {
    int index;
    struct list_head vec[TVR_SIZE];
};

static struct timer_vec tv5;
static struct timer_vec tv4;
static struct timer_vec tv3;
static struct timer_vec tv2;
static struct timer_vec_root tv1;

static struct timer_vec * const tvecs[] = {
    (struct timer_vec *)&tv1, &tv2, &tv3, &tv4, &tv5
};

#define NOOF_TVECS (sizeof(tvecs) / sizeof(tvecs[0]))

void init_timervecs (void)
{
    int i;

    for (i = 0; i < TVN_SIZE; i++) {
        INIT_LIST_HEAD(tv5.vec + i);
        INIT_LIST_HEAD(tv4.vec + i);
        INIT_LIST_HEAD(tv3.vec + i);
        INIT_LIST_HEAD(tv2.vec + i);
    }
    for (i = 0; i < TVR_SIZE; i++)
        INIT_LIST_HEAD(tv1.vec + i);
}

static unsigned long timer_jiffies;

static inline void internal_add_timer(struct timer_list *timer)
{
    /*
     * must be cli-ed when calling this
     */
    unsigned long expires = timer->expires;
    unsigned long idx = expires - timer_jiffies;
    struct list_head * vec;

    if (idx < TVR_SIZE) {
        int i = expires & TVR_MASK;
        vec = tv1.vec + i;
    } else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
        int i = (expires >> TVR_BITS) & TVN_MASK;
        vec = tv2.vec + i;
    } else if (idx < 1 << (TVR_BITS + 2 * TVN_BITS)) {
        int i = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
        vec =  tv3.vec + i;
    } else if (idx < 1 << (TVR_BITS + 3 * TVN_BITS)) {
        int i = (expires >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK;
        vec = tv4.vec + i;
    } else if ((signed long) idx < 0) {
        /* can happen if you add a timer with expires == jiffies,
		 * or you set a timer to go off in the past
		 */
        vec = tv1.vec + tv1.index;
    } else if (idx <= 0xffffffffUL) {
        int i = (expires >> (TVR_BITS + 3 * TVN_BITS)) & TVN_MASK;
        vec = tv5.vec + i;
    } else {
        /* Can only get here on architectures with 64-bit jiffies */
        INIT_LIST_HEAD(&timer->list);
        return;
    }
    /*
	 * Timers are FIFO!
	 */
    list_add(&timer->list, vec->prev);
}

/* Initialize both explicitly - let's try to have them in the same cache line */
spinlock_t timerlist_lock = SPIN_LOCK_UNLOCKED;

#ifdef CONFIG_SMP
volatile struct timer_list * volatile running_timer;
#define timer_enter(t) do { running_timer = t; mb(); } while (0)
#define timer_exit() do { running_timer = NULL; } while (0)
#define timer_is_running(t) (running_timer == t)
#define timer_synchronize(t) while (timer_is_running(t)) barrier()
#else
#define timer_enter(t)		do { } while (0)
#define timer_exit()		do { } while (0)
#endif

void add_timer(struct timer_list *timer)
{
    unsigned long flags;

    spin_lock_irqsave(&timerlist_lock, flags);
    if (timer_pending(timer))
        goto bug;
    internal_add_timer(timer);
    spin_unlock_irqrestore(&timerlist_lock, flags);
    return;
 bug:
    spin_unlock_irqrestore(&timerlist_lock, flags);
    printk("bug: kernel timer added twice at %p.\n",
           __builtin_return_address(0));
}

static inline int detach_timer (struct timer_list *timer)
{
    if (!timer_pending(timer))
        return 0;
    list_del(&timer->list);
    return 1;
}

int mod_timer(struct timer_list *timer, unsigned long expires)
{
    int ret;
    unsigned long flags;

    spin_lock_irqsave(&timerlist_lock, flags);
    timer->expires = expires;
    ret = detach_timer(timer);
    internal_add_timer(timer);
    spin_unlock_irqrestore(&timerlist_lock, flags);
    return ret;
}

int del_timer(struct timer_list * timer)
{
    int ret;
    unsigned long flags;

    spin_lock_irqsave(&timerlist_lock, flags);
    ret = detach_timer(timer);
    timer->list.next = timer->list.prev = NULL;
    spin_unlock_irqrestore(&timerlist_lock, flags);
    return ret;
}

#ifdef CONFIG_SMP
void sync_timers(void)
{
    spin_unlock_wait(&global_bh_lock);
}

/*
 * SMP specific function to delete periodic timer.
 * Caller must disable by some means restarting the timer
 * for new. Upon exit the timer is not queued and handler is not running
 * on any CPU. It returns number of times, which timer was deleted
 * (for reference counting).
 */

int del_timer_sync(struct timer_list * timer)
{
    int ret = 0;

    for (;;) {
        unsigned long flags;
        int running;

        spin_lock_irqsave(&timerlist_lock, flags);
        ret += detach_timer(timer);
        timer->list.next = timer->list.prev = 0;
        running = timer_is_running(timer);
        spin_unlock_irqrestore(&timerlist_lock, flags);

        if (!running)
            break;

        timer_synchronize(timer);
    }

    return ret;
}
#endif


static inline void cascade_timers(struct timer_vec *tv)
{
    /* cascade all the timers from tv up one level */
    struct list_head *head, *curr, *next;

    head = tv->vec + tv->index;
    curr = head->next;
    /*
     * We are removing _all_ timers from the list, so we don't  have to
     * detach them individually, just clear the list afterwards.
	 */
    while (curr != head) {
        struct timer_list *tmp;

        tmp = list_entry(curr, struct timer_list, list);
        next = curr->next;
        list_del(curr); /* not needed */
        internal_add_timer(tmp);
        curr = next;
    }
    INIT_LIST_HEAD(head);
    tv->index = (tv->index + 1) & TVN_MASK;
}

static inline void run_timer_list(void)
{
    spin_lock_irq(&timerlist_lock);
    while ((long)(jiffies - timer_jiffies) >= 0) {
        struct list_head *head, *curr;
        if (!tv1.index) {
            int n = 1;
            do {
                cascade_timers(tvecs[n]);
            } while (tvecs[n]->index == 1 && ++n < NOOF_TVECS);
        }
    repeat:
        head = tv1.vec + tv1.index;
        curr = head->next;
        if (curr != head) {
            struct timer_list *timer;
            void (*fn)(unsigned long);
            unsigned long data;

            timer = list_entry(curr, struct timer_list, list);
            fn = timer->function;
            data= timer->data;

            detach_timer(timer);
            timer->list.next = timer->list.prev = NULL;
            timer_enter(timer);
            spin_unlock_irq(&timerlist_lock);
            fn(data);
            spin_lock_irq(&timerlist_lock);
            timer_exit();
            goto repeat;
        }
        ++timer_jiffies; 
        tv1.index = (tv1.index + 1) & TVR_MASK;
    }
    spin_unlock_irq(&timerlist_lock);
}

spinlock_t tqueue_lock = SPIN_LOCK_UNLOCKED;

static void update_wall_time(unsigned long ticks)
{
    do {
        ticks--;
        xtime.tv_usec += 1000000/HZ;
    } while (ticks);

    if (xtime.tv_usec >= 1000000) {
        xtime.tv_usec -= 1000000;
        xtime.tv_sec++;
    }
}

/* jiffies at the most recent update of wall time */
unsigned long wall_jiffies;

/*
 * This spinlock protect us from races in SMP while playing with xtime. -arca
 */
rwlock_t xtime_lock = RW_LOCK_UNLOCKED;

static inline void update_times(void)
{
    unsigned long ticks;

    /*
     * update_times() is run from the raw timer_bh handler so we
     * just know that the irqs are locally enabled and so we don't
     * need to save/restore the flags of the local CPU here. -arca
     */
    write_lock_irq(&xtime_lock);

    ticks = jiffies - wall_jiffies;
    if (ticks) {
        wall_jiffies += ticks;
        update_wall_time(ticks);
    }
    write_unlock_irq(&xtime_lock);
}

void timer_bh(void)
{
    update_times();
    run_timer_list();
}

void do_timer(struct pt_regs *regs)
{
    (*(unsigned long *)&jiffies)++;
    mark_bh(TIMER_BH);
}
