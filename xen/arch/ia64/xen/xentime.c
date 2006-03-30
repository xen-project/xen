/*
 * xen/arch/ia64/time.c
 *
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <linux/config.h>

#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/efi.h>
#include <linux/profile.h>
#include <linux/timex.h>

#include <asm/machvec.h>
#include <asm/delay.h>
#include <asm/hw_irq.h>
#include <asm/ptrace.h>
#include <asm/sal.h>
#include <asm/sections.h>
#include <asm/system.h>
#include <asm/vcpu.h>
#include <linux/jiffies.h>	// not included by xen/sched.h
#include <xen/softirq.h>
#include <xen/event.h>

/* FIXME: where these declarations should be there ? */
extern void ia64_init_itm(void);

seqlock_t xtime_lock __cacheline_aligned_in_smp = SEQLOCK_UNLOCKED;

#define TIME_KEEPER_ID  0
unsigned long domain0_ready = 0;
static s_time_t        stime_irq = 0x0;       /* System time at last 'time update' */
unsigned long itc_scale, ns_scale;
unsigned long itc_at_irq;

/* We don't expect an absolute cycle value here, since then no way
 * to prevent overflow for large norminator. Normally this conversion
 * is used for relative offset.
 */
u64 cycle_to_ns(u64 cycle)
{
    return (cycle * itc_scale) >> 32;
}

u64 ns_to_cycle(u64 ns)
{
    return (ns * ns_scale) >> 32;
}

static inline u64 get_time_delta(void)
{
    s64      delta_itc;
    u64      cur_itc;
    
    cur_itc = ia64_get_itc();

    delta_itc = (s64)(cur_itc - itc_at_irq);

    /* Ensure that the returned system time is monotonically increasing. */
    if ( unlikely(delta_itc < 0) ) delta_itc = 0;
    return cycle_to_ns(delta_itc);
}


s_time_t get_s_time(void)
{
    s_time_t now;
    unsigned long seq;

    do {
	seq = read_seqbegin(&xtime_lock);
	now = stime_irq + get_time_delta();
    } while (unlikely(read_seqretry(&xtime_lock, seq)));

    return now; 
}

void update_dom_time(struct vcpu *v)
{
    /* N-op here, and let dom0 to manage system time directly */
    return;
}

/* Set clock to <secs,usecs> after 00:00:00 UTC, 1 January, 1970. */
void do_settime(unsigned long secs, unsigned long nsecs, u64 system_time_base)
{
    /* If absolute system time is managed by dom0, there's no need for such
     * action since only virtual itc/itm service is provided.
     */
    return;
}

irqreturn_t
xen_timer_interrupt (int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned long new_itm, old_itc;

#if 0
#define HEARTBEAT_FREQ 16	// period in seconds
#ifdef HEARTBEAT_FREQ
	static long count = 0;
	if (!(++count & ((HEARTBEAT_FREQ*1024)-1))) {
		printf("Heartbeat... iip=%p\n", /*",psr.i=%d,pend=%d\n", */
			regs->cr_iip /*,
			!current->vcpu_info->evtchn_upcall_mask,
			VCPU(current,pending_interruption) */);
		count = 0;
	}
#endif
#endif

	if (!is_idle_domain(current->domain))
		if (vcpu_timer_expired(current)) {
			vcpu_pend_timer(current);
			// ensure another timer interrupt happens even if domain doesn't
			vcpu_set_next_timer(current);
		}

	new_itm = local_cpu_data->itm_next;

	if (!VMX_DOMAIN(current) && !time_after(ia64_get_itc(), new_itm))
		return IRQ_HANDLED;

	while (1) {
		new_itm += local_cpu_data->itm_delta;

		if (smp_processor_id() == TIME_KEEPER_ID) {
			/*
			 * Here we are in the timer irq handler. We have irqs locally
			 * disabled, but we don't know if the timer_bh is running on
			 * another CPU. We need to avoid to SMP race by acquiring the
			 * xtime_lock.
			 */
#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
			write_seqlock(&xtime_lock);
#endif
#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
			do_timer(regs);
#endif
			local_cpu_data->itm_next = new_itm;

		 	/* Updates system time (nanoseconds since boot). */
			old_itc = itc_at_irq;
			itc_at_irq = ia64_get_itc();
			stime_irq += cycle_to_ns(itc_at_irq - old_itc);

#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
			write_sequnlock(&xtime_lock);
#endif
		} else
			local_cpu_data->itm_next = new_itm;

		if (time_after(new_itm, ia64_get_itc()))
			break;
	}

	do {
		/*
		 * If we're too close to the next clock tick for
		 * comfort, we increase the safety margin by
		 * intentionally dropping the next tick(s).  We do NOT
		 * update itm.next because that would force us to call
		 * do_timer() which in turn would let our clock run
		 * too fast (with the potentially devastating effect
		 * of losing monotony of time).
		 */
		while (!time_after(new_itm, ia64_get_itc() + local_cpu_data->itm_delta/2))
			new_itm += local_cpu_data->itm_delta;
		ia64_set_itm(new_itm);
		/* double check, in case we got hit by a (slow) PMI: */
	} while (time_after_eq(ia64_get_itc(), new_itm));
	raise_softirq(TIMER_SOFTIRQ);

	return IRQ_HANDLED;
}

static struct irqaction xen_timer_irqaction = {
	.handler =	(void *) xen_timer_interrupt,
	.name =		"timer"
};

void __init
ia64_time_init (void)
{
	register_percpu_irq(IA64_TIMER_VECTOR, &xen_timer_irqaction);
	ia64_init_itm();
}


/* Late init function (after all CPUs are booted). */
int __init init_xen_time()
{
    ia64_time_init();
    itc_scale  = 1000000000UL << 32 ;
    itc_scale /= local_cpu_data->itc_freq;
    ns_scale = (local_cpu_data->itc_freq << 32) / 1000000000UL;

    /* System time ticks from zero. */
    stime_irq = (s_time_t)0;
    itc_at_irq = ia64_get_itc();

    printk("Time init:\n");
    printk(".... System Time: %ldns\n", NOW());
    printk(".... scale:       %16lX\n", itc_scale);

    return 0;
}

int reprogram_timer(s_time_t timeout)
{
	struct vcpu *v = current;
	s_time_t expire;
	unsigned long seq, cur_itc, itm_next;

	if (!domain0_ready || timeout == 0) return 1;

	do {
		seq = read_seqbegin(&xtime_lock);
		if ((expire = timeout - NOW()) < 0)
			return 0;

		cur_itc = ia64_get_itc();
		itm_next = cur_itc + ns_to_cycle(expire);
	} while (unlikely(read_seqretry(&xtime_lock, seq)));

	local_cpu_data->itm_next = itm_next;
	vcpu_set_next_timer(v);
	return 1;
}

void send_timer_event(struct vcpu *v)
{
	send_guest_virq(v, VIRQ_TIMER);
}

