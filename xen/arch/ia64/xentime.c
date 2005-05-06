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
#ifdef XEN
#include <linux/jiffies.h>	// not included by xen/sched.h
#endif

#define TIME_KEEPER_ID  0
extern unsigned long wall_jiffies;

static s_time_t        stime_irq;       /* System time at last 'time update' */

unsigned long domain0_ready = 0;

static inline u64 get_time_delta(void)
{
	return ia64_get_itc();
}

s_time_t get_s_time(void)
{
    s_time_t now;
    unsigned long flags;

    read_lock_irqsave(&xtime_lock, flags);

    now = stime_irq + get_time_delta();

    /* Ensure that the returned system time is monotonically increasing. */
    {
        static s_time_t prev_now = 0;
        if ( unlikely(now < prev_now) )
            now = prev_now;
        prev_now = now;
    }

    read_unlock_irqrestore(&xtime_lock, flags);

    return now; 
}

void update_dom_time(struct exec_domain *ed)
{
// FIXME: implement this?
//	printf("update_dom_time: called, not implemented, skipping\n");
	return;
}

/* Set clock to <secs,usecs> after 00:00:00 UTC, 1 January, 1970. */
void do_settime(unsigned long secs, unsigned long usecs, u64 system_time_base)
{
// FIXME: Should this be do_settimeofday (from linux)???
	printf("do_settime: called, not implemented, stopping\n");
	dummy();
}

irqreturn_t
xen_timer_interrupt (int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned long new_itm;

#define HEARTBEAT_FREQ 16	// period in seconds
#ifdef HEARTBEAT_FREQ
	static long count = 0;
	if (!(++count & ((HEARTBEAT_FREQ*1024)-1))) {
		printf("Heartbeat... iip=%p,psr.i=%d,pend=%d\n",
			regs->cr_iip,
			current->vcpu_info->arch.interrupt_delivery_enabled,
			current->vcpu_info->arch.pending_interruption);
		count = 0;
	}
#endif
#ifndef XEN
	if (unlikely(cpu_is_offline(smp_processor_id()))) {
		return IRQ_HANDLED;
	}
#endif
#ifdef XEN
	if (current->domain == dom0) {
		// FIXME: there's gotta be a better way of doing this...
		// We have to ensure that domain0 is launched before we
		// call vcpu_timer_expired on it
		//domain0_ready = 1; // moved to xensetup.c
		current->vcpu_info->arch.pending_interruption = 1;
	}
	if (domain0_ready && vcpu_timer_expired(dom0->exec_domain[0])) {
		vcpu_pend_timer(dom0->exec_domain[0]);
		//vcpu_set_next_timer(dom0->exec_domain[0]);
		domain_wake(dom0->exec_domain[0]);
	}
	if (!is_idle_task(current->domain) && current->domain != dom0) {
		if (vcpu_timer_expired(current)) {
			vcpu_pend_timer(current);
			// ensure another timer interrupt happens even if domain doesn't
			vcpu_set_next_timer(current);
			domain_wake(current);
		}
	}
	raise_actimer_softirq();
#endif

#ifndef XEN
	platform_timer_interrupt(irq, dev_id, regs);
#endif

	new_itm = local_cpu_data->itm_next;

	if (!time_after(ia64_get_itc(), new_itm))
#ifdef XEN
		return;
#else
		printk(KERN_ERR "Oops: timer tick before it's due (itc=%lx,itm=%lx)\n",
		       ia64_get_itc(), new_itm);
#endif

#ifdef XEN
//	printf("GOT TO HERE!!!!!!!!!!!\n");
	//while(1);
#else
	profile_tick(CPU_PROFILING, regs);
#endif

	while (1) {
#ifndef XEN
		update_process_times(user_mode(regs));
#endif

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
//#ifdef XEN
//		vcpu_set_next_timer(current);
//#else
//printf("***** timer_interrupt: Setting itm to %lx\n",new_itm);
		ia64_set_itm(new_itm);
//#endif
		/* double check, in case we got hit by a (slow) PMI: */
	} while (time_after_eq(ia64_get_itc(), new_itm));
	return IRQ_HANDLED;
}

static struct irqaction xen_timer_irqaction = {
	.handler =	xen_timer_interrupt,
#ifndef XEN
	.flags =	SA_INTERRUPT,
#endif
	.name =		"timer"
};

void __init
xen_time_init (void)
{
	register_percpu_irq(IA64_TIMER_VECTOR, &xen_timer_irqaction);
	ia64_init_itm();
}
