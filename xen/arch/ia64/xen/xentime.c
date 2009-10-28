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
static s_time_t stime_irq = 0x0;       /* System time at last 'time update' */
static unsigned long itc_scale __read_mostly, ns_scale __read_mostly;
static unsigned long itc_at_irq;

static u32 wc_sec, wc_nsec; /* UTC time at last 'time update'. */
static void ia64_wallclock_set(void);

/* We don't expect an absolute cycle value here, since then no way
 * to prevent overflow for large norminator. Normally this conversion
 * is used for relative offset.
 */
u64 cycle_to_ns(u64 cycle)
{
    return (cycle * itc_scale) >> 32;
}

static u64 ns_to_cycle(u64 ns)
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

void update_vcpu_system_time(struct vcpu *v)
{
    /* N-op here, and let dom0 to manage system time directly */
    return;
}

void
xen_timer_interrupt (int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned long new_itm, old_itc;

	new_itm = local_cpu_data->itm_next;
	while (1) {
		if (smp_processor_id() == TIME_KEEPER_ID) {
			/*
			 * Here we are in the timer irq handler. We have irqs locally
			 * disabled, but we don't know if the timer_bh is running on
			 * another CPU. We need to avoid to SMP race by acquiring the
			 * xtime_lock.
			 */
			write_seqlock(&xtime_lock);
			/* Updates system time (nanoseconds since boot). */
			old_itc = itc_at_irq;
			itc_at_irq = ia64_get_itc();
			stime_irq += cycle_to_ns(itc_at_irq - old_itc);

			write_sequnlock(&xtime_lock);
		}

		local_cpu_data->itm_next = new_itm;

		if (time_after(new_itm, ia64_get_itc())) 
			break;

		new_itm += local_cpu_data->itm_delta;
	}

	if (!is_idle_domain(current->domain) && !VMX_DOMAIN(current)) {
		if (vcpu_timer_expired(current)) {
			vcpu_pend_timer(current);
		} else {
			// ensure another timer interrupt happens
			// even if domain doesn't
			vcpu_set_next_timer(current);
			raise_softirq(TIMER_SOFTIRQ);
			return;
		}
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
}

static struct irqaction __read_mostly xen_timer_irqaction = {
	.handler =	(void *) xen_timer_interrupt,
	.name =		"timer"
};

void __init
ia64_time_init (void)
{
	register_percpu_irq(IA64_TIMER_VECTOR, &xen_timer_irqaction);
	ia64_init_itm();
}

/* wallclock set from efi.get_time */
static void ia64_wallclock_set()
{
    efi_time_t tv;
    efi_time_cap_t tc;
    efi_status_t status = 0;

    status = (*efi.get_time)(&tv, &tc);
    if (status != 0) {
        wc_sec = 0; wc_nsec = 0;
        printk("EFIRTC Get Time failed\n");
        return;
    }

    wc_sec  = mktime(tv.year, tv.month, tv.day, tv.hour, tv.minute, tv.second);
    wc_nsec = tv.nanosecond;
    if (tv.timezone != EFI_UNSPECIFIED_TIMEZONE) {
        wc_sec -= tv.timezone * 60;
        printk("Time Zone is %d minutes difference from UTC\n", tv.timezone);
    } else {
        printk("Time Zone is not specified on EFIRTC\n");
    }
}

/* Late init function (after all CPUs are booted). */
int __init init_xen_time()
{
    ia64_time_init();
    ia64_wallclock_set();
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
	send_guest_vcpu_virq(v, VIRQ_TIMER);
}

/* This is taken from xen/arch/x86/time.c.
 * and the value is replaced 
 * from 1000000000ull to NSEC_PER_SEC.
 */
struct tm wallclock_time(void)
{
    uint64_t seconds;

    if (!wc_sec)
        return (struct tm) { 0 };

    seconds = NOW() + (wc_sec * NSEC_PER_SEC) + wc_nsec;
    do_div(seconds, NSEC_PER_SEC);
    return gmtime(seconds);
}

void get_wallclock(uint64_t *sec, uint64_t *nsec, uint64_t *now)
{
    uint64_t n = NOW();
    uint64_t nano = n + wc_nsec;
    *sec = wc_sec + nano / NSEC_PER_SEC;
    *nsec = nano % NSEC_PER_SEC;
    *now = n;
}
