/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: i386/time.c
 *      Author: 
 *     Changes: 
 *              
 *        Date: Jan 2003
 * 
 * Environment: Xen Hypervisor
 * Description: modified version of Linux' time.c
 *              implements system and wall clock time.
 *				based on freebsd's implementation.
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 */
/*
 *  linux/arch/i386/kernel/time.c
 *
 *  Copyright (C) 1991, 1992, 1995  Linus Torvalds
 */

#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/lib.h>
#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/interrupt.h>
#include <xeno/time.h>
#include <xeno/ac_timer.h>

#include <asm/io.h>
#include <xeno/smp.h>
#include <xeno/irq.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/mc146818rtc.h>

#ifdef TIME_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif



unsigned long cpu_khz;	/* Detected as we calibrate the TSC */
unsigned long ticks_per_usec; /* TSC ticks per microsecond. */

spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;

int timer_ack=0;
extern spinlock_t i8259A_lock;
static inline void do_timer_interrupt(int irq, 
                                      void *dev_id, struct pt_regs *regs)
{
#ifdef CONFIG_X86_IO_APIC
    if (timer_ack) {
        /*
         * Subtle, when I/O APICs are used we have to ack timer IRQ
         * manually to reset the IRR bit for do_slow_gettimeoffset().
         * This will also deassert NMI lines for the watchdog if run
         * on an 82489DX-based system.
         */
        spin_lock(&i8259A_lock);
        outb(0x0c, 0x20);
        /* Ack the IRQ; AEOI will end it automatically. */
        inb(0x20);
        spin_unlock(&i8259A_lock);
    }
#endif
    do_timer(regs);
}

/*
 * This is only temporarily. Once the APIC s up and running this 
 * timer interrupt is turned off.
 */
static void timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    do_timer_interrupt(irq, NULL, regs);
}

static struct irqaction irq0  = { timer_interrupt, SA_INTERRUPT, 0,
								  "timer", NULL, NULL};

/* ------ Calibrate the TSC ------- 
 * Return processor ticks per second / CALIBRATE_FRAC.
 */

#define CLOCK_TICK_RATE 1193180 /* system crystal frequency (Hz) */
#define CALIBRATE_FRAC  20      /* calibrate over 50ms */
#define CALIBRATE_LATCH ((CLOCK_TICK_RATE+(CALIBRATE_FRAC/2))/CALIBRATE_FRAC)

static unsigned long __init calibrate_tsc(void)
{
    /* Set the Gate high, disable speaker */
    outb((inb(0x61) & ~0x02) | 0x01, 0x61);

	/*
	 * Now let's take care of CTC channel 2
	 *
	 * Set the Gate high, program CTC channel 2 for mode 0,
	 * (interrupt on terminal count mode), binary count,
	 * load 5 * LATCH count, (LSB and MSB) to begin countdown.
	 */
    outb(0xb0, 0x43);			/* binary, mode 0, LSB/MSB, Ch 2 */
    outb(CALIBRATE_LATCH & 0xff, 0x42);	/* LSB of count */
    outb(CALIBRATE_LATCH >> 8, 0x42);	/* MSB of count */

    {
        unsigned long startlow, starthigh;
        unsigned long endlow, endhigh;
        unsigned long count;

        rdtsc(startlow,starthigh);
        count = 0;
        do {
            count++;
        } while ((inb(0x61) & 0x20) == 0);
        rdtsc(endlow,endhigh);

        /* Error: ECTCNEVERSET */
        if (count <= 1)
            goto bad_ctc;

        /* 64-bit subtract - gcc just messes up with long longs */
        __asm__("subl %2,%0\n\t"
                "sbbl %3,%1"
                :"=a" (endlow), "=d" (endhigh)
                :"g" (startlow), "g" (starthigh),
                "0" (endlow), "1" (endhigh));

        /* Error: ECPUTOOFAST */
        if (endhigh)
            goto bad_ctc;

        return endlow;
    }

    /*
     * The CTC wasn't reliable: we got a hit on the very first read, or the 
     * CPU was so fast/slow that the quotient wouldn't fit in 32 bits..
     */
 bad_ctc:
    return 0;
}

/***************************************************************************
 * CMOS Timer functions
 ***************************************************************************/

/* Converts Gregorian date to seconds since 1970-01-01 00:00:00.
 * Assumes input in normal date format, i.e. 1980-12-31 23:59:59
 * => year=1980, mon=12, day=31, hour=23, min=59, sec=59.
 *
 * [For the Julian calendar (which was used in Russia before 1917,
 * Britain & colonies before 1752, anywhere else before 1582,
 * and is still in use by some communities) leave out the
 * -year/100+year/400 terms, and add 10.]
 *
 * This algorithm was first published by Gauss (I think).
 *
 * WARNING: this function will overflow on 2106-02-07 06:28:16 on
 * machines were long is 32-bit! (However, as time_t is signed, we
 * will already get problems at other places on 2038-01-19 03:14:08)
 */
static inline unsigned long
mktime (unsigned int year, unsigned int mon,
        unsigned int day, unsigned int hour,
        unsigned int min, unsigned int sec)
{
	if (0 >= (int) (mon -= 2)) {    /* 1..12 -> 11,12,1..10 */
		mon += 12;              /* Puts Feb last since it has leap day */
		year -= 1;
	}
	return ((((unsigned long)(year/4 - year/100 + year/400 + 367*mon/12 + day)+
			  year*365 - 719499
        )*24 + hour /* now have hours */
        )*60 + min /* now have minutes */
        )*60 + sec; /* finally seconds */
}

static unsigned long get_cmos_time(void)
{
	unsigned int year, mon, day, hour, min, sec;
	int i;

	spin_lock(&rtc_lock);
	/* The Linux interpretation of the CMOS clock register contents:
	 * When the Update-In-Progress (UIP) flag goes from 1 to 0, the
	 * RTC registers show the second which has precisely just started.
	 * Let's hope other operating systems interpret the RTC the same way.
	 */
	/* read RTC exactly on falling edge of update flag */
	for (i = 0 ; i < 1000000 ; i++)	/* may take up to 1 second... */
		if (CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP)
			break;
	for (i = 0 ; i < 1000000 ; i++)	/* must try at least 2.228 ms */
		if (!(CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP))
			break;
	do { /* Isn't this overkill ? UIP above should guarantee consistency */
		sec = CMOS_READ(RTC_SECONDS);
		min = CMOS_READ(RTC_MINUTES);
		hour = CMOS_READ(RTC_HOURS);
		day = CMOS_READ(RTC_DAY_OF_MONTH);
		mon = CMOS_READ(RTC_MONTH);
		year = CMOS_READ(RTC_YEAR);
	} while (sec != CMOS_READ(RTC_SECONDS));
	if (!(CMOS_READ(RTC_CONTROL) & RTC_DM_BINARY) || RTC_ALWAYS_BCD)
    {
	    BCD_TO_BIN(sec);
	    BCD_TO_BIN(min);
	    BCD_TO_BIN(hour);
	    BCD_TO_BIN(day);
	    BCD_TO_BIN(mon);
	    BCD_TO_BIN(year);
    }
	spin_unlock(&rtc_lock);
	if ((year += 1900) < 1970)
		year += 100;
	printk(".... CMOS Clock:  %02d/%02d/%04d %02d:%02d:%02d\n",
		   day, mon, year, hour, min, sec);
	return mktime(year, mon, day, hour, min, sec);
}

/***************************************************************************
 * Time
 * XXX RN: Will be able to remove some of the locking once the time is
 * update by the APIC on only one CPU. 
 ***************************************************************************/

static spinlock_t stime_lock;
static u32	st_scale_f;
static u32	st_scale_i;
u32			stime_pcc;	 /* cycle counter value at last timer irq */
s_time_t	stime_now;   /* time in ns at last timer IRQ */

s_time_t get_s_time(void)
{
	unsigned long flags;
    u32 	 delta_tsc, low, pcc;
	u64      delta;
	s_time_t now;

	spin_lock_irqsave(&stime_lock, flags);

    pcc = stime_pcc;		
    now = stime_now;

    /* only use bottom 32bits of TSC. This should be sufficient */
	rdtscl(low);
    delta_tsc = low - pcc;
	delta = ((u64)delta_tsc * st_scale_f);
	delta >>= 32;
	delta += ((u64)delta_tsc * st_scale_i);

	spin_unlock_irqrestore(&stime_lock, flags);

    return now + delta; 
}


/* Wall Clock time */
static spinlock_t wctime_lock;
struct timeval    wall_clock_time; /* wall clock time at last update */
s_time_t	      wctime_st;       /* system time at last update */

void do_gettimeofday(struct timeval *tv)
{
	unsigned long flags;
	unsigned long usec, sec;

	spin_lock_irqsave(&wctime_lock, flags);

	usec = ((unsigned long)(NOW() - wctime_st))/1000;
	sec = wall_clock_time.tv_sec;
	usec += wall_clock_time.tv_usec;

	spin_unlock_irqrestore(&wctime_lock, flags);

	while (usec >= 1000000) {
		usec -= 1000000;
		sec++;
	}
	tv->tv_sec = sec;
	tv->tv_usec = usec;
}

void do_settimeofday(struct timeval *tv)
{
	printk("XXX: do_settimeofday not implemented\n");
}

/***************************************************************************
 * Update times
 ***************************************************************************/

/* update a domains notion of time */
void update_dom_time(shared_info_t *si)
{
	unsigned long flags;

	spin_lock_irqsave(&stime_lock, flags);
	si->system_time  = stime_now;
	si->st_timestamp = stime_pcc;
	spin_unlock_irqrestore(&stime_lock, flags);

	spin_lock_irqsave(&wctime_lock, flags);
	si->tv_sec       = wall_clock_time.tv_sec;
	si->tv_usec      = wall_clock_time.tv_usec;
	si->wc_timestamp = wctime_st;
	si->wc_version++;
	spin_unlock_irqrestore(&wctime_lock, flags);	

	TRC(printk(" 0x%08X%08X\n", (u32)(wctime_st>>32), (u32)wctime_st));
}

/*
 * Update hypervisors notion of time
 * This is done periodically of it's own timer
 */
static struct ac_timer update_timer;
static void update_time(unsigned long foo)
{
	unsigned long  flags;
	u32		       new_pcc;
	s_time_t       new_st;
	unsigned long  usec;

	new_st = NOW();
	rdtscl(new_pcc);

	/* Update system time. */
	spin_lock_irqsave(&stime_lock, flags);
	stime_now = new_st;
	stime_pcc=new_pcc;
    /* Don't reeenable IRQs until we release wctime_lock. */
	spin_unlock(&stime_lock);

	/* Update wall clock time. */
	spin_lock(&wctime_lock);
	usec = ((unsigned long)(new_st - wctime_st))/1000;
	usec += wall_clock_time.tv_usec;
	while (usec >= 1000000) {
		usec -= 1000000;
		wall_clock_time.tv_sec++;
	}
	wall_clock_time.tv_usec = usec;
	wctime_st = new_st;
	spin_unlock_irqrestore(&wctime_lock, flags);

	TRC(printk("TIME[%02d] update time: stime_now=%lld now=%lld,wct=%ld:%ld\n",
			   smp_processor_id(), stime_now, new_st, wall_clock_time.tv_sec,
			   wall_clock_time.tv_usec));

	/* Reload the timer. */
 again:
	update_timer.expires  = new_st + MILLISECS(200);
	if(add_ac_timer(&update_timer) == 1) {
		goto again;
	}
}

/***************************************************************************
 * Init Xeno Time
 * This has to be done after all CPUs have been booted
 ***************************************************************************/
int __init init_xeno_time()
{
	int      cpu = smp_processor_id();
	u32	     cpu_cycle;  /* time of one cpu cyle in pico-seconds */
	u64      scale;      /* scale factor  */

	spin_lock_init(&stime_lock);
	spin_lock_init(&wctime_lock);

	printk("Init Time[%02d]:\n", cpu);

	/* System Time */
	cpu_cycle   = (u32) (1000000000LL/cpu_khz); /* in pico seconds */
	scale = 1000000000LL << 32;
	scale /= cpu_freq;
	st_scale_f = scale & 0xffffffff;
	st_scale_i = scale >> 32;

	/* Wall Clock time */
	wall_clock_time.tv_sec  = get_cmos_time();
	wall_clock_time.tv_usec = 0;

	/* set starting times */
	stime_now = (s_time_t)0;
	rdtscl(stime_pcc);
	wctime_st = NOW();

	/* start timer to update time periodically */
	init_ac_timer(&update_timer);
	update_timer.function = &update_time;
	update_time(0);

	printk(".... System Time: %lldns\n", NOW());
	printk(".....cpu_cycle:   %u ps\n",  cpu_cycle);
	printk(".... st_scale_f:  %X\n",     st_scale_f);
	printk(".... st_scale_i:  %X\n",     st_scale_i);
	printk(".... stime_pcc:   %u\n",     stime_pcc);

	printk(".... Wall Clock:  %lds %ldus\n", wall_clock_time.tv_sec,
		   wall_clock_time.tv_usec);
	printk(".... wctime_st:   %lld\n", wctime_st);

	return 0;
}


/***************************************************************************
 * Init
 ***************************************************************************/

void __init time_init(void)
{
    unsigned long ticks_per_frac = calibrate_tsc();

    if ( !ticks_per_frac )
        panic("Error calibrating TSC\n");

    ticks_per_usec = ticks_per_frac / (1000000/CALIBRATE_FRAC);
    cpu_khz = ticks_per_frac / (1000/CALIBRATE_FRAC);

    printk("Detected %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    setup_irq(0, &irq0);
}
