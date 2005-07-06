/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 - Keir Fraser - University of Cambridge 
 * (C) 2005 - Grzegorz Milos - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: time.c
 *      Author: Rolf Neugebauer and Keir Fraser
 *     Changes: Grzegorz Milos
 *
 * Description: Simple time and timer functions
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */


#include <os.h>
#include <traps.h>
#include <types.h>
#include <hypervisor.h>
#include <events.h>
#include <time.h>
#include <lib.h>

/************************************************************************
 * Time functions
 *************************************************************************/

/* Cached *multiplier* to convert TSC counts to microseconds.
 * (see the equation below).
 * Equal to 2^32 * (1 / (clocks per usec) ).
 * Initialized in time_init.
 */
static unsigned long fast_gettimeoffset_quotient;


/* These are peridically updated in shared_info, and then copied here. */
static u32 shadow_tsc_stamp;
static s64 shadow_system_time;
static u32 shadow_time_version;
static struct timeval shadow_tv;

#ifndef rmb
#define rmb()  __asm__ __volatile__ ("lock; addl $0,0(%%esp)": : :"memory")
#endif

#define HANDLE_USEC_OVERFLOW(_tv)          \
    do {                                   \
        while ( (_tv).tv_usec >= 1000000 ) \
        {                                  \
            (_tv).tv_usec -= 1000000;      \
            (_tv).tv_sec++;                \
        }                                  \
    } while ( 0 )

static void get_time_values_from_xen(void)
{
    do {
        shadow_time_version = HYPERVISOR_shared_info->time_version2;
        rmb();
        shadow_tv.tv_sec    = HYPERVISOR_shared_info->wc_sec;
        shadow_tv.tv_usec   = HYPERVISOR_shared_info->wc_usec;
        shadow_tsc_stamp    = (u32)HYPERVISOR_shared_info->tsc_timestamp;
        shadow_system_time  = HYPERVISOR_shared_info->system_time;
        rmb();
    }
    while ( shadow_time_version != HYPERVISOR_shared_info->time_version1 );
}


#define TIME_VALUES_UP_TO_DATE \
    (shadow_time_version == HYPERVISOR_shared_info->time_version2)

static u32  get_time_delta_usecs(void)
{
	register unsigned long eax, edx;

	/* Read the Time Stamp Counter */

	rdtsc(eax,edx);

	/* .. relative to previous jiffy (32 bits is enough) */
	eax -= shadow_tsc_stamp;

	/*
	 * Time offset = (tsc_low delta) * fast_gettimeoffset_quotient
	 *             = (tsc_low delta) * (usecs_per_clock)
	 *             = (tsc_low delta) * (usecs_per_jiffy / clocks_per_jiffy)
	 *
	 * Using a mull instead of a divl saves up to 31 clock cycles
	 * in the critical path.
	 */

	__asm__("mull %2"
		:"=a" (eax), "=d" (edx)
		:"rm" (fast_gettimeoffset_quotient),
		 "0" (eax));

	/* our adjusted time offset in microseconds */
	return edx;
}

s64 get_s_time (void)
{
    u64 u_delta;
    s64 ret;

 again:

    u_delta = get_time_delta_usecs();
    ret = shadow_system_time + (1000 * u_delta);

    if ( unlikely(!TIME_VALUES_UP_TO_DATE) )
    {
        /*
         * We may have blocked for a long time, rendering our calculations
         * invalid (e.g. the time delta may have overflowed). Detect that
         * and recalculate with fresh values.
         */
        get_time_values_from_xen();
        goto again;
    }

    return ret;
}

void gettimeofday(struct timeval *tv)
{
    struct timeval _tv;

    do {
        get_time_values_from_xen();
        _tv.tv_usec = get_time_delta_usecs();
        _tv.tv_sec   = shadow_tv.tv_sec;
        _tv.tv_usec += shadow_tv.tv_usec;
    }
    while ( unlikely(!TIME_VALUES_UP_TO_DATE) );

    HANDLE_USEC_OVERFLOW(_tv);
    *tv = _tv;
}

static void print_current_time(void)
{
    struct timeval tv;

    get_time_values_from_xen();

    gettimeofday(&tv);
    printk("T(s=%ld us=%ld)\n", tv.tv_sec, tv.tv_usec);
}

void block(u32 millisecs)
{
    struct timeval tv;
    gettimeofday(&tv);
    //printk("tv.tv_sec=%ld, tv.tv_usec=%ld, shadow_system_time=%lld\n", tv.tv_sec, tv.tv_usec, shadow_system_time );
    HYPERVISOR_set_timer_op(get_s_time() + 1000000LL * (s64) millisecs);
    HYPERVISOR_block();
}


/*
 * Just a dummy 
 */
static void timer_handler(int ev, struct pt_regs *regs)
{
    static int i;

    get_time_values_from_xen();

    i++;
    if (i >= 1000) {
        print_current_time();
        i = 0;
    }
}



void init_time(void)
{
    u64         __cpu_khz;
    unsigned long cpu_khz;

    __cpu_khz = HYPERVISOR_shared_info->cpu_freq;

    cpu_khz = (u32) (__cpu_khz/1000);

    printk("Xen reported: %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);
	/* (10^6 * 2^32) / cpu_hz = (10^3 * 2^32) / cpu_khz =
	   (2^32 * 1 / (clocks/us)) */
	{	
		unsigned long eax=0, edx=1000;
		__asm__("divl %2"
		    :"=a" (fast_gettimeoffset_quotient), "=d" (edx)
		    :"r" (cpu_khz),
		    "0" (eax), "1" (edx));
	}

    bind_virq(VIRQ_TIMER, &timer_handler);
}
