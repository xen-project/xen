/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 - Keir Fraser - University of Cambridge 
 ****************************************************************************
 *
 *        File: time.c
 *      Author: Rolf Neugebauer and Keir Fraser
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
#include <types.h>
#include <hypervisor.h>
#include <events.h>
#include <time.h>
#include <lib.h>

/************************************************************************
 * Time functions
 *************************************************************************/

static unsigned int rdtsc_bitshift;
static u32 st_scale_f; /* convert ticks -> usecs */
static u32 st_scale_i; /* convert ticks -> usecs */

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
        shadow_tsc_stamp    = HYPERVISOR_shared_info->tsc_timestamp;
        shadow_system_time  = HYPERVISOR_shared_info->system_time;
        rmb();
    }
    while ( shadow_time_version != HYPERVISOR_shared_info->time_version1 );
}


#define TIME_VALUES_UP_TO_DATE \
    (shadow_time_version == HYPERVISOR_shared_info->time_version2)


static __inline__ unsigned long get_time_delta_usecs(void)
{
    s32      delta_tsc;
    u32      low;
    u64      delta, tsc;

    rdtscll(tsc);
    low = (u32)(tsc >> rdtsc_bitshift);
    delta_tsc = (s32)(low - shadow_tsc_stamp);
    if ( unlikely(delta_tsc < 0) ) delta_tsc = 0;
    delta = ((u64)delta_tsc * st_scale_f);
    delta >>= 32;
    delta += ((u64)delta_tsc * st_scale_i);

    return (unsigned long)delta;
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


/*
 * Just a dummy 
 */
static void timer_handler(int ev, struct pt_regs *regs)
{
    static int i;
    struct timeval tv;

    get_time_values_from_xen();

    i++;
    if (i >= 1000) {
        gettimeofday(&tv);
        printf("T(s=%ld us=%ld)\n", tv.tv_sec, tv.tv_usec);
        i = 0;
    }
}


void init_time(void)
{
    u64         __cpu_khz, cpu_freq, scale;
    unsigned long cpu_khz;

    __cpu_khz = HYPERVISOR_shared_info->cpu_freq;
    cpu_khz = (u32) (__cpu_khz/1000);

    rdtsc_bitshift = HYPERVISOR_shared_info->rdtsc_bitshift;
    cpu_freq       = HYPERVISOR_shared_info->cpu_freq;

    scale = 1000000LL << (32 + rdtsc_bitshift);
    scale /= cpu_freq;

    st_scale_f = scale & 0xffffffff;
    st_scale_i = scale >> 32;

    printk("Xen reported: %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    add_ev_action(EV_TIMER, &timer_handler);
    enable_ev_action(EV_TIMER);
    enable_hypervisor_event(EV_TIMER);

}
