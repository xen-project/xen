/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: time.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Jul 2003
 * 
 * Environment: Xen Minimal OS
 * Description: Simple time and timer functions
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
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
static u32      st_scale_f;
static u32      st_scale_i;
static u32      shadow_st_pcc;
static s_time_t shadow_st;
static u32      shadow_wc_version=0;
static long     shadow_tv_sec;
static long     shadow_tv_usec;
static s_time_t shadow_wc_timestamp;

/*
 * System time.
 * We need to read the values from the shared info page "atomically" 
 * and use the cycle counter value as the "version" number. Clashes
 * should be very rare.
 */
inline s_time_t get_s_time(void)
{
    s32 delta_tsc;
    u32 low;
    u64 delta, tsc;
    u32	version;
    u64 cpu_freq, scale;

    /* check if our values are still up-to-date */
    while ( (version = HYPERVISOR_shared_info->wc_version) != 
            shadow_wc_version )
    {
        barrier();

        shadow_wc_version   = version;
        shadow_tv_sec       = HYPERVISOR_shared_info->tv_sec;
        shadow_tv_usec      = HYPERVISOR_shared_info->tv_usec;
        shadow_wc_timestamp = HYPERVISOR_shared_info->wc_timestamp;
        shadow_st_pcc       = HYPERVISOR_shared_info->st_timestamp;
        shadow_st           = HYPERVISOR_shared_info->system_time;

        rdtsc_bitshift      = HYPERVISOR_shared_info->rdtsc_bitshift;
        cpu_freq            = HYPERVISOR_shared_info->cpu_freq;

        /* XXX cpu_freq as u32 limits it to 4.29 GHz. Get a better do_div! */
        scale = 1000000000LL << (32 + rdtsc_bitshift);
        scale /= cpu_freq;
        st_scale_f = scale & 0xffffffff;
        st_scale_i = scale >> 32;

        barrier();
	}

    rdtscll(tsc);
    low = (u32)(tsc >> rdtsc_bitshift);
    delta_tsc = (s32)(low - shadow_st_pcc);
    if ( unlikely(delta_tsc < 0) ) delta_tsc = 0;
    delta = ((u64)delta_tsc * st_scale_f);
    delta >>= 32;
    delta += ((u64)delta_tsc * st_scale_i);

    return shadow_st + delta;
}


/*
 * Wallclock time.
 * Based on what the hypervisor tells us, extrapolated using system time.
 * Again need to read a number of values from the shared page "atomically".
 * this time using a version number.
 */
void gettimeofday(struct timeval *tv)
{
    long          usec, sec;
    u64           now;

    now   = get_s_time();
    usec  = ((unsigned long)(now-shadow_wc_timestamp))/1000;
    sec   = shadow_tv_sec;
    usec += shadow_tv_usec;

    while ( usec >= 1000000 ) 
    {
        usec -= 1000000;
        sec++;
    }

    tv->tv_sec = sec;
    tv->tv_usec = usec;
}


static void timer_handler(int ev, struct pt_regs *regs)
{
    static int i;
    s_time_t now;

    i++;
    if (i >= 1000) {
        now = get_s_time();
        printf("T(%lld)\n", now);
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

    add_ev_action(EV_TIMER, &timer_handler);
    enable_ev_action(EV_TIMER);
    enable_hypervisor_event(EV_TIMER);

}
