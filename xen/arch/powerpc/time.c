/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/time.h>
#include <xen/smp.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/current.h>
#include <asm/debugger.h>

#define Dprintk(x...) printk(x)

static int cpu_has_hdec = 1;
ulong ticks_per_usec;
unsigned long cpu_khz;
unsigned int timebase_freq;

s_time_t get_s_time(void)
{
    return tb_to_ns(get_timebase());
}

static void set_preempt(unsigned ns)
{
    ulong ticks = ns_to_tb(ns);
    if (cpu_has_hdec) {
        mthdec(ticks);
    } else {
        mtdec(ticks);
    }
}

/*
 * set preemption timer  Timeout value is in ticks from start of boot
 * returns 1 on success
 * returns 0 if the timeout value is too small or in the past.
 */
extern int reprogram_timer(s_time_t timeout);
int reprogram_timer(s_time_t timeout)
{
    s_time_t expire;

    if (timeout == 0) {
        expire = INT_MAX;
    } else {
        s_time_t now;

        now = get_s_time();
        expire = timeout - now; /* value from now */

        if (expire <= 0) {
            Dprintk("%s[%02d] Timeout in the past "
                    "0x%08X%08X > 0x%08X%08X\n", __func__,
                    smp_processor_id(), (u32)(now >> 32), 
                    (u32)now, (u32)(timeout >> 32), (u32)timeout);
            return 0;
        }
    }
    set_preempt(expire);
    return 1;
}

void send_timer_event(struct vcpu *v)
{
    v->arch.dec = 1;
    vcpu_unblock(v);
}

void update_vcpu_system_time(struct vcpu *v)
{
}
