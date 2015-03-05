/*
 * QEMU MC146818 RTC emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <asm/mc146818rtc.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/current.h>

#define USEC_PER_SEC    1000000UL
#define NS_PER_USEC     1000UL
#define NS_PER_SEC      1000000000ULL

#define SEC_PER_MIN     60
#define SEC_PER_HOUR    3600
#define MIN_PER_HOUR    60
#define HOUR_PER_DAY    24

#define domain_vrtc(x) (&(x)->arch.hvm_domain.pl_time.vrtc)
#define vcpu_vrtc(x)   (domain_vrtc((x)->domain))
#define vrtc_domain(x) (container_of((x), struct domain, \
                                     arch.hvm_domain.pl_time.vrtc))
#define vrtc_vcpu(x)   (pt_global_vcpu_target(vrtc_domain(x)))
#define epoch_year     1900
#define get_year(x)    (x + epoch_year)

enum rtc_mode {
   rtc_mode_no_ack,
   rtc_mode_strict
};

/* This must be in sync with how hvmloader sets the ACPI WAET flags. */
#define mode_is(d, m) ((void)(d), rtc_mode_##m == rtc_mode_no_ack)
#define rtc_mode_is(s, m) mode_is(vrtc_domain(s), m)

static void rtc_copy_date(RTCState *s);
static void rtc_set_time(RTCState *s);
static inline int from_bcd(RTCState *s, int a);
static inline int convert_hour(RTCState *s, int hour);

static void rtc_update_irq(RTCState *s)
{
    ASSERT(spin_is_locked(&s->lock));

    if ( rtc_mode_is(s, strict) && (s->hw.cmos_data[RTC_REG_C] & RTC_IRQF) )
        return;

    /* IRQ is raised if any source is both raised & enabled */
    if ( !(s->hw.cmos_data[RTC_REG_B] &
           s->hw.cmos_data[RTC_REG_C] &
           (RTC_PF | RTC_AF | RTC_UF)) )
        return;

    s->hw.cmos_data[RTC_REG_C] |= RTC_IRQF;
    if ( rtc_mode_is(s, no_ack) )
        hvm_isa_irq_deassert(vrtc_domain(s), RTC_IRQ);
    hvm_isa_irq_assert(vrtc_domain(s), RTC_IRQ);
}

/* Called by the VPT code after it's injected a PF interrupt for us.
 * Fix up the register state to reflect what happened. */
static void rtc_pf_callback(struct vcpu *v, void *opaque)
{
    RTCState *s = opaque;

    spin_lock(&s->lock);

    if ( !rtc_mode_is(s, no_ack)
         && (s->hw.cmos_data[RTC_REG_C] & RTC_IRQF)
         && ++(s->pt_dead_ticks) >= 10 )
    {
        /* VM is ignoring its RTC; no point in running the timer */
        destroy_periodic_time(&s->pt);
        s->period = 0;
    }

    s->hw.cmos_data[RTC_REG_C] |= RTC_PF|RTC_IRQF;

    spin_unlock(&s->lock);
}

/* Check whether the REG_C.PF bit should have been set by a tick since
 * the last time we looked. This is used to track ticks when REG_B.PIE
 * is clear; when PIE is set, PF ticks are handled by the VPT callbacks.  */
static void check_for_pf_ticks(RTCState *s)
{
    s_time_t now;

    if ( s->period == 0 || (s->hw.cmos_data[RTC_REG_B] & RTC_PIE) )
        return;

    now = NOW();
    if ( (now - s->start_time) / s->period
         != (s->check_ticks_since - s->start_time) / s->period )
        s->hw.cmos_data[RTC_REG_C] |= RTC_PF;

    s->check_ticks_since = now;
}

/* Enable/configure/disable the periodic timer based on the RTC_PIE and
 * RTC_RATE_SELECT settings */
static void rtc_timer_update(RTCState *s)
{
    int period_code, period, delta;
    struct vcpu *v = vrtc_vcpu(s);

    ASSERT(spin_is_locked(&s->lock));

    s->pt_dead_ticks = 0;

    period_code = s->hw.cmos_data[RTC_REG_A] & RTC_RATE_SELECT;
    switch ( s->hw.cmos_data[RTC_REG_A] & RTC_DIV_CTL )
    {
    case RTC_REF_CLCK_32KHZ:
        if ( (period_code != 0) && (period_code <= 2) )
            period_code += 7;
        /* fall through */
    case RTC_REF_CLCK_1MHZ:
    case RTC_REF_CLCK_4MHZ:
        if ( period_code != 0 )
        {
            period = 1 << (period_code - 1); /* period in 32 Khz cycles */
            period = DIV_ROUND(period * 1000000000ULL, 32768); /* in ns */
            if ( period != s->period )
            {
                s_time_t now = NOW();

                s->period = period;
                if ( v->domain->arch.hvm_domain.params[HVM_PARAM_VPT_ALIGN] )
                    delta = 0;
                else
                    delta = period - ((now - s->start_time) % period);
                if ( s->hw.cmos_data[RTC_REG_B] & RTC_PIE )
                    create_periodic_time(v, &s->pt, delta, period,
                                         RTC_IRQ, rtc_pf_callback, s);
                else
                    s->check_ticks_since = now;
            }
            break;
        }
        /* fall through */
    default:
        destroy_periodic_time(&s->pt);
        s->period = 0;
        break;
    }
}

/* handle update-ended timer */
static void check_update_timer(RTCState *s)
{
    uint64_t next_update_time, expire_time;
    uint64_t guest_usec;
    struct domain *d = vrtc_domain(s);
    stop_timer(&s->update_timer);
    stop_timer(&s->update_timer2);

    ASSERT(spin_is_locked(&s->lock));

    if (!(s->hw.cmos_data[RTC_REG_C] & RTC_UF) &&
            !(s->hw.cmos_data[RTC_REG_B] & RTC_SET))
    {
        s->use_timer = 1;
        guest_usec = get_localtime_us(d) % USEC_PER_SEC;
        if (guest_usec >= (USEC_PER_SEC - 244))
        {
            /* RTC is in update cycle */
            s->hw.cmos_data[RTC_REG_A] |= RTC_UIP;
            next_update_time = (USEC_PER_SEC - guest_usec) * NS_PER_USEC;
            expire_time = NOW() + next_update_time;
            /* release lock before set timer */
            spin_unlock(&s->lock);
            set_timer(&s->update_timer2, expire_time);
            /* fetch lock again */
            spin_lock(&s->lock);
        }
        else
        {
            next_update_time = (USEC_PER_SEC - guest_usec - 244) * NS_PER_USEC;
            expire_time = NOW() + next_update_time;
            s->next_update_time = expire_time;
            /* release lock before set timer */
            spin_unlock(&s->lock);
            set_timer(&s->update_timer, expire_time);
            /* fetch lock again */
            spin_lock(&s->lock);
        }
    }
    else
        s->use_timer = 0;
}

static void rtc_update_timer(void *opaque)
{
    RTCState *s = opaque;

    spin_lock(&s->lock);
    if (!(s->hw.cmos_data[RTC_REG_B] & RTC_SET))
    {
        s->hw.cmos_data[RTC_REG_A] |= RTC_UIP;
        set_timer(&s->update_timer2, s->next_update_time + 244000UL);
    }
    spin_unlock(&s->lock);
}

static void rtc_update_timer2(void *opaque)
{
    RTCState *s = opaque;

    spin_lock(&s->lock);
    if (!(s->hw.cmos_data[RTC_REG_B] & RTC_SET))
    {
        s->hw.cmos_data[RTC_REG_C] |= RTC_UF;
        s->hw.cmos_data[RTC_REG_A] &= ~RTC_UIP;
        rtc_update_irq(s);
        check_update_timer(s);
    }
    spin_unlock(&s->lock);
}

/* handle alarm timer */
static void alarm_timer_update(RTCState *s)
{
    uint64_t next_update_time, next_alarm_sec;
    uint64_t expire_time;
    int32_t alarm_sec, alarm_min, alarm_hour, cur_hour, cur_min, cur_sec;
    int32_t hour, min;
    struct domain *d = vrtc_domain(s);

    ASSERT(spin_is_locked(&s->lock));

    stop_timer(&s->alarm_timer);

    if (!(s->hw.cmos_data[RTC_REG_C] & RTC_AF) &&
            !(s->hw.cmos_data[RTC_REG_B] & RTC_SET))
    {
        s->current_tm = gmtime(get_localtime(d));
        rtc_copy_date(s);

        alarm_sec = from_bcd(s, s->hw.cmos_data[RTC_SECONDS_ALARM]);
        alarm_min = from_bcd(s, s->hw.cmos_data[RTC_MINUTES_ALARM]);
        alarm_hour = convert_hour(s, s->hw.cmos_data[RTC_HOURS_ALARM]);

        cur_sec = from_bcd(s, s->hw.cmos_data[RTC_SECONDS]);
        cur_min = from_bcd(s, s->hw.cmos_data[RTC_MINUTES]);
        cur_hour = convert_hour(s, s->hw.cmos_data[RTC_HOURS]);

        next_update_time = USEC_PER_SEC - (get_localtime_us(d) % USEC_PER_SEC);
        next_update_time = next_update_time * NS_PER_USEC + NOW();

        if ((s->hw.cmos_data[RTC_HOURS_ALARM] & 0xc0) == 0xc0)
        {
            if ((s->hw.cmos_data[RTC_MINUTES_ALARM] & 0xc0) == 0xc0)
            {
                if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                    next_alarm_sec = 1;
                else if (cur_sec < alarm_sec)
                    next_alarm_sec = alarm_sec - cur_sec;
                else
                    next_alarm_sec = alarm_sec + SEC_PER_MIN - cur_sec;
            }
            else
            {
                if (cur_min < alarm_min)
                {
                    min = alarm_min - cur_min;
                    next_alarm_sec = min * SEC_PER_MIN - cur_sec;
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec += 0;
                    else
                        next_alarm_sec += alarm_sec;
                }
                else if (cur_min == alarm_min)
                {
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec = 1;
                    else if (cur_sec < alarm_sec)
                        next_alarm_sec = alarm_sec - cur_sec;
                    else
                    {
                        min = alarm_min + MIN_PER_HOUR - cur_min;
                        next_alarm_sec =
                            alarm_sec + min * SEC_PER_MIN - cur_sec;
                    }
                }
                else
                {
                    min = alarm_min + MIN_PER_HOUR - cur_min;
                    next_alarm_sec = min * SEC_PER_MIN - cur_sec;
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec += 0;
                    else
                        next_alarm_sec += alarm_sec;
                }
            }
        }
        else
        {
            if (cur_hour < alarm_hour)
            {
                hour = alarm_hour - cur_hour;
                next_alarm_sec = hour * SEC_PER_HOUR -
                    cur_min * SEC_PER_MIN - cur_sec;
                if ((s->hw.cmos_data[RTC_MINUTES_ALARM] & 0xc0) == 0xc0)
                {
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec += 0;
                    else
                        next_alarm_sec += alarm_sec;
                }
                else
                {
                    next_alarm_sec += alarm_min * SEC_PER_MIN;
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec += 0;
                    else
                        next_alarm_sec += alarm_sec;
                }
            }
            else if (cur_hour == alarm_hour)
            {
                if ((s->hw.cmos_data[RTC_MINUTES_ALARM] & 0xc0) == 0xc0)
                {
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec = 1;
                    else if (cur_sec < alarm_sec)
                        next_alarm_sec = alarm_sec - cur_sec;
                    else
                        next_alarm_sec = alarm_sec + SEC_PER_MIN - cur_sec;
                }
                else if (cur_min < alarm_min)
                {
                    min = alarm_min - cur_min;
                    next_alarm_sec = min * SEC_PER_MIN - cur_sec;
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec += 0;
                    else
                        next_alarm_sec += alarm_sec;
                }
                else if (cur_min == alarm_min)
                {
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec = 1;
                    else if (cur_sec < alarm_sec)
                        next_alarm_sec = alarm_sec - cur_sec;
                    else
                    {
                        hour = alarm_hour + HOUR_PER_DAY - cur_hour;
                        next_alarm_sec = hour * SEC_PER_HOUR -
                            cur_min * SEC_PER_MIN - cur_sec;
                        next_alarm_sec += alarm_min * SEC_PER_MIN + alarm_sec;
                    }
                }
                else
                {
                    hour = alarm_hour + HOUR_PER_DAY - cur_hour;
                    next_alarm_sec = hour * SEC_PER_HOUR -
                        cur_min * SEC_PER_MIN - cur_sec;
                    next_alarm_sec += alarm_min * SEC_PER_MIN;
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec += 0;
                    else
                        next_alarm_sec += alarm_sec;
                }
            }
            else
            {
                hour = alarm_hour + HOUR_PER_DAY - cur_hour;
                next_alarm_sec = hour * SEC_PER_HOUR -
                    cur_min * SEC_PER_MIN - cur_sec;
                if ((s->hw.cmos_data[RTC_MINUTES_ALARM] & 0xc0) == 0xc0)
                {
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec += 0;
                    else
                        next_alarm_sec += alarm_sec;
                }
                else
                {
                    next_alarm_sec += alarm_min * SEC_PER_MIN;
                    if ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0)
                        next_alarm_sec += 0;
                    else
                        next_alarm_sec += alarm_sec;
                }
            }
        }
        expire_time = (next_alarm_sec - 1) * NS_PER_SEC + next_update_time;
        /* release lock before set timer */
        spin_unlock(&s->lock);
        set_timer(&s->alarm_timer, expire_time);
        /* fetch lock again */
        spin_lock(&s->lock);
    }
}

static void rtc_alarm_cb(void *opaque)
{
    RTCState *s = opaque;

    spin_lock(&s->lock);
    if (!(s->hw.cmos_data[RTC_REG_B] & RTC_SET))
    {
        s->hw.cmos_data[RTC_REG_C] |= RTC_AF;
        rtc_update_irq(s);
        alarm_timer_update(s);
    }
    spin_unlock(&s->lock);
}

static int rtc_ioport_write(void *opaque, uint32_t addr, uint32_t data)
{
    RTCState *s = opaque;
    struct domain *d = vrtc_domain(s);
    uint32_t orig;

    spin_lock(&s->lock);

    if ( (addr & 1) == 0 )
    {
        data &= 0x7f;
        s->hw.cmos_index = data;
        spin_unlock(&s->lock);
        return (data < RTC_CMOS_SIZE);
    }

    if ( s->hw.cmos_index >= RTC_CMOS_SIZE )
    {
        spin_unlock(&s->lock);
        return 0;
    }

    orig = s->hw.cmos_data[s->hw.cmos_index];
    switch ( s->hw.cmos_index )
    {
    case RTC_SECONDS_ALARM:
    case RTC_MINUTES_ALARM:
    case RTC_HOURS_ALARM:
        s->hw.cmos_data[s->hw.cmos_index] = data;
        alarm_timer_update(s);
        break;
    case RTC_SECONDS:
    case RTC_MINUTES:
    case RTC_HOURS:
    case RTC_DAY_OF_WEEK:
    case RTC_DAY_OF_MONTH:
    case RTC_MONTH:
    case RTC_YEAR:
        /* if in set mode, just write the register */
        if ( (s->hw.cmos_data[RTC_REG_B] & RTC_SET) )
            s->hw.cmos_data[s->hw.cmos_index] = data;
        else
        {
            /* Fetch the current time and update just this field. */
            s->current_tm = gmtime(get_localtime(d));
            rtc_copy_date(s);
            s->hw.cmos_data[s->hw.cmos_index] = data;
            rtc_set_time(s);
        }
        alarm_timer_update(s);
        break;
    case RTC_REG_A:
        /* UIP bit is read only */
        s->hw.cmos_data[RTC_REG_A] = (data & ~RTC_UIP) | (orig & RTC_UIP);
        if ( (data ^ orig) & ~RTC_UIP )
            rtc_timer_update(s);
        break;
    case RTC_REG_B:
        if ( data & RTC_SET )
        {
            /* set mode: reset UIP mode */
            s->hw.cmos_data[RTC_REG_A] &= ~RTC_UIP;
            /* adjust cmos before stopping */
            if (!(orig & RTC_SET))
            {
                s->current_tm = gmtime(get_localtime(d));
                rtc_copy_date(s);
            }
        }
        else
        {
            /* if disabling set mode, update the time */
            if ( orig & RTC_SET )
                rtc_set_time(s);
        }
        check_for_pf_ticks(s);
        s->hw.cmos_data[RTC_REG_B] = data;
        /*
         * If the interrupt is already set when the interrupt becomes
         * enabled, raise an interrupt immediately.
         */
        rtc_update_irq(s);
        if ( (data ^ orig) & RTC_PIE )
        {
            destroy_periodic_time(&s->pt);
            s->period = 0;
            rtc_timer_update(s);
        }
        if ( (data ^ orig) & RTC_SET )
            check_update_timer(s);
        if ( (data ^ orig) & (RTC_24H | RTC_DM_BINARY | RTC_SET) )
            alarm_timer_update(s);
        break;
    case RTC_REG_C:
    case RTC_REG_D:
        /* cannot write to them */
        break;
    }

    spin_unlock(&s->lock);

    return 1;
}

static inline int to_bcd(RTCState *s, int a)
{
    if ( s->hw.cmos_data[RTC_REG_B] & RTC_DM_BINARY )
        return a;
    else
        return ((a / 10) << 4) | (a % 10);
}

static inline int from_bcd(RTCState *s, int a)
{
    if ( s->hw.cmos_data[RTC_REG_B] & RTC_DM_BINARY )
        return a;
    else
        return ((a >> 4) * 10) + (a & 0x0f);
}

/* Hours in 12 hour mode are in 1-12 range, not 0-11.
 * So we need convert it before using it*/
static inline int convert_hour(RTCState *s, int raw)
{
    int hour = from_bcd(s, raw & 0x7f);

    if (!(s->hw.cmos_data[RTC_REG_B] & RTC_24H))
    {
        hour %= 12;
        if (raw & 0x80)
            hour += 12;
    }
    return hour;
}

static void rtc_set_time(RTCState *s)
{
    struct tm *tm = &s->current_tm;
    struct domain *d = vrtc_domain(s);
    unsigned long before, after; /* XXX s_time_t */
      
    ASSERT(spin_is_locked(&s->lock));

    before = mktime(get_year(tm->tm_year), tm->tm_mon + 1, tm->tm_mday,
		    tm->tm_hour, tm->tm_min, tm->tm_sec);
    
    tm->tm_sec = from_bcd(s, s->hw.cmos_data[RTC_SECONDS]);
    tm->tm_min = from_bcd(s, s->hw.cmos_data[RTC_MINUTES]);
    tm->tm_hour = convert_hour(s, s->hw.cmos_data[RTC_HOURS]);
    tm->tm_wday = from_bcd(s, s->hw.cmos_data[RTC_DAY_OF_WEEK]);
    tm->tm_mday = from_bcd(s, s->hw.cmos_data[RTC_DAY_OF_MONTH]);
    tm->tm_mon = from_bcd(s, s->hw.cmos_data[RTC_MONTH]) - 1;
    tm->tm_year = from_bcd(s, s->hw.cmos_data[RTC_YEAR]) + 100;

    after = mktime(get_year(tm->tm_year), tm->tm_mon + 1, tm->tm_mday,
                   tm->tm_hour, tm->tm_min, tm->tm_sec);

    /* We use the guest's setting of the RTC to define the local-time 
     * offset for this domain. */
    d->time_offset_seconds += (after - before);
    update_domain_wallclock_time(d);
    /* Also tell qemu-dm about it so it will be remembered for next boot. */
    send_timeoffset_req(after - before);
}

static void rtc_copy_date(RTCState *s)
{
    const struct tm *tm = &s->current_tm;

    ASSERT(spin_is_locked(&s->lock));

    s->hw.cmos_data[RTC_SECONDS] = to_bcd(s, tm->tm_sec);
    s->hw.cmos_data[RTC_MINUTES] = to_bcd(s, tm->tm_min);
    if ( s->hw.cmos_data[RTC_REG_B] & RTC_24H )
    {
        /* 24 hour format */
        s->hw.cmos_data[RTC_HOURS] = to_bcd(s, tm->tm_hour);
    }
    else
    {
        /* 12 hour format */
        int h = (tm->tm_hour % 12) ? tm->tm_hour % 12 : 12;
        s->hw.cmos_data[RTC_HOURS] = to_bcd(s, h);
        if ( tm->tm_hour >= 12 )
            s->hw.cmos_data[RTC_HOURS] |= 0x80;
    }
    s->hw.cmos_data[RTC_DAY_OF_WEEK] = to_bcd(s, tm->tm_wday);
    s->hw.cmos_data[RTC_DAY_OF_MONTH] = to_bcd(s, tm->tm_mday);
    s->hw.cmos_data[RTC_MONTH] = to_bcd(s, tm->tm_mon + 1);
    s->hw.cmos_data[RTC_YEAR] = to_bcd(s, tm->tm_year % 100);
}

static int update_in_progress(RTCState *s)
{
    uint64_t guest_usec;
    struct domain *d = vrtc_domain(s);

    if (s->hw.cmos_data[RTC_REG_B] & RTC_SET)
        return 0;

    guest_usec = get_localtime_us(d);
    /* UIP bit will be set at last 244us of every second. */
    if ((guest_usec % USEC_PER_SEC) >= (USEC_PER_SEC - 244))
        return 1;

    return 0;
}

static uint32_t rtc_ioport_read(RTCState *s, uint32_t addr)
{
    int ret;
    struct domain *d = vrtc_domain(s);

    if ( (addr & 1) == 0 )
        return 0xff;

    spin_lock(&s->lock);

    switch ( s->hw.cmos_index )
    {
    case RTC_SECONDS:
    case RTC_MINUTES:
    case RTC_HOURS:
    case RTC_DAY_OF_WEEK:
    case RTC_DAY_OF_MONTH:
    case RTC_MONTH:
    case RTC_YEAR:
        /* if not in set mode, adjust cmos before reading*/
        if (!(s->hw.cmos_data[RTC_REG_B] & RTC_SET))
        {
            s->current_tm = gmtime(get_localtime(d));
            rtc_copy_date(s);
        }
        ret = s->hw.cmos_data[s->hw.cmos_index];
        break;
    case RTC_REG_A:
        ret = s->hw.cmos_data[s->hw.cmos_index];
        if ((s->use_timer == 0) && update_in_progress(s))
            ret |= RTC_UIP;
        break;
    case RTC_REG_C:
        check_for_pf_ticks(s);
        ret = s->hw.cmos_data[s->hw.cmos_index];
        s->hw.cmos_data[RTC_REG_C] = 0x00;
        if ( ret & RTC_IRQF )
            hvm_isa_irq_deassert(d, RTC_IRQ);
        check_update_timer(s);
        alarm_timer_update(s);
        s->pt_dead_ticks = 0;
        break;
    default:
        ret = s->hw.cmos_data[s->hw.cmos_index];
        break;
    }

    spin_unlock(&s->lock);

    return ret;
}

static int handle_rtc_io(
    int dir, uint32_t port, uint32_t bytes, uint32_t *val)
{
    struct RTCState *vrtc = vcpu_vrtc(current);

    if ( bytes != 1 )
    {
        gdprintk(XENLOG_WARNING, "HVM_RTC bad access\n");
        *val = ~0;
        return X86EMUL_OKAY;
    }
    
    if ( dir == IOREQ_WRITE )
    {
        if ( rtc_ioport_write(vrtc, port, (uint8_t)*val) )
            return X86EMUL_OKAY;
    }
    else if ( vrtc->hw.cmos_index < RTC_CMOS_SIZE )
    {
        *val = rtc_ioport_read(vrtc, port);
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

void rtc_migrate_timers(struct vcpu *v)
{
    RTCState *s = vcpu_vrtc(v);

    if ( v->vcpu_id == 0 )
    {
        migrate_timer(&s->update_timer, v->processor);;
        migrate_timer(&s->update_timer2, v->processor);;
        migrate_timer(&s->alarm_timer, v->processor);;
    }
}

/* Save RTC hardware state */
static int rtc_save(struct domain *d, hvm_domain_context_t *h)
{
    RTCState *s = domain_vrtc(d);
    int rc;
    spin_lock(&s->lock);
    rc = hvm_save_entry(RTC, 0, h, &s->hw);
    spin_unlock(&s->lock);
    return rc;
}

/* Reload the hardware state from a saved domain */
static int rtc_load(struct domain *d, hvm_domain_context_t *h)
{
    RTCState *s = domain_vrtc(d);

    spin_lock(&s->lock);

    /* Restore the registers */
    if ( hvm_load_entry(RTC, h, &s->hw) != 0 )
    {
        spin_unlock(&s->lock);
        return -EINVAL;
    }

    /* Reset the wall-clock time.  In normal running, this runs with host 
     * time, so let's keep doing that. */
    s->current_tm = gmtime(get_localtime(d));
    rtc_copy_date(s);

    /* Reset the periodic interrupt timer based on the registers */
    rtc_timer_update(s);
    check_update_timer(s);
    alarm_timer_update(s);

    spin_unlock(&s->lock);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(RTC, rtc_save, rtc_load, 1, HVMSR_PER_DOM);

void rtc_reset(struct domain *d)
{
    RTCState *s = domain_vrtc(d);

    destroy_periodic_time(&s->pt);
    s->period = 0;
    s->pt.source = PTSRC_isa;
}

void rtc_init(struct domain *d)
{
    RTCState *s = domain_vrtc(d);

    spin_lock_init(&s->lock);

    init_timer(&s->update_timer, rtc_update_timer, s, smp_processor_id());
    init_timer(&s->update_timer2, rtc_update_timer2, s, smp_processor_id());
    init_timer(&s->alarm_timer, rtc_alarm_cb, s, smp_processor_id());

    register_portio_handler(d, RTC_PORT(0), 2, handle_rtc_io);

    rtc_reset(d);

    spin_lock(&s->lock);

    s->hw.cmos_data[RTC_REG_A] = RTC_REF_CLCK_32KHZ | 6; /* ~1kHz */
    s->hw.cmos_data[RTC_REG_B] = RTC_24H;
    s->hw.cmos_data[RTC_REG_C] = 0;
    s->hw.cmos_data[RTC_REG_D] = RTC_VRT;

    s->current_tm = gmtime(get_localtime(d));
    s->start_time = NOW();

    rtc_copy_date(s);

    check_update_timer(s);
    spin_unlock(&s->lock);
}

void rtc_deinit(struct domain *d)
{
    RTCState *s = domain_vrtc(d);

    spin_barrier(&s->lock);

    destroy_periodic_time(&s->pt);
    kill_timer(&s->update_timer);
    kill_timer(&s->update_timer2);
    kill_timer(&s->alarm_timer);
}

void rtc_update_clock(struct domain *d)
{
    RTCState *s = domain_vrtc(d);

    spin_lock(&s->lock);
    s->current_tm = gmtime(get_localtime(d));
    spin_unlock(&s->lock);
}
