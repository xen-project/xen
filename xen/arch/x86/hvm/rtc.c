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

#define domain_vrtc(x) (&(x)->arch.hvm_domain.pl_time.vrtc)
#define vcpu_vrtc(x)   (domain_vrtc((x)->domain))
#define vrtc_domain(x) (container_of((x), struct domain, \
                                     arch.hvm_domain.pl_time.vrtc))
#define vrtc_vcpu(x)   (pt_global_vcpu_target(vrtc_domain(x)))
#define epoch_year     1900
#define get_year(x)    (x + epoch_year)

static void rtc_copy_date(RTCState *s);

static void rtc_periodic_cb(struct vcpu *v, void *opaque)
{
    RTCState *s = opaque;
    spin_lock(&s->lock);
    s->hw.cmos_data[RTC_REG_C] |= 0xc0;
    spin_unlock(&s->lock);
}

/* Enable/configure/disable the periodic timer based on the RTC_PIE and
 * RTC_RATE_SELECT settings */
static void rtc_timer_update(RTCState *s)
{
    int period_code, period;
    struct vcpu *v = vrtc_vcpu(s);

    ASSERT(spin_is_locked(&s->lock));

    period_code = s->hw.cmos_data[RTC_REG_A] & RTC_RATE_SELECT;
    if ( (period_code != 0) && (s->hw.cmos_data[RTC_REG_B] & RTC_PIE) )
    {
        if ( period_code <= 2 )
            period_code += 7;

        period = 1 << (period_code - 1); /* period in 32 Khz cycles */
        period = DIV_ROUND((period * 1000000000ULL), 32768); /* period in ns */
        create_periodic_time(v, &s->pt, period, period, RTC_IRQ,
                             rtc_periodic_cb, s);
    }
    else
    {
        destroy_periodic_time(&s->pt);
    }
}

static void rtc_set_time(RTCState *s);

static int rtc_ioport_write(void *opaque, uint32_t addr, uint32_t data)
{
    RTCState *s = opaque;
    struct domain *d = vrtc_domain(s);

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

    switch ( s->hw.cmos_index )
    {
    case RTC_SECONDS_ALARM:
    case RTC_MINUTES_ALARM:
    case RTC_HOURS_ALARM:
        s->hw.cmos_data[s->hw.cmos_index] = data;
        break;
    case RTC_SECONDS:
    case RTC_MINUTES:
    case RTC_HOURS:
    case RTC_DAY_OF_WEEK:
    case RTC_DAY_OF_MONTH:
    case RTC_MONTH:
    case RTC_YEAR:
        s->hw.cmos_data[s->hw.cmos_index] = data;
        /* if in set mode, do not update the time */
        if ( !(s->hw.cmos_data[RTC_REG_B] & RTC_SET) )
            rtc_set_time(s);
        break;
    case RTC_REG_A:
        /* UIP bit is read only */
        s->hw.cmos_data[RTC_REG_A] = (data & ~RTC_UIP) |
            (s->hw.cmos_data[RTC_REG_A] & RTC_UIP);
        rtc_timer_update(s);
        break;
    case RTC_REG_B:
        if ( data & RTC_SET )
        {
            /* set mode: reset UIP mode */
            s->hw.cmos_data[RTC_REG_A] &= ~RTC_UIP;
            /* adjust cmos before stopping */
            if (!(s->hw.cmos_data[RTC_REG_B] & RTC_SET))
            {
                s->current_tm = gmtime(get_localtime(d));
                rtc_copy_date(s);
            }
        }
        else
        {
            /* if disabling set mode, update the time */
            if ( s->hw.cmos_data[RTC_REG_B] & RTC_SET )
                rtc_set_time(s);
        }
        s->hw.cmos_data[RTC_REG_B] = data;
        rtc_timer_update(s);
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
    if ( s->hw.cmos_data[RTC_REG_B] & 0x04 )
        return a;
    else
        return ((a / 10) << 4) | (a % 10);
}

static inline int from_bcd(RTCState *s, int a)
{
    if ( s->hw.cmos_data[RTC_REG_B] & 0x04 )
        return a;
    else
        return ((a >> 4) * 10) + (a & 0x0f);
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
    tm->tm_hour = from_bcd(s, s->hw.cmos_data[RTC_HOURS] & 0x7f);
    if ( !(s->hw.cmos_data[RTC_REG_B] & 0x02) &&
         (s->hw.cmos_data[RTC_HOURS] & 0x80) )
        tm->tm_hour += 12;
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
        s->hw.cmos_data[RTC_HOURS] = to_bcd(s, tm->tm_hour % 12);
        if ( tm->tm_hour >= 12 )
            s->hw.cmos_data[RTC_HOURS] |= 0x80;
    }
    s->hw.cmos_data[RTC_DAY_OF_WEEK] = to_bcd(s, tm->tm_wday);
    s->hw.cmos_data[RTC_DAY_OF_MONTH] = to_bcd(s, tm->tm_mday);
    s->hw.cmos_data[RTC_MONTH] = to_bcd(s, tm->tm_mon + 1);
    s->hw.cmos_data[RTC_YEAR] = to_bcd(s, tm->tm_year % 100);
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
        break;
    case RTC_REG_C:
        ret = s->hw.cmos_data[s->hw.cmos_index];
        hvm_isa_irq_deassert(vrtc_domain(s), RTC_IRQ);
        s->hw.cmos_data[RTC_REG_C] = 0x00;
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
        gdprintk(XENLOG_WARNING, "HVM_RTC bas access\n");
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
    if ( v->vcpu_id == 0 )
    {
        ;
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

    spin_unlock(&s->lock);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(RTC, rtc_save, rtc_load, 1, HVMSR_PER_DOM);

void rtc_reset(struct domain *d)
{
    RTCState *s = domain_vrtc(d);

    destroy_periodic_time(&s->pt);
    s->pt.source = PTSRC_isa;
}

void rtc_init(struct domain *d)
{
    RTCState *s = domain_vrtc(d);

    spin_lock_init(&s->lock);

    register_portio_handler(d, RTC_PORT(0), 2, handle_rtc_io);

    rtc_reset(d);

    spin_lock(&s->lock);

    s->hw.cmos_data[RTC_REG_A] = RTC_REF_CLCK_32KHZ | 6; /* ~1kHz */
    s->hw.cmos_data[RTC_REG_B] = RTC_24H;
    s->hw.cmos_data[RTC_REG_C] = 0;
    s->hw.cmos_data[RTC_REG_D] = RTC_VRT;

    s->current_tm = gmtime(get_localtime(d));

    rtc_copy_date(s);

    spin_unlock(&s->lock);
}

void rtc_deinit(struct domain *d)
{
    RTCState *s = domain_vrtc(d);

    spin_barrier(&s->lock);

    destroy_periodic_time(&s->pt);
}

void rtc_update_clock(struct domain *d)
{
    RTCState *s = domain_vrtc(d);

    spin_lock(&s->lock);
    s->current_tm = gmtime(get_localtime(d));
    spin_unlock(&s->lock);
}
