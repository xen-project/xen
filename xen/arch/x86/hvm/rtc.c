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

/* #define DEBUG_RTC */

void rtc_periodic_cb(struct vcpu *v, void *opaque)
{
    RTCState *s = opaque;
    s->hw.cmos_data[RTC_REG_C] |= 0xc0;
}

int is_rtc_periodic_irq(void *opaque)
{
    RTCState *s = opaque;

    return !(s->hw.cmos_data[RTC_REG_C] & RTC_AF || 
           s->hw.cmos_data[RTC_REG_C] & RTC_UF);
}

/* Enable/configure/disable the periodic timer based on the RTC_PIE and
 * RTC_RATE_SELECT settings */
static void rtc_timer_update(RTCState *s, struct vcpu *v)
{
    int period_code; 
    int period;

    period_code = s->hw.cmos_data[RTC_REG_A] & RTC_RATE_SELECT;
    if ( (period_code != 0) && (s->hw.cmos_data[RTC_REG_B] & RTC_PIE) )
    {
        if ( period_code <= 2 )
            period_code += 7;
        
        period = 1 << (period_code - 1); /* period in 32 Khz cycles */
        period = DIV_ROUND((period * 1000000000ULL), 32768); /* period in ns */
#ifdef DEBUG_RTC
        printk("HVM_RTC: period = %uns\n", period);
#endif
        create_periodic_time(v, &s->pt, period, RTC_IRQ, 0, rtc_periodic_cb, s);
    } 
    else
        destroy_periodic_time(&s->pt);
}

static void rtc_set_time(RTCState *s);

static int rtc_ioport_write(void *opaque, uint32_t addr, uint32_t data)
{
    RTCState *s = opaque;

    if ( (addr & 1) == 0 )
    {
        s->hw.cmos_index = data & 0x7f;
        return (s->hw.cmos_index < RTC_CMOS_SIZE);
    }

    if (s->hw.cmos_index >= RTC_CMOS_SIZE)
        return 0;

#ifdef DEBUG_RTC
    printk("HVM_RTC: write index=0x%02x val=0x%02x\n",
           s->hw.cmos_index, data);
#endif

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
        rtc_timer_update(s, current);
        break;
    case RTC_REG_B:
        if ( data & RTC_SET )
        {
            /* set mode: reset UIP mode */
            s->hw.cmos_data[RTC_REG_A] &= ~RTC_UIP;
            data &= ~RTC_UIE;
        }
        else
        {
            /* if disabling set mode, update the time */
            if ( s->hw.cmos_data[RTC_REG_B] & RTC_SET )
                rtc_set_time(s);
        }
        s->hw.cmos_data[RTC_REG_B] = data;
        rtc_timer_update(s, current);
        break;
    case RTC_REG_C:
    case RTC_REG_D:
        /* cannot write to them */
        break;
    }

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
    unsigned long before, after; /* XXX s_time_t */
      
    before = mktime(tm->tm_year, tm->tm_mon, tm->tm_mday,
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

    after = mktime(tm->tm_year, tm->tm_mon, tm->tm_mday,
                   tm->tm_hour, tm->tm_min, tm->tm_sec);
    send_timeoffset_req(after - before);
}

static void rtc_copy_date(RTCState *s)
{
    const struct tm *tm = &s->current_tm;

    if (s->time_offset_seconds != s->pt.vcpu->domain->time_offset_seconds) {
        s->current_tm = gmtime(get_localtime(s->pt.vcpu->domain));
        s->time_offset_seconds = s->pt.vcpu->domain->time_offset_seconds;
    }

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

/* month is between 0 and 11. */
static int get_days_in_month(int month, int year)
{
    static const int days_tab[12] = { 
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 
    };
    int d;
    if ( (unsigned)month >= 12 )
        return 31;
    d = days_tab[month];
    if ( month == 1 )
        if ( (year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0) )
            d++;
    return d;
}

/* update 'tm' to the next second */
static void rtc_next_second(RTCState *s)
{
    struct tm *tm = &s->current_tm;
    int days_in_month;

    if (s->time_offset_seconds != s->pt.vcpu->domain->time_offset_seconds) {
        s->current_tm = gmtime(get_localtime(s->pt.vcpu->domain));
        s->time_offset_seconds = s->pt.vcpu->domain->time_offset_seconds;
    }

    tm->tm_sec++;
    if ((unsigned)tm->tm_sec >= 60) {
        tm->tm_sec = 0;
        tm->tm_min++;
        if ((unsigned)tm->tm_min >= 60) {
            tm->tm_min = 0;
            tm->tm_hour++;
            if ((unsigned)tm->tm_hour >= 24) {
                tm->tm_hour = 0;
                /* next day */
                tm->tm_wday++;
                if ((unsigned)tm->tm_wday >= 7)
                    tm->tm_wday = 0;
                days_in_month = get_days_in_month(tm->tm_mon, 
                                                  tm->tm_year + 1900);
                tm->tm_mday++;
                if (tm->tm_mday < 1) {
                    tm->tm_mday = 1;
                } else if (tm->tm_mday > days_in_month) {
                    tm->tm_mday = 1;
                    tm->tm_mon++;
                    if (tm->tm_mon >= 12) {
                        tm->tm_mon = 0;
                        tm->tm_year++;
                    }
                }
            }
        }
    }
}

static void rtc_update_second(void *opaque)
{
    RTCState *s = opaque;

    /* if the oscillator is not in normal operation, we do not update */
    if ( (s->hw.cmos_data[RTC_REG_A] & RTC_DIV_CTL) != RTC_REF_CLCK_32KHZ )
    {
        s->next_second_time += 1000000000ULL;
        set_timer(&s->second_timer, s->next_second_time);
    }
    else
    {
        rtc_next_second(s);
        
        if ( !(s->hw.cmos_data[RTC_REG_B] & RTC_SET) )
            s->hw.cmos_data[RTC_REG_A] |= RTC_UIP;

        /* Delay time before update cycle */
        set_timer(&s->second_timer2, s->next_second_time + 244000);
    }
}

static void rtc_update_second2(void *opaque)
{
    RTCState *s = opaque;

    if ( !(s->hw.cmos_data[RTC_REG_B] & RTC_SET) )
        rtc_copy_date(s);

    /* check alarm */
    if ( s->hw.cmos_data[RTC_REG_B] & RTC_AIE )
    {
        if ( ((s->hw.cmos_data[RTC_SECONDS_ALARM] & 0xc0) == 0xc0 ||
              from_bcd(s, s->hw.cmos_data[RTC_SECONDS_ALARM]) ==
              s->current_tm.tm_sec) &&
             ((s->hw.cmos_data[RTC_MINUTES_ALARM] & 0xc0) == 0xc0 ||
              from_bcd(s, s->hw.cmos_data[RTC_MINUTES_ALARM]) ==
              s->current_tm.tm_min) &&
             ((s->hw.cmos_data[RTC_HOURS_ALARM] & 0xc0) == 0xc0 ||
              from_bcd(s, s->hw.cmos_data[RTC_HOURS_ALARM]) ==
              s->current_tm.tm_hour) )
        {
            s->hw.cmos_data[RTC_REG_C] |= 0xa0; 
            hvm_isa_irq_deassert(s->pt.vcpu->domain, RTC_IRQ);
            hvm_isa_irq_assert(s->pt.vcpu->domain, RTC_IRQ);
        }
    }

    /* update ended interrupt */
    if ( s->hw.cmos_data[RTC_REG_B] & RTC_UIE )
    {
        s->hw.cmos_data[RTC_REG_C] |= 0x90; 
        hvm_isa_irq_deassert(s->pt.vcpu->domain, RTC_IRQ);
        hvm_isa_irq_assert(s->pt.vcpu->domain, RTC_IRQ);
    }

    /* clear update in progress bit */
    s->hw.cmos_data[RTC_REG_A] &= ~RTC_UIP;

    s->next_second_time += 1000000000ULL;
    set_timer(&s->second_timer, s->next_second_time);
}

static uint32_t rtc_ioport_read(void *opaque, uint32_t addr)
{
    RTCState *s = opaque;
    int ret;

    if ( (addr & 1) == 0 )
        return 0xff;

    switch ( s->hw.cmos_index )
    {
    case RTC_SECONDS:
    case RTC_MINUTES:
    case RTC_HOURS:
    case RTC_DAY_OF_WEEK:
    case RTC_DAY_OF_MONTH:
    case RTC_MONTH:
    case RTC_YEAR:
        ret = s->hw.cmos_data[s->hw.cmos_index];
        break;
    case RTC_REG_A:
        ret = s->hw.cmos_data[s->hw.cmos_index];
        break;
    case RTC_REG_C:
        ret = s->hw.cmos_data[s->hw.cmos_index];
        hvm_isa_irq_deassert(s->pt.vcpu->domain, RTC_IRQ);
        s->hw.cmos_data[RTC_REG_C] = 0x00; 
        break;
    default:
        ret = s->hw.cmos_data[s->hw.cmos_index];
        break;
    }

#ifdef DEBUG_RTC
    printk("HVM_RTC: read index=0x%02x val=0x%02x\n",
           s->hw.cmos_index, ret);
#endif

    return ret;
}

static int handle_rtc_io(ioreq_t *p)
{
    struct vcpu *v = current;
    struct RTCState *vrtc = &v->domain->arch.hvm_domain.pl_time.vrtc;

    if ( (p->size != 1) || p->data_is_ptr || (p->type != IOREQ_TYPE_PIO) )
    {
        printk("HVM_RTC: wrong RTC IO!\n");
        return 1;
    }
    
    if ( p->dir == 0 ) /* write */
    {
        if ( rtc_ioport_write(vrtc, p->addr, p->data & 0xFF) )
            return 1;
    }
    else if ( (p->dir == 1) && (vrtc->hw.cmos_index < RTC_CMOS_SIZE) ) /* read */
    {
        p->data = rtc_ioport_read(vrtc, p->addr);
        return 1;
    }

    return 0;
}

/* Move the RTC timers on to this vcpu's current cpu */
void rtc_migrate_timers(struct vcpu *v)
{
    RTCState *s = &v->domain->arch.hvm_domain.pl_time.vrtc;

    if ( s->pt.vcpu == v )
    {
        if ( s->pt.enabled )
            migrate_timer(&s->pt.timer, v->processor);
        migrate_timer(&s->second_timer, v->processor);
        migrate_timer(&s->second_timer2, v->processor);
    }
}

/* Save RTC hardware state */
static int rtc_save(struct domain *d, hvm_domain_context_t *h)
{
    return hvm_save_entry(RTC, 0, h, &d->arch.hvm_domain.pl_time.vrtc.hw);
}

/* Reload the hardware state from a saved domain */
static int rtc_load(struct domain *d, hvm_domain_context_t *h)
{
    RTCState *s = &d->arch.hvm_domain.pl_time.vrtc;    

    /* Restore the registers */
    if ( hvm_load_entry(RTC, h, &s->hw) != 0 )
        return -EINVAL;

    /* Reset the wall-clock time.  In normal running, this runs with host 
     * time, so let's keep doing that. */
    s->current_tm = gmtime(get_localtime(d));
    rtc_copy_date(s);
    s->next_second_time = NOW() + 1000000000ULL;
    stop_timer(&s->second_timer);
    set_timer(&s->second_timer2, s->next_second_time);

    /* Reset the periodic interrupt timer based on the registers */
    rtc_timer_update(s, d->vcpu[0]);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(RTC, rtc_save, rtc_load, 1, HVMSR_PER_DOM);


void rtc_init(struct vcpu *v, int base)
{
    RTCState *s = &v->domain->arch.hvm_domain.pl_time.vrtc;

    s->pt.vcpu = v;
    s->hw.cmos_data[RTC_REG_A] = RTC_REF_CLCK_32KHZ | 6; /* ~1kHz */
    s->hw.cmos_data[RTC_REG_B] = RTC_24H;
    s->hw.cmos_data[RTC_REG_C] = 0;
    s->hw.cmos_data[RTC_REG_D] = RTC_VRT;

    s->current_tm = gmtime(get_localtime(v->domain));
    rtc_copy_date(s);

    init_timer(&s->pt.timer, pt_timer_fn, &s->pt, v->processor);
    init_timer(&s->second_timer, rtc_update_second, s, v->processor);
    init_timer(&s->second_timer2, rtc_update_second2, s, v->processor);

    s->next_second_time = NOW() + 1000000000ULL;
    set_timer(&s->second_timer2, s->next_second_time);

    register_portio_handler(v->domain, base, 2, handle_rtc_io);
}

void rtc_deinit(struct domain *d)
{
    RTCState *s = &d->arch.hvm_domain.pl_time.vrtc;

    kill_timer(&s->pt.timer);
    kill_timer(&s->second_timer);
    kill_timer(&s->second_timer2);
}
