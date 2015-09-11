/*
 * hpet.c: HPET emulation for HVM guests.
 * Copyright (c) 2006, Intel Corporation.
 * Copyright (c) 2006, Keir Fraser <keir@xensource.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/hvm/vpt.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/trace.h>
#include <asm/current.h>
#include <asm/hpet.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/trace.h>

#define domain_vhpet(x) (&(x)->arch.hvm_domain.pl_time.vhpet)
#define vcpu_vhpet(x)   (domain_vhpet((x)->domain))
#define vhpet_domain(x) (container_of((x), struct domain, \
                                      arch.hvm_domain.pl_time.vhpet))
#define vhpet_vcpu(x)   (pt_global_vcpu_target(vhpet_domain(x)))

#define HPET_BASE_ADDRESS   0xfed00000ULL
#define HPET_MMAP_SIZE      1024
#define S_TO_NS  1000000000ULL           /* 1s  = 10^9  ns */
#define S_TO_FS  1000000000000000ULL     /* 1s  = 10^15 fs */

/* Frequency_of_Xen_systeme_time / frequency_of_HPET = 16 */
#define STIME_PER_HPET_TICK 16
#define guest_time_hpet(hpet) \
    (hvm_get_guest_time(vhpet_vcpu(hpet)) / STIME_PER_HPET_TICK)

#define HPET_TN_INT_ROUTE_CAP_SHIFT 32
#define HPET_TN_CFG_BITS_READONLY_OR_RESERVED (HPET_TN_RESERVED | \
    HPET_TN_PERIODIC_CAP | HPET_TN_64BIT_CAP | HPET_TN_FSB_CAP)

/* can be routed to IOAPIC.redirect_table[23..20] */
#define HPET_TN_INT_ROUTE_CAP      (0x00f00000ULL \
                    << HPET_TN_INT_ROUTE_CAP_SHIFT)

#define HPET_TN_INT_ROUTE_CAP_MASK (0xffffffffULL \
                    << HPET_TN_INT_ROUTE_CAP_SHIFT)

#define HPET_TN(reg, addr) (((addr) - HPET_Tn_##reg(0)) / \
                            (HPET_Tn_##reg(1) - HPET_Tn_##reg(0)))

#define hpet_tick_to_ns(h, tick)                        \
    ((s_time_t)((((tick) > (h)->hpet_to_ns_limit) ?     \
        ~0ULL : (tick) * (h)->hpet_to_ns_scale) >> 10))

#define timer_config(h, n)       (h->hpet.timers[n].config)
#define timer_enabled(h, n)      (timer_config(h, n) & HPET_TN_ENABLE)
#define timer_is_periodic(h, n)  (timer_config(h, n) & HPET_TN_PERIODIC)
#define timer_is_32bit(h, n)     (timer_config(h, n) & HPET_TN_32BIT)
#define hpet_enabled(h)          (h->hpet.config & HPET_CFG_ENABLE)
#define timer_level(h, n)        (timer_config(h, n) & HPET_TN_LEVEL)

#define timer_int_route(h, n)   \
    ((timer_config(h, n) & HPET_TN_ROUTE) >> HPET_TN_ROUTE_SHIFT)

#define timer_int_route_cap(h, n)   \
    ((timer_config(h, n) & HPET_TN_INT_ROUTE_CAP_MASK) \
        >> HPET_TN_INT_ROUTE_CAP_SHIFT)

static inline uint64_t hpet_read_maincounter(HPETState *h, uint64_t guest_time)
{
    ASSERT(rw_is_locked(&h->lock));

    if ( hpet_enabled(h) )
        return guest_time + h->mc_offset;
    else
        return h->hpet.mc64;
}

static uint64_t hpet_get_comparator(HPETState *h, unsigned int tn,
                                    uint64_t guest_time)
{
    uint64_t comparator;
    uint64_t elapsed;

    ASSERT(rw_is_write_locked(&h->lock));

    comparator = h->hpet.comparator64[tn];
    if ( hpet_enabled(h) && timer_is_periodic(h, tn) )
    {
        /* update comparator by number of periods elapsed since last update */
        uint64_t period = h->hpet.period[tn];
        if (period)
        {
            elapsed = hpet_read_maincounter(h, guest_time) - comparator;
            if ( (int64_t)elapsed >= 0 )
            {
                comparator += ((elapsed + period) / period) * period;
                h->hpet.comparator64[tn] = comparator;
            }
        }
    }

    /* truncate if timer is in 32 bit mode */
    if ( timer_is_32bit(h, tn) )
        comparator = (uint32_t)comparator;
    h->hpet.timers[tn].cmp = comparator;
    return comparator;
}
static inline uint64_t hpet_read64(HPETState *h, unsigned long addr,
                                   uint64_t guest_time)
{
    addr &= ~7;

    switch ( addr )
    {
    case HPET_ID:
        return h->hpet.capability;
    case HPET_CFG:
        return h->hpet.config;
    case HPET_STATUS:
        return h->hpet.isr;
    case HPET_COUNTER:
        return hpet_read_maincounter(h, guest_time);
    case HPET_Tn_CFG(0):
    case HPET_Tn_CFG(1):
    case HPET_Tn_CFG(2):
        return h->hpet.timers[HPET_TN(CFG, addr)].config;
    case HPET_Tn_CMP(0):
    case HPET_Tn_CMP(1):
    case HPET_Tn_CMP(2):
        return hpet_get_comparator(h, HPET_TN(CMP, addr), guest_time);
    case HPET_Tn_ROUTE(0):
    case HPET_Tn_ROUTE(1):
    case HPET_Tn_ROUTE(2):
        return h->hpet.timers[HPET_TN(ROUTE, addr)].fsb;
    }

    return 0;
}

static inline int hpet_check_access_length(
    unsigned long addr, unsigned long len)
{
    if ( (addr & (len - 1)) || (len > 8) )
    {
        /*
         * According to ICH9 specification, unaligned accesses may result
         * in unexpected behaviour or master abort, but should not crash/hang.
         * Hence we read all-ones, drop writes, and log a warning.
         */
        gdprintk(XENLOG_WARNING, "HPET: access across register boundary: "
                 "%lx %lx\n", addr, len);
        return -EINVAL;
    }

    return 0;
}

static int hpet_read(
    struct vcpu *v, unsigned long addr, unsigned int length,
    unsigned long *pval)
{
    HPETState *h = vcpu_vhpet(v);
    unsigned long result;
    uint64_t val;

    if ( !v->domain->arch.hvm_domain.params[HVM_PARAM_HPET_ENABLED] )
    {
        result = ~0ul;
        goto out;
    }

    addr &= HPET_MMAP_SIZE-1;

    if ( hpet_check_access_length(addr, length) != 0 )
    {
        result = ~0ul;
        goto out;
    }

    result = addr < HPET_Tn_CMP(0) ||
             ((addr - HPET_Tn_CMP(0)) % (HPET_Tn_CMP(1) - HPET_Tn_CMP(0))) > 7;
    if ( result )
        read_lock(&h->lock);
    else
        write_lock(&h->lock);

    val = hpet_read64(h, addr, guest_time_hpet(h));

    if ( result )
        read_unlock(&h->lock);
    else
        write_unlock(&h->lock);

    result = val;
    if ( length != 8 )
        result = (val >> ((addr & 7) * 8)) & ((1ULL << (length * 8)) - 1);

 out:
    *pval = result;
    return X86EMUL_OKAY;
}

static void hpet_stop_timer(HPETState *h, unsigned int tn,
                            uint64_t guest_time)
{
    ASSERT(tn < HPET_TIMER_NUM);
    ASSERT(rw_is_write_locked(&h->lock));
    TRACE_1D(TRC_HVM_EMUL_HPET_STOP_TIMER, tn);
    destroy_periodic_time(&h->pt[tn]);
    /* read the comparator to get it updated so a read while stopped will
     * return the expected value. */
    hpet_get_comparator(h, tn, guest_time);
}

/* the number of HPET tick that stands for
 * 1/(2^10) second, namely, 0.9765625 milliseconds */
#define  HPET_TINY_TIME_SPAN  ((h->stime_freq >> 10) / STIME_PER_HPET_TICK)

static void hpet_set_timer(HPETState *h, unsigned int tn,
                           uint64_t guest_time)
{
    uint64_t tn_cmp, cur_tick, diff;
    unsigned int irq;
    unsigned int oneshot;

    ASSERT(tn < HPET_TIMER_NUM);
    ASSERT(rw_is_write_locked(&h->lock));

    if ( (tn == 0) && (h->hpet.config & HPET_CFG_LEGACY) )
    {
        /* HPET specification requires PIT shouldn't generate
         * interrupts if LegacyReplacementRoute is set for timer0 */
        pit_stop_channel0_irq(&vhpet_domain(h)->arch.vpit);
    }

    if ( !timer_enabled(h, tn) )
        return;

    tn_cmp   = hpet_get_comparator(h, tn, guest_time);
    cur_tick = hpet_read_maincounter(h, guest_time);
    if ( timer_is_32bit(h, tn) )
    {
        tn_cmp   = (uint32_t)tn_cmp;
        cur_tick = (uint32_t)cur_tick;
    }

    diff = tn_cmp - cur_tick;

    /*
     * Detect time values set in the past. This is hard to do for 32-bit
     * comparators as the timer does not have to be set that far in the future
     * for the counter difference to wrap a 32-bit signed integer. We fudge
     * by looking for a 'small' time value in the past.
     */
    if ( (int64_t)diff < 0 )
        diff = (timer_is_32bit(h, tn) && (-diff > HPET_TINY_TIME_SPAN))
            ? (uint32_t)diff : 0;

    if ( (tn <= 1) && (h->hpet.config & HPET_CFG_LEGACY) )
        /* if LegacyReplacementRoute bit is set, HPET specification requires
           timer0 be routed to IRQ0 in NON-APIC or IRQ2 in the I/O APIC,
           timer1 be routed to IRQ8 in NON-APIC or IRQ8 in the I/O APIC. */
        irq = (tn == 0) ? 0 : 8;
    else
        irq = timer_int_route(h, tn);

    /*
     * diff is the time from now when the timer should fire, for a periodic
     * timer we also need the period which may be different because time may
     * have elapsed between the time the comparator was written and the timer
     * being enabled (now).
     */
    oneshot = !timer_is_periodic(h, tn);
    TRACE_2_LONG_4D(TRC_HVM_EMUL_HPET_START_TIMER, tn, irq,
                    TRC_PAR_LONG(hpet_tick_to_ns(h, diff)),
                    TRC_PAR_LONG(oneshot ? 0LL :
                                 hpet_tick_to_ns(h, h->hpet.period[tn])));
    create_periodic_time(vhpet_vcpu(h), &h->pt[tn],
                         hpet_tick_to_ns(h, diff),
                         oneshot ? 0 : hpet_tick_to_ns(h, h->hpet.period[tn]),
                         irq, NULL, NULL);
}

static inline uint64_t hpet_fixup_reg(
    uint64_t new, uint64_t old, uint64_t mask)
{
    new &= mask;
    new |= old & ~mask;
    return new;
}

static int hpet_write(
    struct vcpu *v, unsigned long addr,
    unsigned int length, unsigned long val)
{
    HPETState *h = vcpu_vhpet(v);
    uint64_t old_val, new_val;
    uint64_t guest_time;
    int tn, i;

    /* Acculumate a bit mask of timers whos state is changed by this write. */
    unsigned long start_timers = 0;
    unsigned long stop_timers  = 0;
#define set_stop_timer(n)    (__set_bit((n), &stop_timers))
#define set_start_timer(n)   (__set_bit((n), &start_timers))
#define set_restart_timer(n) (set_stop_timer(n),set_start_timer(n))

    if ( !v->domain->arch.hvm_domain.params[HVM_PARAM_HPET_ENABLED] )
        goto out;

    addr &= HPET_MMAP_SIZE-1;

    if ( hpet_check_access_length(addr, length) != 0 )
        goto out;

    write_lock(&h->lock);

    guest_time = guest_time_hpet(h);
    old_val = hpet_read64(h, addr, guest_time);
    new_val = val;
    if ( length != 8 )
        new_val = hpet_fixup_reg(
            new_val << (addr & 7) * 8, old_val,
            ((1ULL << (length*8)) - 1) << ((addr & 7) * 8));

    switch ( addr & ~7 )
    {
    case HPET_CFG:
        h->hpet.config = hpet_fixup_reg(new_val, old_val, 0x3);

        if ( !(old_val & HPET_CFG_ENABLE) && (new_val & HPET_CFG_ENABLE) )
        {
            /* Enable main counter and interrupt generation. */
            h->mc_offset = h->hpet.mc64 - guest_time;
            for ( i = 0; i < HPET_TIMER_NUM; i++ )
            {
                h->hpet.comparator64[i] =
                            h->hpet.timers[i].config & HPET_TN_32BIT ?
                                          (uint32_t)h->hpet.timers[i].cmp :
                                                    h->hpet.timers[i].cmp;
                if ( timer_enabled(h, i) )
                    set_start_timer(i);
            }
        }
        else if ( (old_val & HPET_CFG_ENABLE) && !(new_val & HPET_CFG_ENABLE) )
        {
            /* Halt main counter and disable interrupt generation. */
            h->hpet.mc64 = h->mc_offset + guest_time;
            for ( i = 0; i < HPET_TIMER_NUM; i++ )
                if ( timer_enabled(h, i) )
                    set_stop_timer(i);
        }
        break;

    case HPET_COUNTER:
        h->hpet.mc64 = new_val;
        if ( hpet_enabled(h) )
        {
            gdprintk(XENLOG_WARNING,
                     "HPET: writing main counter but it's not halted!\n");
            for ( i = 0; i < HPET_TIMER_NUM; i++ )
                if ( timer_enabled(h, i) )
                    set_restart_timer(i);
        }
        break;

    case HPET_Tn_CFG(0):
    case HPET_Tn_CFG(1):
    case HPET_Tn_CFG(2):
        tn = HPET_TN(CFG, addr);

        h->hpet.timers[tn].config = hpet_fixup_reg(new_val, old_val, 0x3f4e);

        if ( timer_level(h, tn) )
        {
            gdprintk(XENLOG_ERR,
                     "HPET: level triggered interrupt not supported now\n");
            domain_crash(current->domain);
            break;
        }

        if ( new_val & HPET_TN_32BIT )
        {
            h->hpet.timers[tn].cmp = (uint32_t)h->hpet.timers[tn].cmp;
            h->hpet.period[tn] = (uint32_t)h->hpet.period[tn];
        }
        if ( hpet_enabled(h) )
        {
            if ( new_val & HPET_TN_ENABLE )
            {
                if ( (new_val ^ old_val) & HPET_TN_PERIODIC )
                    /* timer is enabled but switching mode to/from periodic/
                     * one-shot, stop and restart the vpt timer to get it in
                     * the right mode. */
                    set_restart_timer(tn);
                else if ( (new_val & HPET_TN_32BIT) &&
                         !(old_val & HPET_TN_32BIT) )
                    /* switching from 64 bit to 32 bit mode could cause timer
                     * next fire time, or period, to change. */
                    set_restart_timer(tn);
                else if ( !(old_val & HPET_TN_ENABLE) )
                    /* transition from timer disabled to timer enabled. */
                    set_start_timer(tn);
            }
            else if ( old_val & HPET_TN_ENABLE )
                /* transition from timer enabled to timer disabled. */
                set_stop_timer(tn);
        }
        break;

    case HPET_Tn_CMP(0):
    case HPET_Tn_CMP(1):
    case HPET_Tn_CMP(2):
        tn = HPET_TN(CMP, addr);
        if ( timer_is_periodic(h, tn) &&
             !(h->hpet.timers[tn].config & HPET_TN_SETVAL) )
        {
            uint64_t max_period = (timer_is_32bit(h, tn) ? ~0u : ~0ull) >> 1;

            /*
             * Clamp period to reasonable min/max values:
             *  - minimum is 100us, same as timers controlled by vpt.c
             *  - maximum is to prevent overflow in time_after() calculations
             */
            if ( hpet_tick_to_ns(h, new_val) < MICROSECS(100) )
                new_val = (MICROSECS(100) << 10) / h->hpet_to_ns_scale;
            if ( new_val > max_period )
                new_val = max_period;
            h->hpet.period[tn] = new_val;
        }
        else
        {
            /*
             * When SETVAL is one, software is able to "directly set
             * a periodic timer's accumulator."  That is, set the
             * comparator without adjusting the period.  Much the
             * same as just setting the comparator on an enabled
             * one-shot timer.
             *
             * This configuration bit clears when the comparator is
             * written.
             */
            h->hpet.timers[tn].config &= ~HPET_TN_SETVAL;
            h->hpet.comparator64[tn] = new_val;
            /* truncate if timer is in 32 bit mode */
            if ( timer_is_32bit(h, tn) )
                new_val = (uint32_t)new_val;
            h->hpet.timers[tn].cmp = new_val;
        }
        if ( hpet_enabled(h) && timer_enabled(h, tn) )
            set_restart_timer(tn);
        break;

    case HPET_Tn_ROUTE(0):
    case HPET_Tn_ROUTE(1):
    case HPET_Tn_ROUTE(2):
        tn = HPET_TN(ROUTE, addr);
        h->hpet.timers[tn].fsb = new_val;
        break;

    default:
        /* Ignore writes to unsupported and reserved registers. */
        break;
    }

    /* stop/start timers whos state was changed by this write. */
    while (stop_timers)
    {
        i = find_first_set_bit(stop_timers);
        __clear_bit(i, &stop_timers);
        hpet_stop_timer(h, i, guest_time);
    }

    while (start_timers)
    {
        i = find_first_set_bit(start_timers);
        __clear_bit(i, &start_timers);
        hpet_set_timer(h, i, guest_time);
    }

#undef set_stop_timer
#undef set_start_timer
#undef set_restart_timer

    write_unlock(&h->lock);

 out:
    return X86EMUL_OKAY;
}

static int hpet_range(struct vcpu *v, unsigned long addr)
{
    return ( (addr >= HPET_BASE_ADDRESS) &&
             (addr < (HPET_BASE_ADDRESS + HPET_MMAP_SIZE)) );
}

static const struct hvm_mmio_ops hpet_mmio_ops = {
    .check = hpet_range,
    .read  = hpet_read,
    .write = hpet_write
};


static int hpet_save(struct domain *d, hvm_domain_context_t *h)
{
    HPETState *hp = domain_vhpet(d);
    struct vcpu *v = pt_global_vcpu_target(d);
    int rc;
    uint64_t guest_time;

    write_lock(&hp->lock);
    guest_time = (v->arch.hvm_vcpu.guest_time ?: hvm_get_guest_time(v)) /
                 STIME_PER_HPET_TICK;

    /* Write the proper value into the main counter */
    if ( hpet_enabled(hp) )
        hp->hpet.mc64 = hp->mc_offset + guest_time;

    /* Save the HPET registers */
    rc = _hvm_init_entry(h, HVM_SAVE_CODE(HPET), 0, HVM_SAVE_LENGTH(HPET));
    if ( rc == 0 )
    {
        struct hvm_hw_hpet *rec = (struct hvm_hw_hpet *)&h->data[h->cur];
        h->cur += HVM_SAVE_LENGTH(HPET);
        memset(rec, 0, HVM_SAVE_LENGTH(HPET));
#define C(x) rec->x = hp->hpet.x
        C(capability);
        C(config);
        C(isr);
        C(mc64);
        C(timers[0].config);
        C(timers[0].fsb);
        C(timers[1].config);
        C(timers[1].fsb);
        C(timers[2].config);
        C(timers[2].fsb);
        C(period[0]);
        C(period[1]);
        C(period[2]);
#undef C
        /*
         * read the comparator to get it updated so hpet_save will
         * return the expected value.
         */
        hpet_get_comparator(hp, 0, guest_time);
        hpet_get_comparator(hp, 1, guest_time);
        hpet_get_comparator(hp, 2, guest_time);
        /*
         * save the 64 bit comparator in the 64 bit timer[n].cmp
         * field regardless of whether or not the timer is in 32 bit
         * mode.
         */
        rec->timers[0].cmp = hp->hpet.comparator64[0];
        rec->timers[1].cmp = hp->hpet.comparator64[1];
        rec->timers[2].cmp = hp->hpet.comparator64[2];
    }

    write_unlock(&hp->lock);

    return rc;
}

static int hpet_load(struct domain *d, hvm_domain_context_t *h)
{
    HPETState *hp = domain_vhpet(d);
    struct hvm_hw_hpet *rec;
    uint64_t cmp;
    uint64_t guest_time;
    int i;

    write_lock(&hp->lock);

    /* Reload the HPET registers */
    if ( _hvm_check_entry(h, HVM_SAVE_CODE(HPET), HVM_SAVE_LENGTH(HPET), 1) )
    {
        write_unlock(&hp->lock);
        return -EINVAL;
    }

    rec = (struct hvm_hw_hpet *)&h->data[h->cur];
    h->cur += HVM_SAVE_LENGTH(HPET);

#define C(x) hp->hpet.x = rec->x
    C(capability);
    C(config);
    C(isr);
    C(mc64);
    /* The following define will generate a compiler error if HPET_TIMER_NUM
     * changes. This indicates an incompatability with previous saved state. */
#define HPET_TIMER_NUM 3
    for ( i = 0; i < HPET_TIMER_NUM; i++ )
    {
        C(timers[i].config);
        C(timers[i].fsb);
        C(period[i]);
        /* restore the hidden 64 bit comparator and truncate the timer's
         * visible comparator field if in 32 bit mode. */
        cmp = rec->timers[i].cmp;
        hp->hpet.comparator64[i] = cmp;
        if ( timer_is_32bit(hp, i) )
            cmp = (uint32_t)cmp;
        hp->hpet.timers[i].cmp = cmp;
    }
#undef C

    /* Recalculate the offset between the main counter and guest time */
    guest_time = guest_time_hpet(hp);
    hp->mc_offset = hp->hpet.mc64 - guest_time;

    /* restart all timers */

    if ( hpet_enabled(hp) )
        for ( i = 0; i < HPET_TIMER_NUM; i++ )
            if ( timer_enabled(hp, i) )
                hpet_set_timer(hp, i, guest_time);

    write_unlock(&hp->lock);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(HPET, hpet_save, hpet_load, 1, HVMSR_PER_DOM);

void hpet_init(struct domain *d)
{
    HPETState *h = domain_vhpet(d);
    int i;

    memset(h, 0, sizeof(HPETState));

    rwlock_init(&h->lock);

    h->stime_freq = S_TO_NS;

    h->hpet_to_ns_scale = ((S_TO_NS * STIME_PER_HPET_TICK) << 10) / h->stime_freq;
    h->hpet_to_ns_limit = ~0ULL / h->hpet_to_ns_scale;

    h->hpet.capability = 0x80860001ULL |
                         ((HPET_TIMER_NUM - 1) << HPET_ID_NUMBER_SHIFT) |
                         HPET_ID_64BIT | HPET_ID_LEGSUP;

    /* This is the number of femptoseconds per HPET tick. */
    /* Here we define HPET's frequency to be 1/16 of Xen system time */
    h->hpet.capability |= ((S_TO_FS*STIME_PER_HPET_TICK/h->stime_freq) << 32);

    for ( i = 0; i < HPET_TIMER_NUM; i++ )
    {
        h->hpet.timers[i].config =
            HPET_TN_INT_ROUTE_CAP | HPET_TN_64BIT_CAP | HPET_TN_PERIODIC_CAP;
        h->hpet.timers[i].cmp = ~0ULL;
        h->hpet.comparator64[i] = ~0ULL;
        h->pt[i].source = PTSRC_isa;
    }

    register_mmio_handler(d, &hpet_mmio_ops);
}

void hpet_deinit(struct domain *d)
{
    int i;
    HPETState *h = domain_vhpet(d);

    write_lock(&h->lock);

    if ( hpet_enabled(h) )
    {
        uint64_t guest_time = guest_time_hpet(h);

        for ( i = 0; i < HPET_TIMER_NUM; i++ )
            if ( timer_enabled(h, i) )
                hpet_stop_timer(h, i, guest_time);
    }

    write_unlock(&h->lock);
}

void hpet_reset(struct domain *d)
{
    hpet_deinit(d);
    hpet_init(d);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
