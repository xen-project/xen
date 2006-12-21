/*
 * hpet.c: emulating HPET in Xen
 * Copyright (c) 2006, Intel Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <asm/hvm/vpt.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/current.h>
#include <xen/sched.h>
#include <xen/event.h>

#define HPET_BASE_ADDRESS   0xfed00000ULL
#define HPET_MMAP_SIZE      1024
#define S_TO_NS  1000000000ULL           /* 1s  = 10^9  ns */
#define S_TO_FS  1000000000000000ULL     /* 1s  = 10^15 fs */

#define HPET_ID         0x000
#define HPET_PERIOD     0x004
#define HPET_CFG        0x010
#define HPET_STATUS     0x020
#define HPET_COUNTER    0x0f0
#define HPET_T0_CFG     0x100
#define HPET_T0_CMP     0x108
#define HPET_T0_ROUTE   0x110
#define HPET_T1_CFG     0x120
#define HPET_T1_CMP     0x128
#define HPET_T1_ROUTE   0x130
#define HPET_T2_CFG     0x140
#define HPET_T2_CMP     0x148
#define HPET_T2_ROUTE   0x150
#define HPET_T3_CFG     0x158 /* not supported now*/

#define HPET_REV                0x01ULL
#define HPET_NUMBER            0x200ULL /* 3 timers */
#define HPET_COUNTER_SIZE_CAP 0x2000ULL
#define HPET_LEG_RT_CAP       0x8000ULL
#define HPET_VENDOR_8086  0x80860000ULL

/* 64bit main counter; 3 timers supported now;
   LegacyReplacemen Route supported.           */
#define HPET_CAP_ID_REG \
    (HPET_REV | HPET_NUMBER | HPET_COUNTER_SIZE_CAP | \
     HPET_LEG_RT_CAP | HPET_VENDOR_8086)

#define HPET_CFG_ENABLE          0x001
#define HPET_CFG_LEGACY          0x002

#define HPET_TN_INT_TYPE_LEVEL   0x002
#define HPET_TN_ENABLE           0x004
#define HPET_TN_PERIODIC         0x008
#define HPET_TN_PERIODIC_CAP     0x010
#define HPET_TN_SETVAL           0x040
#define HPET_TN_32BIT            0x100
#define HPET_TN_INT_ROUTE_MASK  0x3e00
#define HPET_TN_INT_ROUTE_SHIFT      9
#define HPET_TN_INT_ROUTE_CAP_SHIFT 32
#define HPET_TN_CFG_BITS_READONLY_OR_RESERVED 0xffff80b1U

/* can be routed to IOAPIC.redirect_table[23..20] */
#define HPET_TN_INT_ROUTE_CAP      (0x00f00000ULL \
                    << HPET_TN_INT_ROUTE_CAP_SHIFT) 

#define HPET_TN_INT_ROUTE_CAP_MASK (0xffffffffULL \
                    << HPET_TN_INT_ROUTE_CAP_SHIFT)

#define HPET_TIMER_CMP32_DEFAULT 0xffffffffULL
#define HPET_TIMER_CMP64_DEFAULT 0xffffffffffffffffULL
#define HPET_TN_SIZE_CAP         (1 << 5)

#define hpet_tick_to_ns(h, tick) ((s_time_t)(tick)*S_TO_NS/h->tsc_freq)
#define timer_config(h, n)       (h->hpet.timers[n].config)
#define timer_enabled(h, n)      (timer_config(h, n) & HPET_TN_ENABLE)
#define timer_is_periodic(h, n)  (timer_config(h, n) & HPET_TN_PERIODIC)
#define timer_is_32bit(h, n)     (timer_config(h, n) & HPET_TN_32BIT)
#define timer_period_cap(h, n)   (timer_config(h, n) & HPET_TN_PERIODIC_CAP)
#define hpet_enabled(h)          (h->hpet.config & HPET_CFG_ENABLE)
#define timer_level(h, n)        (timer_config(h, n) & HPET_TN_INT_TYPE_LEVEL)

#define timer_int_route(h, n)   \
    ((timer_config(h, n) & HPET_TN_INT_ROUTE_MASK) >> HPET_TN_INT_ROUTE_SHIFT)

#define timer_int_route_cap(h, n)   \
    ((timer_config(h, n) & HPET_TN_INT_ROUTE_CAP_MASK) \
        >> HPET_TN_INT_ROUTE_CAP_SHIFT)

#define timer_int_route_valid(h, n)  \
    (timer_int_route_cap(h, n) & (1 << timer_int_route(h, n)))    
 
#define hpet_time_after(a, b)   ((int32_t)(b) -(int32_t)(a) < 0)
#define hpet_time_after64(a, b)   ((int64_t)(b) -(int64_t)(a) < 0)

static inline uint32_t hpet_read32(HPETState *h, unsigned long addr)
{
    unsigned long p = ((unsigned long)&h->hpet) + addr;
    return  *((uint32_t*)p);
}

static inline void hpet_write32(HPETState *h, unsigned long addr, uint32_t val)
{
    unsigned long p = ((unsigned long)&h->hpet) + addr;
    *((uint32_t*)p) = val;
}

static int hpet_check_access_length(unsigned long addr, unsigned long len)
{
    if ( (len != 4) && (len != 8) )
    {
        gdprintk(XENLOG_ERR, "HPET: access with len=%lu\n", len);
        goto fail;
    }

    if ( addr & (len-1) )
    {
        gdprintk(XENLOG_ERR, "HPET: access across register boundary\n");
        goto fail;
    }

    return 0;

 fail:
    domain_crash(current->domain);
    return -EINVAL;
}

static int hpet_check_access_offset(unsigned long addr)
{
    if ( addr >= HPET_T3_CFG )
    {
        gdprintk(XENLOG_ERR, "HPET: only 3 timers supported now\n");
        goto fail;
    }

    if ( (addr == HPET_T0_ROUTE) || (addr == HPET_T0_ROUTE+4) ||
         (addr == HPET_T1_ROUTE) || (addr == HPET_T1_ROUTE+4) ||
         (addr == HPET_T2_ROUTE) || (addr == HPET_T2_ROUTE+4) )
    {
        gdprintk(XENLOG_ERR, "HPET: FSB interrupt route not supported now\n");
        goto fail;
    }

    return 0;

 fail:
    domain_crash(current->domain);
    return -EINVAL;
}

static void hpet_level_triggered_interrupt_not_supported(void)
{
    /* It's hard to support level triggered interrupt in HPET. */
    /* Now we haven't found any OS uses this kind of interrupt of HPET. */
    gdprintk(XENLOG_ERR,
             "HPET: level triggered interrupt not supported now\n");
    domain_crash(current->domain);
}

static uint64_t hpet_update_maincounter(HPETState *h)
{
    if ( hpet_enabled(h) )
        return hvm_get_guest_time(h->vcpu) + h->mc_offset;
    else 
        return h->hpet.mc64;
}

static unsigned long hpet_read(
    struct vcpu *v, unsigned long addr, unsigned long length)
{
    HPETState *h = &v->domain->arch.hvm_domain.pl_time.vhpet;
    uint64_t mc, result;

    addr &= HPET_MMAP_SIZE-1;

    if ( hpet_check_access_length(addr, length) != 0 )
        goto fail;

    if ( length == 8 )
    {
        /* TODO: no OS is found to use length=8 now. 
         * Windows 2000/XP/2003 doesn't use HPET; all of Linux 
         * and 32bit/64bit Vista use 4-byte-length access.
         * Besides, section 2.4.7 of HPET spec gives a note saying
         * 64bit read may be inaccurate in some platforms. */
        gdprintk(XENLOG_ERR, "HPET: hpet_read with len=8 not implementated\n");
        domain_crash(v->domain);
        goto fail;
    }

    switch ( addr )
    {
    case HPET_COUNTER:
        mc = hpet_update_maincounter(h);
        result = mc & 0xffffffffU;
        break;
    case HPET_COUNTER + 4:
        mc = hpet_update_maincounter(h);
        result = (mc >> 32);
        break;
    case HPET_T0_CMP:
        result = hpet_read32(h, addr);
        break;
    case HPET_T0_CMP + 4:
        result = timer_is_32bit(h, 0) ? 0 : hpet_read32(h, addr);
        break;
    default:
        if ( hpet_check_access_offset(addr) != 0 )
            goto fail;
        result = hpet_read32(h, addr);
        break;
    }

    return result;

 fail:
    return ~0UL;
}

static void hpet_stop_timer(HPETState *h, unsigned int tn)
{
    ASSERT( tn < HPET_TIMER_NUM );
    stop_timer(&h->timers[tn]);
}

static void hpet_set_timer(HPETState *h, unsigned int tn)
{
    uint64_t tn_cmp;
    uint32_t cur_tick;

    ASSERT(tn < HPET_TIMER_NUM);
    
    if ( !hpet_enabled(h) || !timer_enabled(h, tn) )
        return;

    switch ( tn )
    {
    case 0:
        if ( !(h->hpet.config & HPET_CFG_LEGACY) )
        {
            gdprintk(XENLOG_INFO,
                     "HPET: LegacyReplacementRoute not set for timer0\n");
        }
        else
        {
            /* HPET specification requires PIT shouldn't generate
             * interrupts if LegacyReplacementRoute is set for timer0 */
            PITState *pit = &h->vcpu->domain->arch.hvm_domain.pl_time.vpit;
            pit_stop_channel0_irq(pit);
        }
        if ( timer_is_32bit(h, 0) )
            h->t0_period = hpet_tick_to_ns(h, (uint32_t)h->t0_initial_cnt);
        else
            h->t0_period = hpet_tick_to_ns(h, h->t0_initial_cnt);
        h->t0_period = hpet_tick_to_ns(h, h->t0_initial_cnt);
        set_timer(&h->timers[0], NOW() + h->t0_period);
        break;
    case 1:
    case 2: /* only support 32bit timer1 & timer 2 now */
        tn_cmp = h->hpet.timers[tn].c64 & 0xffffffffULL;
        cur_tick = hpet_update_maincounter(h);
        if ( tn_cmp > cur_tick )
            set_timer(&h->timers[tn], NOW() +
                      hpet_tick_to_ns(h, tn_cmp-cur_tick));
        else /* handle the overflow case */
            set_timer(&h->timers[tn], NOW() +
                      hpet_tick_to_ns(h, 0xffffffff-cur_tick+tn_cmp));
        break;
    }
}

static void hpet_write(
    struct vcpu *v, unsigned long addr,
    unsigned long length, unsigned long val)
{
    HPETState *h = &v->domain->arch.hvm_domain.pl_time.vhpet;
    unsigned long old_val;
    int tn, i;

    addr &= HPET_MMAP_SIZE-1;

    if ( hpet_check_access_length(addr, length) != 0 )
        return;

    if ( length == 8 )
    {
        gdprintk(XENLOG_ERR, "HPET: hpet_write with len=8 not implemented\n");
        domain_crash(v->domain);
        return;
    }

    switch ( addr )
    {
    case HPET_ID: 
    case HPET_ID + 4: 
        gdprintk(XENLOG_WARNING,
                 "HPET: Capabilities and ID register is readonly\n");
        break;
    case HPET_CFG: 
        old_val = h->hpet.config;
        h->hpet.config = val;

        if ( !(old_val & HPET_CFG_ENABLE) && (val & HPET_CFG_ENABLE) )
        {
            /* enable main counter & interrupt generating */
            h->mc_offset = h->hpet.mc64 - hvm_get_guest_time(h->vcpu);
            for ( i = 0; i < HPET_TIMER_NUM; i++ )
                hpet_set_timer(h, i); 
        }
        else if ( (old_val & HPET_CFG_ENABLE) && !(val & HPET_CFG_ENABLE) )
        {
            /* halt main counter & disable interrupt generating */
            h->hpet.mc64 = h->mc_offset + hvm_get_guest_time(h->vcpu);
            for ( i = 0; i < HPET_TIMER_NUM; i++ )
                hpet_stop_timer(h, i);
        }
        break;
    case HPET_STATUS:
        hpet_level_triggered_interrupt_not_supported();
        break;
    case HPET_COUNTER:
    case HPET_COUNTER + 4:
        if ( hpet_enabled(h) )
            gdprintk(XENLOG_WARNING, 
                     "HPET: writing main counter but it's not halted!\n");
        hpet_write32(h, addr, val);
        break;
    default:
        if ( hpet_check_access_offset(addr) != 0 )
            break;

        if ( (addr < HPET_T0_CFG) || (addr >= HPET_T2_ROUTE) )
        {
            gdprintk(XENLOG_WARNING,
                     "HPET: writing reserved addr=0x%lx, ignored\n", addr);
            break;
        }

        tn = (addr - HPET_T0_CFG) / 0x20;
        if ( (addr == HPET_T0_CMP + 0x20*tn) || 
             (addr == HPET_T0_CMP + 0x20*tn+4) )
        {
            hpet_write32(h, addr, val);
            if ( addr == HPET_T0_CMP )
                *((uint32_t*)&(h->t0_initial_cnt)) = val;
            else if ( addr == HPET_T0_CMP + 4 )
                *(((uint32_t*)&(h->t0_initial_cnt))+1) = val;
            if( hpet_enabled(h) && timer_enabled(h, tn) )
                hpet_set_timer(h, tn);
        }
        else /* HPET_Tn_CFG or HPET_Tn_CFG+4 */
        {
            if ( addr == (HPET_T0_CFG + 0x20*tn + 4) )
            {
                gdprintk(XENLOG_WARNING,
                         "HPET:  Timer%d_CFG[63..32] is readonly\n", tn);
            }
            else
            {
                old_val = timer_config(h, tn);
                if( (old_val & HPET_TN_CFG_BITS_READONLY_OR_RESERVED) !=
                    (val & HPET_TN_CFG_BITS_READONLY_OR_RESERVED) )
                {
                    gdprintk(XENLOG_ERR,
                             "HPET: TN_CFG writing incorrect value\n");
                    domain_crash(v->domain);
                    break;
                }
                hpet_write32(h, addr, val);

                if ( timer_level(h, tn) )
                {
                    hpet_level_triggered_interrupt_not_supported();
                    break;
                }

                if ( !(old_val & HPET_TN_ENABLE) &&
                     (val & HPET_TN_ENABLE) )
                    hpet_set_timer(h, tn);
                else if ( (old_val & HPET_TN_ENABLE) &&
                          !(val & HPET_TN_ENABLE) )
                    hpet_stop_timer(h, tn); 
            }
        }
        break;
    }
}

static int hpet_range(struct vcpu *v, unsigned long addr)
{
    return ((addr >= HPET_BASE_ADDRESS) &&
            (addr < (HPET_BASE_ADDRESS + HPET_MMAP_SIZE)));
}

struct hvm_mmio_handler hpet_mmio_handler = {
    .check_handler = hpet_range,
    .read_handler = hpet_read,
    .write_handler = hpet_write
};

static void hpet_irq_assert(struct domain *d, 
                            unsigned int isa_irq, unsigned int intr)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    spin_lock(&hvm_irq->lock);

    if ( !__test_and_set_bit(isa_irq, &hvm_irq->isa_irq) &&
         (hvm_irq->gsi_assert_count[isa_irq]++ == 0) )
    {
        vioapic_irq_positive_edge(d, intr);
        vpic_irq_positive_edge(d, isa_irq);
    }

    spin_unlock(&hvm_irq->lock);
}

static void hpet_irq_deassert(struct domain *d,
                unsigned int isa_irq, unsigned int intr)
{
    hvm_isa_irq_deassert(d, isa_irq);
}

static void hpet_set_irq(struct domain *d, int hpet_tn)
{
    int irq, intr;

    if ( (hpet_tn != 0) && (hpet_tn != 1) )
        return;

    /* if LegacyReplacementRoute bit is set, HPET specification requires
       timer0 be routed to IRQ0 in NON-APIC or IRQ2 in the I/O APIC,
       timer1 be routed to IRQ8 in NON-APIC or IRQ8 in the I/O APIC.
       It's hard to distinguish NON-APIC and I/O APIC, so we set both PIC
       and I/O APIC here. Guest OS shall make proper mask setting to ensure
       only one interrupt is injected into it. */
    if ( hpet_tn == 0 )
    {
        irq  = 0;
        intr = 2;
    }
    else
    {
        irq = intr = 8;
    }
    
    hpet_irq_deassert(d, irq, intr);
    hpet_irq_assert(d, irq, intr);
}

static void hpet_route_interrupt(HPETState *h, unsigned int tn)
{
    unsigned int tn_int_route = timer_int_route(h, tn);
    struct domain *d = h->vcpu->domain;
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    if ( (tn_int_route >= VIOAPIC_NUM_PINS) || !timer_int_route_valid(h, tn) )
    {
        gdprintk(XENLOG_ERR,
                 "HPET: timer%u: invalid interrupt route config\n", tn);
        domain_crash(d);
        return;
    }

    /* We only support edge-triggered interrupt now  */
    spin_lock(&hvm_irq->lock);
    vioapic_irq_positive_edge(d, tn_int_route);
    spin_unlock(&hvm_irq->lock);
}

static void hpet_timer_fn(void *opaque)
{
    struct HPET_timer_fn_info *htfi = opaque;
    HPETState *h = htfi->hs;
    unsigned int tn = htfi->tn;

    if ( !hpet_enabled(h) || !timer_enabled(h, tn) )
        return;
    
    if ( timer_level(h, tn) )
    {
        hpet_level_triggered_interrupt_not_supported();
        return;
    }

    switch ( tn )
    {
        case 0:
        case 1:
            if ( h->hpet.config & HPET_CFG_LEGACY )
                hpet_set_irq(h->vcpu->domain, tn);
            else
                hpet_route_interrupt(h, tn);

            if ( (tn == 0) && timer_is_periodic(h, tn) )
            {
                uint64_t mc = hpet_update_maincounter(h);
                if ( timer_is_32bit(h, 0) )
                {
                    while ( hpet_time_after(mc, h->hpet.timers[0].c32) )
                        h->hpet.timers[0].c32 += h->t0_initial_cnt;
                }
                else
                {
                    while ( hpet_time_after64(mc, h->hpet.timers[0].c64) )
                        h->hpet.timers[0].c64 += h->t0_initial_cnt;
                }
                set_timer(&h->timers[tn], NOW() + h->t0_period);
            }
            break;
        case 2:
            hpet_route_interrupt(h, tn);
            break;
        default:
            gdprintk(XENLOG_WARNING,
                     "HPET: timer%u is not supported now\n", tn);
            break;
    }

    vcpu_kick(h->vcpu);    
}

void hpet_migrate_timers(struct vcpu *v)
{
    struct HPETState *h = &v->domain->arch.hvm_domain.pl_time.vhpet;
    int i;

    for ( i = 0; i < HPET_TIMER_NUM; i++ )
        migrate_timer(&h->timers[i], v->processor);
}

void hpet_init(struct vcpu *v)
{
    HPETState *h = &v->domain->arch.hvm_domain.pl_time.vhpet;
    int i;

    memset(h, 0, sizeof(HPETState));

    h->vcpu = v;
    h->tsc_freq = ticks_per_sec(v);
    h->hpet.capability = HPET_CAP_ID_REG;

    /* This is the number of femptoseconds per HPET tick. */
    /* Here we define HPET's frequency as tsc's. */
    h->hpet.capability |= ((S_TO_FS/h->tsc_freq) << 32);

    h->hpet.timers[0].config = HPET_TN_INT_ROUTE_CAP | 
                        HPET_TN_SIZE_CAP | HPET_TN_PERIODIC_CAP;
    h->hpet.timers[0].c64 = HPET_TIMER_CMP64_DEFAULT;

    h->hpet.timers[1].config = HPET_TN_INT_ROUTE_CAP;
    h->hpet.timers[1].c32 = HPET_TIMER_CMP32_DEFAULT;
    h->hpet.timers[2].config = HPET_TN_INT_ROUTE_CAP;
    h->hpet.timers[2].c32 = HPET_TIMER_CMP32_DEFAULT;

    for ( i = 0; i < HPET_TIMER_NUM; i++ )
    {
        h->timer_fn_info[i].hs = h;
        h->timer_fn_info[i].tn = i;
        init_timer(&h->timers[i], hpet_timer_fn, &h->timer_fn_info[i],
                   v->processor);
    }
}

void hpet_deinit(struct domain *d)
{
    int i;
    HPETState *h = &d->arch.hvm_domain.pl_time.vhpet;

    for ( i = 0; i < HPET_TIMER_NUM; i++ )
        kill_timer(&h->timers[i]);
}

