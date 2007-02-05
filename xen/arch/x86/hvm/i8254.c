/*
 * QEMU 8253/8254 interval timer emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2006 Intel Corperation
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/* Edwin Zhai <edwin.zhai@intel.com>, Eddie Dong <eddie.dong@intel.com>
 * Ported to xen:
 * Add a new layer of periodic time on top of PIT;
 * move speaker io access to hypervisor;
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/current.h>

/* Enable DEBUG_PIT may cause guest calibration inaccuracy */
/* #define DEBUG_PIT */

#define RW_STATE_LSB 1
#define RW_STATE_MSB 2
#define RW_STATE_WORD0 3
#define RW_STATE_WORD1 4

static int handle_pit_io(ioreq_t *p);
static int handle_speaker_io(ioreq_t *p);

/* compute with 96 bit intermediate result: (a*b)/c */
uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
    union {
        uint64_t ll;
        struct {
#ifdef WORDS_BIGENDIAN
            uint32_t high, low;
#else
            uint32_t low, high;
#endif            
        } l;
    } u, res;
    uint64_t rl, rh;

    u.ll = a;
    rl = (uint64_t)u.l.low * (uint64_t)b;
    rh = (uint64_t)u.l.high * (uint64_t)b;
    rh += (rl >> 32);
    res.l.high = rh / c;
    res.l.low = (((rh % c) << 32) + (rl & 0xffffffff)) / c;
    return res.ll;
}

static int pit_get_count(PITState *s, int channel)
{
    uint64_t d;
    int  counter;
    struct hvm_hw_pit_channel *c = &s->hw.channels[channel];
    struct periodic_time *pt = &s->pt[channel];

    d = muldiv64(hvm_get_guest_time(pt->vcpu) - s->count_load_time[channel],
                 PIT_FREQ, ticks_per_sec(pt->vcpu));
    switch(c->mode) {
    case 0:
    case 1:
    case 4:
    case 5:
        counter = (c->count - d) & 0xffff;
        break;
    case 3:
        /* XXX: may be incorrect for odd counts */
        counter = c->count - ((2 * d) % c->count);
        break;
    default:
        counter = c->count - (d % c->count);
        break;
    }
    return counter;
}

/* get pit output bit */
int pit_get_out(PITState *pit, int channel, int64_t current_time)
{
    struct hvm_hw_pit_channel *s = &pit->hw.channels[channel];
    uint64_t d;
    int out;

    d = muldiv64(current_time - pit->count_load_time[channel], 
                 PIT_FREQ, ticks_per_sec(pit->pt[channel].vcpu));
    switch(s->mode) {
    default:
    case 0:
        out = (d >= s->count);
        break;
    case 1:
        out = (d < s->count);
        break;
    case 2:
        if ((d % s->count) == 0 && d != 0)
            out = 1;
        else
            out = 0;
        break;
    case 3:
        out = (d % s->count) < ((s->count + 1) >> 1);
        break;
    case 4:
    case 5:
        out = (d == s->count);
        break;
    }
    return out;
}

/* val must be 0 or 1 */
void pit_set_gate(PITState *pit, int channel, int val)
{
    struct hvm_hw_pit_channel *s = &pit->hw.channels[channel];
    struct periodic_time *pt = &pit->pt[channel];

    switch(s->mode) {
    default:
    case 0:
    case 4:
        /* XXX: just disable/enable counting */
        break;
    case 1:
    case 5:
        if (s->gate < val) {
            /* restart counting on rising edge */
            pit->count_load_time[channel] = hvm_get_guest_time(pt->vcpu);
//            pit_irq_timer_update(s, s->count_load_time);
        }
        break;
    case 2:
    case 3:
        if (s->gate < val) {
            /* restart counting on rising edge */
            pit->count_load_time[channel] = hvm_get_guest_time(pt->vcpu);
//            pit_irq_timer_update(s, s->count_load_time);
        }
        /* XXX: disable/enable counting */
        break;
    }
    s->gate = val;
}

int pit_get_gate(PITState *pit, int channel)
{
    return pit->hw.channels[channel].gate;
}

void pit_time_fired(struct vcpu *v, void *priv)
{
    uint64_t *count_load_time = priv;
    *count_load_time = hvm_get_guest_time(v);
}

static inline void pit_load_count(PITState *pit, int channel, int val)
{
    u32 period;
    struct hvm_hw_pit_channel *s = &pit->hw.channels[channel];
    struct periodic_time *pt = &pit->pt[channel];
    struct vcpu *v;

    if (val == 0)
        val = 0x10000;
    pit->count_load_time[channel] = hvm_get_guest_time(pt->vcpu);
    s->count = val;
    period = DIV_ROUND((val * 1000000000ULL), PIT_FREQ);

    if (channel != 0)
        return;

#ifdef DEBUG_PIT
    printk("HVM_PIT: pit-load-counter(%p), count=0x%x, period=%uns mode=%d, load_time=%lld\n",
            s,
            val,
            period,
            s->mode,
            (long long)pit->count_load_time[channel]);
#endif

    /* Choose a vcpu to set the timer on: current if appropriate else vcpu 0 */
    if ( likely(pit == &current->domain->arch.hvm_domain.pl_time.vpit) )
        v = current;
    else 
        v = container_of(pit, struct domain, 
                         arch.hvm_domain.pl_time.vpit)->vcpu[0];

    switch (s->mode) {
        case 2:
            /* create periodic time */
            create_periodic_time(v, pt, period, 0, 0, pit_time_fired, 
                                 &pit->count_load_time[channel]);
            break;
        case 1:
            /* create one shot time */
            create_periodic_time(v, pt, period, 0, 1, pit_time_fired,
                                 &pit->count_load_time[channel]);
#ifdef DEBUG_PIT
            printk("HVM_PIT: create one shot time.\n");
#endif
            break;
        default:
            destroy_periodic_time(pt);
            break;
    }
}

/* if already latched, do not latch again */
static void pit_latch_count(PITState *s, int channel)
{
    struct hvm_hw_pit_channel *c = &s->hw.channels[channel];
    if (!c->count_latched) {
        c->latched_count = pit_get_count(s, channel);
        c->count_latched = c->rw_mode;
    }
}

static void pit_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    PITState *pit = opaque;
    int channel, access;
    struct hvm_hw_pit_channel *s;
    val &= 0xff;

    addr &= 3;
    if (addr == 3) {
        channel = val >> 6;
        if (channel == 3) {
            /* read back command */
            for(channel = 0; channel < 3; channel++) {
                s = &pit->hw.channels[channel];
                if (val & (2 << channel)) {
                    if (!(val & 0x20)) {
                        pit_latch_count(pit, channel);
                    }
                    if (!(val & 0x10) && !s->status_latched) {
                        /* status latch */
                        /* XXX: add BCD and null count */
                        s->status = (pit_get_out(pit, channel, hvm_get_guest_time(pit->pt[channel].vcpu)) << 7) |
                            (s->rw_mode << 4) |
                            (s->mode << 1) |
                            s->bcd;
                        s->status_latched = 1;
                    }
                }
            }
        } else {
            s = &pit->hw.channels[channel];
            access = (val >> 4) & 3;
            if (access == 0) {
                pit_latch_count(pit, channel);
            } else {
                s->rw_mode = access;
                s->read_state = access;
                s->write_state = access;

                s->mode = (val >> 1) & 7;
                s->bcd = val & 1;
                /* XXX: update irq timer ? */
            }
        }
    } else {
        s = &pit->hw.channels[addr];
        switch(s->write_state) {
        default:
        case RW_STATE_LSB:
            pit_load_count(pit, addr, val);
            break;
        case RW_STATE_MSB:
            pit_load_count(pit, addr, val << 8);
            break;
        case RW_STATE_WORD0:
            s->write_latch = val;
            s->write_state = RW_STATE_WORD1;
            break;
        case RW_STATE_WORD1:
            pit_load_count(pit, addr, s->write_latch | (val << 8));
            s->write_state = RW_STATE_WORD0;
            break;
        }
    }
}

static uint32_t pit_ioport_read(void *opaque, uint32_t addr)
{
    PITState *pit = opaque;
    int ret, count;
    struct hvm_hw_pit_channel *s;
    
    addr &= 3;
    s = &pit->hw.channels[addr];
    if (s->status_latched) {
        s->status_latched = 0;
        ret = s->status;
    } else if (s->count_latched) {
        switch(s->count_latched) {
        default:
        case RW_STATE_LSB:
            ret = s->latched_count & 0xff;
            s->count_latched = 0;
            break;
        case RW_STATE_MSB:
            ret = s->latched_count >> 8;
            s->count_latched = 0;
            break;
        case RW_STATE_WORD0:
            ret = s->latched_count & 0xff;
            s->count_latched = RW_STATE_MSB;
            break;
        }
    } else {
        switch(s->read_state) {
        default:
        case RW_STATE_LSB:
            count = pit_get_count(pit, addr);
            ret = count & 0xff;
            break;
        case RW_STATE_MSB:
            count = pit_get_count(pit, addr);
            ret = (count >> 8) & 0xff;
            break;
        case RW_STATE_WORD0:
            count = pit_get_count(pit, addr);
            ret = count & 0xff;
            s->read_state = RW_STATE_WORD1;
            break;
        case RW_STATE_WORD1:
            count = pit_get_count(pit, addr);
            ret = (count >> 8) & 0xff;
            s->read_state = RW_STATE_WORD0;
            break;
        }
    }
    return ret;
}

void pit_stop_channel0_irq(PITState * pit)
{
    destroy_periodic_time(&pit->pt[0]);
}

#ifdef HVM_DEBUG_SUSPEND
static void pit_info(PITState *pit)
{
    struct hvm_hw_pit_channel *s;
    struct periodic_time *pt;
    int i;

    for(i = 0; i < 3; i++) {
        printk("*****pit channel %d's state:*****\n", i);
        s = &pit->hw.channels[i];
        printk("pit 0x%x.\n", s->count);
        printk("pit 0x%x.\n", s->latched_count);
        printk("pit 0x%x.\n", s->count_latched);
        printk("pit 0x%x.\n", s->status_latched);
        printk("pit 0x%x.\n", s->status);
        printk("pit 0x%x.\n", s->read_state);
        printk("pit 0x%x.\n", s->write_state);
        printk("pit 0x%x.\n", s->write_latch);
        printk("pit 0x%x.\n", s->rw_mode);
        printk("pit 0x%x.\n", s->mode);
        printk("pit 0x%x.\n", s->bcd);
        printk("pit 0x%x.\n", s->gate);
        printk("pit %"PRId64"\n", pit->count_load_time[i]);

        pt = &pit->pt[i];
        if (pt) {
            printk("pit channel %d has a periodic timer:\n", i);
            printk("pt %d.\n", pt->enabled);
            printk("pt %d.\n", pt->one_shot);
            printk("pt %d.\n", pt->irq);
            printk("pt %d.\n", pt->first_injected);

            printk("pt %d.\n", pt->pending_intr_nr);
            printk("pt %d.\n", pt->period);
            printk("pt %"PRId64"\n", pt->period_cycles);
            printk("pt %"PRId64"\n", pt->last_plt_gtime);
        }
    }

}
#else
static void pit_info(PITState *pit)
{
}
#endif

static int pit_save(struct domain *d, hvm_domain_context_t *h)
{
    PITState *pit = &d->arch.hvm_domain.pl_time.vpit;
    
    pit_info(pit);

    /* Save the PIT hardware state */
    return hvm_save_entry(PIT, 0, h, &pit->hw);
}

static int pit_load(struct domain *d, hvm_domain_context_t *h)
{
    PITState *pit = &d->arch.hvm_domain.pl_time.vpit;
    int i;

    /* Restore the PIT hardware state */
    if ( hvm_load_entry(PIT, h, &pit->hw) )
        return 1;
    
    /* Recreate platform timers from hardware state.  There will be some 
     * time jitter here, but the wall-clock will have jumped massively, so 
     * we hope the guest can handle it. */

    for(i = 0; i < 3; i++) {
        pit_load_count(pit, i, pit->hw.channels[i].count);
        pit->pt[i].last_plt_gtime = hvm_get_guest_time(d->vcpu[0]);
    }

    pit_info(pit);
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(PIT, pit_save, pit_load);

static void pit_reset(void *opaque)
{
    PITState *pit = opaque;
    struct hvm_hw_pit_channel *s;
    int i;

    for(i = 0;i < 3; i++) {
        s = &pit->hw.channels[i];
        destroy_periodic_time(&pit->pt[i]);
        s->mode = 0xff; /* the init mode */
        s->gate = (i != 2);
        pit_load_count(pit, i, 0);
    }
}

void pit_init(struct vcpu *v, unsigned long cpu_khz)
{
    PITState *pit = &v->domain->arch.hvm_domain.pl_time.vpit;
    struct periodic_time *pt;

    pt = &pit->pt[0];  
    pt->vcpu = v;
    /* the timer 0 is connected to an IRQ */
    init_timer(&pt->timer, pt_timer_fn, pt, v->processor);
    pt++; pt->vcpu = v;
    pt++; pt->vcpu = v;

    register_portio_handler(v->domain, PIT_BASE, 4, handle_pit_io);
    /* register the speaker port */
    register_portio_handler(v->domain, 0x61, 1, handle_speaker_io);
    ticks_per_sec(v) = cpu_khz * (int64_t)1000;
#ifdef DEBUG_PIT
    printk("HVM_PIT: guest frequency =%lld\n", (long long)ticks_per_sec(v));
#endif
    pit_reset(pit);
    return;
}

void pit_migrate_timers(struct vcpu *v)
{
    PITState *pit = &v->domain->arch.hvm_domain.pl_time.vpit;
    struct periodic_time *pt;

    pt = &pit->pt[0];
    if ( pt->vcpu == v && pt->enabled )
        migrate_timer(&pt->timer, v->processor);
}

void pit_deinit(struct domain *d)
{
    PITState *pit = &d->arch.hvm_domain.pl_time.vpit;

    kill_timer(&pit->pt[0].timer);
}

/* the intercept action for PIT DM retval:0--not handled; 1--handled */  
static int handle_pit_io(ioreq_t *p)
{
    struct vcpu *v = current;
    struct PITState *vpit = &(v->domain->arch.hvm_domain.pl_time.vpit);

    if (p->size != 1 ||
        p->data_is_ptr ||
        p->type != IOREQ_TYPE_PIO){
        printk("HVM_PIT:wrong PIT IO!\n");
        return 1;
    }
    
    if (p->dir == 0) {/* write */
        pit_ioport_write(vpit, p->addr, p->data);
    } else if (p->dir == 1) { /* read */
        if ( (p->addr & 3) != 3 ) {
            p->data = pit_ioport_read(vpit, p->addr);
        } else {
            printk("HVM_PIT: read A1:A0=3!\n");
        }
    }
    return 1;
}

static void speaker_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    PITState *pit = opaque;
    pit->hw.speaker_data_on = (val >> 1) & 1;
    pit_set_gate(pit, 2, val & 1);
}

static uint32_t speaker_ioport_read(void *opaque, uint32_t addr)
{
    PITState *pit = opaque;
    int out = pit_get_out(pit, 2,
                          hvm_get_guest_time(pit->pt[2].vcpu));
    /* Refresh clock toggles at about 15us. We approximate as 2^14ns. */
    unsigned int refresh_clock = ((unsigned int)NOW() >> 14) & 1;
    return ((pit->hw.speaker_data_on << 1) | pit_get_gate(pit, 2) |
            (out << 5) | refresh_clock << 4);
}

static int handle_speaker_io(ioreq_t *p)
{
    struct vcpu *v = current;
    struct PITState *vpit = &(v->domain->arch.hvm_domain.pl_time.vpit);

    if (p->size != 1 ||
        p->data_is_ptr ||
        p->type != IOREQ_TYPE_PIO){
        printk("HVM_SPEAKER:wrong SPEAKER IO!\n");
        return 1;
    }

    if (p->dir == 0) {/* write */
        speaker_ioport_write(vpit, p->addr, p->data);
    } else if (p->dir == 1) {/* read */
        p->data = speaker_ioport_read(vpit, p->addr);
    }

    return 1;
}

int pv_pit_handler(int port, int data, int write)
{
    ioreq_t ioreq = {
        .size = 1,
        .type = IOREQ_TYPE_PIO,
        .addr = port,
        .dir  = write ? 0 : 1,
        .data = write ? data : 0,
    };

    if (port == 0x61)
        handle_speaker_io(&ioreq);
    else
        handle_pit_io(&ioreq);

    return !write ? ioreq.data : 0;
}
