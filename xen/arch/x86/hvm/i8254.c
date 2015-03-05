/*
 * QEMU 8253/8254 interval timer emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2006 Intel Corperation
 * Copyright (c) 2007 Keir Fraser, XenSource Inc.
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

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/trace.h>
#include <asm/time.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/current.h>

#define domain_vpit(x) (&(x)->arch.vpit)
#define vcpu_vpit(x)   (domain_vpit((x)->domain))
#define vpit_domain(x) (container_of((x), struct domain, arch.vpit))
#define vpit_vcpu(x)   (pt_global_vcpu_target(vpit_domain(x)))

#define RW_STATE_LSB 1
#define RW_STATE_MSB 2
#define RW_STATE_WORD0 3
#define RW_STATE_WORD1 4

static int handle_pit_io(
    int dir, uint32_t port, uint32_t bytes, uint32_t *val);
static int handle_speaker_io(
    int dir, uint32_t port, uint32_t bytes, uint32_t *val);

#define get_guest_time(v) \
   (is_hvm_vcpu(v) ? hvm_get_guest_time(v) : (u64)get_s_time())

static int pit_get_count(PITState *pit, int channel)
{
    uint64_t d;
    int  counter;
    struct hvm_hw_pit_channel *c = &pit->hw.channels[channel];
    struct vcpu *v = vpit_vcpu(pit);

    ASSERT(spin_is_locked(&pit->lock));

    d = muldiv64(get_guest_time(v) - pit->count_load_time[channel],
                 PIT_FREQ, SYSTEM_TIME_HZ);

    switch ( c->mode )
    {
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

static int pit_get_out(PITState *pit, int channel)
{
    struct hvm_hw_pit_channel *s = &pit->hw.channels[channel];
    uint64_t d;
    int out;
    struct vcpu *v = vpit_vcpu(pit);

    ASSERT(spin_is_locked(&pit->lock));

    d = muldiv64(get_guest_time(v) - pit->count_load_time[channel], 
                 PIT_FREQ, SYSTEM_TIME_HZ);

    switch ( s->mode )
    {
    default:
    case 0:
        out = (d >= s->count);
        break;
    case 1:
        out = (d < s->count);
        break;
    case 2:
        out = (((d % s->count) == 0) && (d != 0));
        break;
    case 3:
        out = ((d % s->count) < ((s->count + 1) >> 1));
        break;
    case 4:
    case 5:
        out = (d == s->count);
        break;
    }

    return out;
}

static void pit_set_gate(PITState *pit, int channel, int val)
{
    struct hvm_hw_pit_channel *s = &pit->hw.channels[channel];
    struct vcpu *v = vpit_vcpu(pit);

    ASSERT(spin_is_locked(&pit->lock));

    switch ( s->mode )
    {
    default:
    case 0:
    case 4:
        /* XXX: just disable/enable counting */
        break;
    case 1:
    case 5:
    case 2:
    case 3:
        /* Restart counting on rising edge. */
        if ( s->gate < val )
            pit->count_load_time[channel] = get_guest_time(v);
        break;
    }

    s->gate = val;
}

static int pit_get_gate(PITState *pit, int channel)
{
    ASSERT(spin_is_locked(&pit->lock));
    return pit->hw.channels[channel].gate;
}

static void pit_time_fired(struct vcpu *v, void *priv)
{
    uint64_t *count_load_time = priv;
    TRACE_0D(TRC_HVM_EMUL_PIT_TIMER_CB);
    *count_load_time = get_guest_time(v);
}

static void pit_load_count(PITState *pit, int channel, int val)
{
    u32 period;
    struct hvm_hw_pit_channel *s = &pit->hw.channels[channel];
    struct vcpu *v = vpit_vcpu(pit);

    ASSERT(spin_is_locked(&pit->lock));

    if ( val == 0 )
        val = 0x10000;

    if ( v == NULL )
        pit->count_load_time[channel] = 0;
    else
        pit->count_load_time[channel] = get_guest_time(v);
    s->count = val;
    period = DIV_ROUND(val * SYSTEM_TIME_HZ, PIT_FREQ);

    if ( (v == NULL) || !is_hvm_vcpu(v) || (channel != 0) )
        return;

    switch ( s->mode )
    {
    case 2:
    case 3:
        /* Periodic timer. */
        TRACE_2D(TRC_HVM_EMUL_PIT_START_TIMER, period, period);
        create_periodic_time(v, &pit->pt0, period, period, 0, pit_time_fired, 
                             &pit->count_load_time[channel]);
        break;
    case 1:
    case 4:
        /* One-shot timer. */
        TRACE_2D(TRC_HVM_EMUL_PIT_START_TIMER, period, 0);
        create_periodic_time(v, &pit->pt0, period, 0, 0, pit_time_fired,
                             &pit->count_load_time[channel]);
        break;
    default:
        TRACE_0D(TRC_HVM_EMUL_PIT_STOP_TIMER);
        destroy_periodic_time(&pit->pt0);
        break;
    }
}

static void pit_latch_count(PITState *pit, int channel)
{
    struct hvm_hw_pit_channel *c = &pit->hw.channels[channel];

    ASSERT(spin_is_locked(&pit->lock));

    if ( !c->count_latched )
    {
        c->latched_count = pit_get_count(pit, channel);
        c->count_latched = c->rw_mode;
    }
}

static void pit_latch_status(PITState *pit, int channel)
{
    struct hvm_hw_pit_channel *c = &pit->hw.channels[channel];

    ASSERT(spin_is_locked(&pit->lock));

    if ( !c->status_latched )
    {
        /* TODO: Return NULL COUNT (bit 6). */
        c->status = ((pit_get_out(pit, channel) << 7) |
                     (c->rw_mode << 4) |
                     (c->mode << 1) |
                     c->bcd);
        c->status_latched = 1;
    }
}

static void pit_ioport_write(struct PITState *pit, uint32_t addr, uint32_t val)
{
    int channel, access;
    struct hvm_hw_pit_channel *s;

    val  &= 0xff;
    addr &= 3;

    spin_lock(&pit->lock);

    if ( addr == 3 )
    {
        channel = val >> 6;
        if ( channel == 3 )
        {
            /* Read-Back Command. */
            for ( channel = 0; channel < 3; channel++ )
            {
                s = &pit->hw.channels[channel];
                if ( val & (2 << channel) )
                {
                    if ( !(val & 0x20) )
                        pit_latch_count(pit, channel);
                    if ( !(val & 0x10) )
                        pit_latch_status(pit, channel);
                }
            }
        }
        else
        {
            /* Select Counter <channel>. */
            s = &pit->hw.channels[channel];
            access = (val >> 4) & 3;
            if ( access == 0 )
            {
                pit_latch_count(pit, channel);
            }
            else
            {
                s->rw_mode = access;
                s->read_state = access;
                s->write_state = access;
                s->mode = (val >> 1) & 7;
                if ( s->mode > 5 )
                    s->mode -= 4;
                s->bcd = val & 1;
                /* XXX: update irq timer ? */
            }
        }
    }
    else
    {
        /* Write Count. */
        s = &pit->hw.channels[addr];
        switch ( s->write_state )
        {
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

    spin_unlock(&pit->lock);
}

static uint32_t pit_ioport_read(struct PITState *pit, uint32_t addr)
{
    int ret, count;
    struct hvm_hw_pit_channel *s;
    
    addr &= 3;
    s = &pit->hw.channels[addr];

    spin_lock(&pit->lock);

    if ( s->status_latched )
    {
        s->status_latched = 0;
        ret = s->status;
    }
    else if ( s->count_latched )
    {
        switch ( s->count_latched )
        {
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
    }
    else
    {
        switch ( s->read_state )
        {
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

    spin_unlock(&pit->lock);

    return ret;
}

void pit_stop_channel0_irq(PITState *pit)
{
    TRACE_0D(TRC_HVM_EMUL_PIT_STOP_TIMER);
    spin_lock(&pit->lock);
    destroy_periodic_time(&pit->pt0);
    spin_unlock(&pit->lock);
}

static int pit_save(struct domain *d, hvm_domain_context_t *h)
{
    PITState *pit = domain_vpit(d);
    int rc;

    spin_lock(&pit->lock);
    
    rc = hvm_save_entry(PIT, 0, h, &pit->hw);

    spin_unlock(&pit->lock);

    return rc;
}

static int pit_load(struct domain *d, hvm_domain_context_t *h)
{
    PITState *pit = domain_vpit(d);
    int i;

    spin_lock(&pit->lock);

    if ( hvm_load_entry(PIT, h, &pit->hw) )
    {
        spin_unlock(&pit->lock);
        return 1;
    }
    
    /*
     * Recreate platform timers from hardware state.  There will be some 
     * time jitter here, but the wall-clock will have jumped massively, so 
     * we hope the guest can handle it.
     */
    pit->pt0.last_plt_gtime = get_guest_time(d->vcpu[0]);
    for ( i = 0; i < 3; i++ )
        pit_load_count(pit, i, pit->hw.channels[i].count);

    spin_unlock(&pit->lock);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(PIT, pit_save, pit_load, 1, HVMSR_PER_DOM);

void pit_reset(struct domain *d)
{
    PITState *pit = domain_vpit(d);
    struct hvm_hw_pit_channel *s;
    int i;

    TRACE_0D(TRC_HVM_EMUL_PIT_STOP_TIMER);
    destroy_periodic_time(&pit->pt0);
    pit->pt0.source = PTSRC_isa;

    spin_lock(&pit->lock);

    for ( i = 0; i < 3; i++ )
    {
        s = &pit->hw.channels[i];
        s->mode = 0xff; /* the init mode */
        s->gate = (i != 2);
        pit_load_count(pit, i, 0);
    }

    spin_unlock(&pit->lock);
}

void pit_init(struct domain *d, unsigned long cpu_khz)
{
    PITState *pit = domain_vpit(d);

    spin_lock_init(&pit->lock);

    if ( is_hvm_domain(d) )
    {
        register_portio_handler(d, PIT_BASE, 4, handle_pit_io);
        register_portio_handler(d, 0x61, 1, handle_speaker_io);
    }

    pit_reset(d);
}

void pit_deinit(struct domain *d)
{
    PITState *pit = domain_vpit(d);

    TRACE_0D(TRC_HVM_EMUL_PIT_STOP_TIMER);
    destroy_periodic_time(&pit->pt0);
}

/* the intercept action for PIT DM retval:0--not handled; 1--handled */  
static int handle_pit_io(
    int dir, uint32_t port, uint32_t bytes, uint32_t *val)
{
    struct PITState *vpit = vcpu_vpit(current);

    if ( bytes != 1 )
    {
        gdprintk(XENLOG_WARNING, "PIT bad access\n");
        *val = ~0;
        return X86EMUL_OKAY;
    }

    if ( dir == IOREQ_WRITE )
    {
        pit_ioport_write(vpit, port, *val);
    }
    else
    {
        if ( (port & 3) != 3 )
            *val = pit_ioport_read(vpit, port);
        else
            gdprintk(XENLOG_WARNING, "PIT: read A1:A0=3!\n");
    }

    return X86EMUL_OKAY;
}

static void speaker_ioport_write(
    struct PITState *pit, uint32_t addr, uint32_t val)
{
    pit->hw.speaker_data_on = (val >> 1) & 1;
    pit_set_gate(pit, 2, val & 1);
}

static uint32_t speaker_ioport_read(
    struct PITState *pit, uint32_t addr)
{
    /* Refresh clock toggles at about 15us. We approximate as 2^14ns. */
    unsigned int refresh_clock = ((unsigned int)NOW() >> 14) & 1;
    return ((pit->hw.speaker_data_on << 1) | pit_get_gate(pit, 2) |
            (pit_get_out(pit, 2) << 5) | (refresh_clock << 4));
}

static int handle_speaker_io(
    int dir, uint32_t port, uint32_t bytes, uint32_t *val)
{
    struct PITState *vpit = vcpu_vpit(current);

    BUG_ON(bytes != 1);

    spin_lock(&vpit->lock);

    if ( dir == IOREQ_WRITE )
        speaker_ioport_write(vpit, port, *val);
    else
        *val = speaker_ioport_read(vpit, port);

    spin_unlock(&vpit->lock);

    return X86EMUL_OKAY;
}

int pv_pit_handler(int port, int data, int write)
{
    ioreq_t ioreq = {
        .size = 1,
        .type = IOREQ_TYPE_PIO,
        .addr = port,
        .dir  = write ? IOREQ_WRITE : IOREQ_READ,
        .data = data
    };

    if ( is_hardware_domain(current->domain) && hwdom_pit_access(&ioreq) )
    {
        /* nothing to do */;
    }
    else
    {
        uint32_t val = data;
        if ( port == 0x61 )
            handle_speaker_io(ioreq.dir, port, 1, &val);
        else
            handle_pit_io(ioreq.dir, port, 1, &val);
        ioreq.data = val;
    }

    return !write ? ioreq.data : 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
