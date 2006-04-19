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
/* Edwin Zhai <edwin.zhai@intel.com>
 * Ported to xen:
 * use actimer for intr generation;
 * move speaker io access to hypervisor;
 * use new method for counter/intrs calculation
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
#include <asm/hvm/vpit.h>
#include <asm/current.h>

/*#define DEBUG_PIT*/

#define RW_STATE_LSB 1
#define RW_STATE_MSB 2
#define RW_STATE_WORD0 3
#define RW_STATE_WORD1 4

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC (1000000000ULL)
#endif

#ifndef TIMER_SLOP 
#define TIMER_SLOP (50*1000) /* ns */
#endif

static void pit_irq_timer_update(PITChannelState *s, s64 current_time);

s_time_t hvm_get_clock(void)
{
    /* TODO: add pause/unpause support */
    return NOW();
}

static int pit_get_count(PITChannelState *s)
{
    u64 d;
    u64 counter;

    d = hvm_get_clock() - s->count_load_time;
    switch(s->mode) {
    case 0:
    case 1:
    case 4:
    case 5:
        counter = (s->period - d) & 0xffff;
        break;
    case 3:
        /* XXX: may be incorrect for odd counts */
        counter = s->period - ((2 * d) % s->period);
        break;
    default:
        /* mod 2 counter handle */
        d = hvm_get_clock() - s->hvm_time->count_point;
        d += s->hvm_time->count_advance;
        counter = s->period - (d % s->period);
        break;
    }
    /* change from ns to pit counter */
    counter = DIV_ROUND( (counter * PIT_FREQ), NSEC_PER_SEC);
    return counter;
}

/* get pit output bit */
static int pit_get_out1(PITChannelState *s, s64 current_time)
{
    u64 d;
    int out;

    d = current_time - s->count_load_time;
    switch(s->mode) {
    default:
    case 0:
        out = (d >= s->period);
        break;
    case 1:
        out = (d < s->period);
        break;
    case 2:
        /* mod2 out is no meaning, since intr are generated in background */
        if ((d % s->period) == 0 && d != 0)
            out = 1;
        else
            out = 0;
        break;
    case 3:
        out = (d % s->period) < ((s->period + 1) >> 1);
        break;
    case 4:
    case 5:
        out = (d == s->period);
        break;
    }
    return out;
}

int pit_get_out(hvm_virpit *pit, int channel, s64 current_time)
{
    PITChannelState *s = &pit->channels[channel];
    return pit_get_out1(s, current_time);
}

static __inline__ s64 missed_ticks(PITChannelState *s, s64 current_time)
{
    struct hvm_time_info *hvm_time = s->hvm_time;
    /* ticks from current time(expected time) to NOW */ 
    int missed_ticks;
    /* current_time is expected time for next intr, check if it's true
     * (actimer has a TIMER_SLOP in advance)
     */
    s64 missed_time = hvm_get_clock() + TIMER_SLOP - current_time;

    if (missed_time >= 0) {
        missed_ticks = missed_time/(s_time_t)s->period + 1;
        hvm_time->pending_intr_nr += missed_ticks;
        s->next_transition_time = current_time + (missed_ticks ) * s->period;
    } else
        printk("HVM_PIT:missed ticks < 0 \n");

    return s->next_transition_time;
}

/* only rearm the actimer when return value > 0
 *  -2: init state
 *  -1: the mode has expired
 *   0: current VCPU is not running
 *  >0: the next fired time
 */
s64 pit_get_next_transition_time(PITChannelState *s, 
                                            s64 current_time)
{
    s64 d, next_time, base;
    int period2;
    struct hvm_time_info *hvm_time = s->hvm_time;

    d = current_time - s->count_load_time;
    switch(s->mode) {
    default:
    case 0:
    case 1:
        if (d < s->period)
            next_time = s->period;
        else
            return -1;
        break;
    case 2:
        if (test_bit(_VCPUF_running, &(hvm_time->vcpu->vcpu_flags)) )
            next_time = missed_ticks(s, current_time);
        else
            return 0;
        break;
    case 3:
        base = (d / s->period) * s->period;
        period2 = ((s->period + 1) >> 1);
        if ((d - base) < period2) 
            next_time = base + period2;
        else
            next_time = base + s->period;
        break;
    case 4:
    case 5:
        if (d < s->period)
            next_time = s->period;
        else if (d == s->period)
            next_time = s->period + 1;
        else
            return -1;
        break;
    case 0xff:
        return -2;      /* for init state */ 
        break;
    }
    /* XXX: better solution: use a clock at PIT_FREQ Hz */
    if (next_time <= current_time){
#ifdef DEBUG_PIT
        printk("HVM_PIT:next_time <= current_time. next=0x%llx, current=0x%llx!\n",next_time, current_time);
#endif
        next_time = current_time + 1;
    }
    return next_time;
}

/* val must be 0 or 1 */
void pit_set_gate(hvm_virpit *pit, int channel, int val)
{
    PITChannelState *s = &pit->channels[channel];

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
            s->count_load_time = hvm_get_clock();
            pit_irq_timer_update(s, s->count_load_time);
        }
        break;
    case 2:
    case 3:
        if (s->gate < val) {
            /* restart counting on rising edge */
            s->count_load_time = hvm_get_clock();
            pit_irq_timer_update(s, s->count_load_time);
        }
        /* XXX: disable/enable counting */
        break;
    }
    s->gate = val;
}

int pit_get_gate(hvm_virpit *pit, int channel)
{
    PITChannelState *s = &pit->channels[channel];
    return s->gate;
}

static inline void pit_load_count(PITChannelState *s, int val)
{
    if (val == 0)
        val = 0x10000;

    s->count_load_time = hvm_get_clock();
    s->count = val;
    s->period = DIV_ROUND(((s->count) * NSEC_PER_SEC), PIT_FREQ);

#ifdef DEBUG_PIT
    printk("HVM_PIT: pit-load-counter, count=0x%x,period=0x%u us,mode=%d, load_time=%lld\n",
            val,
            s->period / 1000,
            s->mode,
            s->count_load_time);
#endif

    if (s->mode == HVM_PIT_ACCEL_MODE) {
        if (!s->hvm_time) {
            printk("HVM_PIT:guest should only set mod 2 on channel 0!\n");
            return;
        }
        s->hvm_time->period_cycles = (u64)s->period * cpu_khz / 1000000L;
        s->hvm_time->first_injected = 0;

        if (s->period < 900000) { /* < 0.9 ms */
            printk("HVM_PIT: guest programmed too small an count: %x\n",
                    s->count);
            s->period = 1000000;
        }
    }
        
    pit_irq_timer_update(s, s->count_load_time);
}

/* if already latched, do not latch again */
static void pit_latch_count(PITChannelState *s)
{
    if (!s->count_latched) {
        s->latched_count = pit_get_count(s);
        s->count_latched = s->rw_mode;
    }
}

static void pit_ioport_write(void *opaque, u32 addr, u32 val)
{
    hvm_virpit *pit = opaque;
    int channel, access;
    PITChannelState *s;
    val &= 0xff;

    addr &= 3;
    if (addr == 3) {
        channel = val >> 6;
        if (channel == 3) {
            /* read back command */
            for(channel = 0; channel < 3; channel++) {
                s = &pit->channels[channel];
                if (val & (2 << channel)) {
                    if (!(val & 0x20)) {
                        pit_latch_count(s);
                    }
                    if (!(val & 0x10) && !s->status_latched) {
                        /* status latch */
                        /* XXX: add BCD and null count */
                        s->status =  (pit_get_out1(s, hvm_get_clock()) << 7) |
                            (s->rw_mode << 4) |
                            (s->mode << 1) |
                            s->bcd;
                        s->status_latched = 1;
                    }
                }
            }
        } else {
            s = &pit->channels[channel];
            access = (val >> 4) & 3;
            if (access == 0) {
                pit_latch_count(s);
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
        s = &pit->channels[addr];
        switch(s->write_state) {
        default:
        case RW_STATE_LSB:
            pit_load_count(s, val);
            break;
        case RW_STATE_MSB:
            pit_load_count(s, val << 8);
            break;
        case RW_STATE_WORD0:
            s->write_latch = val;
            s->write_state = RW_STATE_WORD1;
            break;
        case RW_STATE_WORD1:
            pit_load_count(s, s->write_latch | (val << 8));
            s->write_state = RW_STATE_WORD0;
            break;
        }
    }
}

static u32 pit_ioport_read(void *opaque, u32 addr)
{
    hvm_virpit *pit = opaque;
    int ret, count;
    PITChannelState *s;
    
    addr &= 3;
    s = &pit->channels[addr];
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
            count = pit_get_count(s);
            ret = count & 0xff;
            break;
        case RW_STATE_MSB:
            count = pit_get_count(s);
            ret = (count >> 8) & 0xff;
            break;
        case RW_STATE_WORD0:
            count = pit_get_count(s);
            ret = count & 0xff;
            s->read_state = RW_STATE_WORD1;
            break;
        case RW_STATE_WORD1:
            count = pit_get_count(s);
            ret = (count >> 8) & 0xff;
            s->read_state = RW_STATE_WORD0;
            break;
        }
    }
    return ret;
}

static void pit_irq_timer_update(PITChannelState *s, s64 current_time)
{
    s64 expire_time;
    int irq_level;
    struct vcpu *v = current;
    struct hvm_virpic *pic= &v->domain->arch.hvm_domain.vpic;

    if (!s->hvm_time || s->mode == 0xff)
        return;

    expire_time = pit_get_next_transition_time(s, current_time);
    /* not generate intr by direct pic_set_irq in mod 2
     * XXX:mod 3 should be same as mod 2
     */
    if (s->mode != HVM_PIT_ACCEL_MODE) {
        irq_level = pit_get_out1(s, current_time);
        pic_set_irq(pic, s->irq, irq_level);
        s->next_transition_time = expire_time;
#ifdef DEBUG_PIT
        printk("HVM_PIT:irq_level=%d next_delay=%l ns\n",
                irq_level, 
                (expire_time - current_time));
#endif
    }

    if (expire_time > 0)
        set_timer(&(s->hvm_time->pit_timer), s->next_transition_time);

}

static void pit_irq_timer(void *data)
{
    PITChannelState *s = data;

    pit_irq_timer_update(s, s->next_transition_time);
}

static void pit_reset(void *opaque)
{
    hvm_virpit *pit = opaque;
    PITChannelState *s;
    int i;

    for(i = 0;i < 3; i++) {
        s = &pit->channels[i];
        s->mode = 0xff; /* the init mode */
        s->gate = (i != 2);
        pit_load_count(s, 0);
    }
}

/* hvm_io_assist light-weight version, specific to PIT DM */ 
static void resume_pit_io(ioreq_t *p)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    unsigned long old_eax = regs->eax;
    p->state = STATE_INVALID;

    switch(p->size) {
    case 1:
        regs->eax = (old_eax & 0xffffff00) | (p->u.data & 0xff);
        break;
    case 2:
        regs->eax = (old_eax & 0xffff0000) | (p->u.data & 0xffff);
        break;
    case 4:
        regs->eax = (p->u.data & 0xffffffff);
        break;
    default:
        BUG();
    }
}

/* the intercept action for PIT DM retval:0--not handled; 1--handled */  
int handle_pit_io(ioreq_t *p)
{
    struct vcpu *v = current;
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);

    if (p->size != 1 ||
        p->pdata_valid ||
        p->type != IOREQ_TYPE_PIO){
        printk("HVM_PIT:wrong PIT IO!\n");
        return 1;
    }
    
    if (p->dir == 0) {/* write */
        pit_ioport_write(vpit, p->addr, p->u.data);
    } else if (p->dir == 1) { /* read */
        p->u.data = pit_ioport_read(vpit, p->addr);
        resume_pit_io(p);
    }

    /* always return 1, since PIT sit in HV now */
    return 1;
}

static void speaker_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    hvm_virpit *pit = opaque;
    val &= 0xff;
    pit->speaker_data_on = (val >> 1) & 1;
    pit_set_gate(pit, 2, val & 1);
}

static uint32_t speaker_ioport_read(void *opaque, uint32_t addr)
{
    int out;
    hvm_virpit *pit = opaque;
    out = pit_get_out(pit, 2, hvm_get_clock());
    pit->dummy_refresh_clock ^= 1;

    return (pit->speaker_data_on << 1) | pit_get_gate(pit, 2) | (out << 5) |
      (pit->dummy_refresh_clock << 4);
}

int handle_speaker_io(ioreq_t *p)
{
    struct vcpu *v = current;
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);

    if (p->size != 1 ||
        p->pdata_valid ||
        p->type != IOREQ_TYPE_PIO){
        printk("HVM_SPEAKER:wrong SPEAKER IO!\n");
        return 1;
    }
    
    if (p->dir == 0) {/* write */
        speaker_ioport_write(vpit, p->addr, p->u.data);
    } else if (p->dir == 1) {/* read */
        p->u.data = speaker_ioport_read(vpit, p->addr);
        resume_pit_io(p);
    }

    return 1;
}

/* pick up missed timer ticks at deactive time */
void pickup_deactive_ticks(struct hvm_virpit *vpit)
{
    s64 next_time;
    PITChannelState *s = &(vpit->channels[0]);
    if ( !active_timer(&(vpit->time_info.pit_timer)) ) {
        next_time = pit_get_next_transition_time(s, s->next_transition_time); 
        if (next_time > 0)
            set_timer(&(s->hvm_time->pit_timer), s->next_transition_time);
        else {
            printk("HVM_PIT:not set_timer before resume next_time=%lld!\n", next_time);
            next_time = s->next_transition_time;
        }
    }
}

void pit_init(struct hvm_virpit *pit, struct vcpu *v)
{
    PITChannelState *s;
    struct hvm_time_info *hvm_time;

    s = &pit->channels[0];
    /* the timer 0 is connected to an IRQ */
    s->irq = 0;
    /* channel 0 need access the related time info for intr injection */
    hvm_time = s->hvm_time = &pit->time_info;
    hvm_time->vcpu = v;

    init_timer(&(hvm_time->pit_timer), pit_irq_timer, s, v->processor);

    register_portio_handler(PIT_BASE, 4, handle_pit_io);

    /* register the speaker port */
    register_portio_handler(0x61, 1, handle_speaker_io);

    pit_reset(pit);

    return;

}
