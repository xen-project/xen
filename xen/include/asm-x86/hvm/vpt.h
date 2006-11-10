/*
 * vpt.h: Virtual Platform Timer definitions
 *
 * Copyright (c) 2004, Intel Corporation.
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

#ifndef __ASM_X86_HVM_VPT_H__
#define __ASM_X86_HVM_VPT_H__

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <asm/hvm/vpic.h>

#define PIT_FREQ 1193181
#define PIT_BASE 0x40

typedef struct PITChannelState {
    int count; /* can be 65536 */
    u16 latched_count;
    u8 count_latched;
    u8 status_latched;
    u8 status;
    u8 read_state;
    u8 write_state;
    u8 write_latch;
    u8 rw_mode;
    u8 mode;
    u8 bcd; /* not supported */
    u8 gate; /* timer start */
    s64 count_load_time;
    /* irq handling */
    struct vcpu      *vcpu;
    struct periodic_time *pt;
} PITChannelState;

typedef struct PITState {
    PITChannelState channels[3];
    int speaker_data_on;
    int dummy_refresh_clock;
} PITState;

#define RTC_SIZE 14
typedef struct RTCState {
    uint8_t cmos_data[RTC_SIZE];  /* Only handle time/interrupt part in HV */
    uint8_t cmos_index;
    struct tm current_tm;
    int irq;
    /* second update */
    int64_t next_second_time;
    struct timer second_timer;
    struct timer second_timer2;
    struct vcpu      *vcpu;
    struct periodic_time *pt;
} RTCState;

#define FREQUENCE_PMTIMER  3579545
typedef struct PMTState {
    uint32_t pm1_timer;
    uint32_t pm1_status;
    uint64_t last_gtime;
    struct timer timer;
    uint64_t scale;
    struct vcpu *vcpu;
} PMTState;

/*
 * Abstract layer of periodic time, one short time.
 */
typedef void time_cb(struct vcpu *v, void *opaque);

struct periodic_time {
    char enabled;               /* enabled */
    char one_shot;              /* one shot time */
    char irq;
    char first_injected;        /* flag to prevent shadow window */
    u32 bind_vcpu;              /* vcpu timer interrupt delivers to */
    u32 pending_intr_nr;        /* the couner for pending timer interrupts */
    u32 period;                 /* frequency in ns */
    u64 period_cycles;          /* frequency in cpu cycles */
    s_time_t scheduled;         /* scheduled timer interrupt */
    u64 last_plt_gtime;         /* platform time when last IRQ is injected */
    struct timer timer;         /* ac_timer */
    time_cb *cb;
    void *priv;                 /* ponit back to platform time source */
};

struct pl_time {    /* platform time */
    struct periodic_time periodic_tm;
    struct PITState      vpit;
    struct RTCState      vrtc;
    struct PMTState      vpmt;
};

static __inline__ s_time_t get_scheduled(
    struct vcpu *v, int irq,
    struct periodic_time *pt)
{
    if ( is_irq_enabled(v, irq) ) {
        return pt->scheduled;
    }
    else
        return -1;
}

extern u64 hvm_get_guest_time(struct vcpu *v);
/*
 * get processor time.
 * unit: TSC
 */
static __inline__ int64_t hvm_get_clock(struct vcpu *v)
{
    uint64_t  gtsc;

    gtsc = hvm_get_guest_time(v);
    return gtsc;
}

#define ticks_per_sec(v)      (v->domain->arch.hvm_domain.tsc_frequency)

/* to hook the ioreq packet to get the PIT initialization info */
extern void hvm_hooks_assist(struct vcpu *v);
extern void pickup_deactive_ticks(struct periodic_time *vpit);
extern struct periodic_time *create_periodic_time(u32 period, char irq, char one_shot, time_cb *cb, void *data);
extern void destroy_periodic_time(struct periodic_time *pt);
void pit_init(struct vcpu *v, unsigned long cpu_khz);
void rtc_init(struct vcpu *v, int base, int irq);
void rtc_deinit(struct domain *d);
void pmtimer_init(struct vcpu *v, int base);
void pmtimer_deinit(struct domain *d);
int is_rtc_periodic_irq(void *opaque);
void pt_timer_fn(void *data);
void pit_time_fired(struct vcpu *v, void *priv);

#endif /* __ASM_X86_HVM_VPT_H__ */
