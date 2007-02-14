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
#include <xen/list.h>
#include <asm/hvm/vpic.h>
#include <public/hvm/save.h>


struct HPETState;
struct HPET_timer_fn_info {
    struct HPETState       *hs;
    unsigned int    tn;
};

typedef struct HPETState {
    struct hvm_hw_hpet hpet;
    struct vcpu *vcpu;
    uint64_t tsc_freq;
    uint64_t mc_offset;
    struct timer timers[HPET_TIMER_NUM];
    struct HPET_timer_fn_info timer_fn_info[HPET_TIMER_NUM]; 
} HPETState;


/*
 * Abstract layer of periodic time, one short time.
 */
typedef void time_cb(struct vcpu *v, void *opaque);

struct periodic_time {
    struct list_head list;
    char enabled;
    char one_shot;              /* one shot time */
    u8 irq;
    struct vcpu *vcpu;          /* vcpu timer interrupt delivers to */
    u32 pending_intr_nr;        /* the couner for pending timer interrupts */
    u64 period;                 /* frequency in ns */
    u64 period_cycles;          /* frequency in cpu cycles */
    s_time_t scheduled;         /* scheduled timer interrupt */
    u64 last_plt_gtime;         /* platform time when last IRQ is injected */
    struct timer timer;         /* ac_timer */
    time_cb *cb;
    void *priv;                 /* point back to platform time source */
};


#define PIT_FREQ 1193181
#define PIT_BASE 0x40

typedef struct PITState {
    /* Hardware state */
    struct hvm_hw_pit hw;
    /* Last time the counters read zero, for calcuating counter reads */
    int64_t count_load_time[3];
    /* irq handling */
    struct periodic_time pt[3];
} PITState;

typedef struct RTCState {
    /* Hardware state */
    struct hvm_hw_rtc hw;
    /* RTC's idea of the current time */
    struct tm current_tm;
    /* second update */
    int64_t next_second_time;
    struct timer second_timer;
    struct timer second_timer2;
    struct periodic_time pt;
} RTCState;

#define FREQUENCE_PMTIMER  3579545  /* Timer should run at 3.579545 MHz */
typedef struct PMTState {
    struct hvm_hw_pmtimer pm;   /* 32bit timer value */
    struct vcpu *vcpu;          /* Keeps sync with this vcpu's guest-time */
    uint64_t last_gtime;        /* Last (guest) time we updated the timer */
    uint64_t scale;             /* Multiplier to get from tsc to timer ticks */
} PMTState;

struct pl_time {    /* platform time */
    struct PITState  vpit;
    struct RTCState  vrtc;
    struct HPETState vhpet;
    struct PMTState  vpmt;
};

#define ticks_per_sec(v) (v->domain->arch.hvm_domain.tsc_frequency)

void pt_freeze_time(struct vcpu *v);
void pt_thaw_time(struct vcpu *v);
void pt_timer_fn(void *data);
void pt_update_irq(struct vcpu *v);
struct periodic_time *is_pt_irq(struct vcpu *v, int vector, int type);
void pt_intr_post(struct vcpu *v, int vector, int type);
void pt_reset(struct vcpu *v);
void create_periodic_time(struct vcpu *v, struct periodic_time *pt, uint64_t period,
                          uint8_t irq, char one_shot, time_cb *cb, void *data);
void destroy_periodic_time(struct periodic_time *pt);

int pv_pit_handler(int port, int data, int write);
void pit_init(struct vcpu *v, unsigned long cpu_khz);
void pit_stop_channel0_irq(PITState * pit);
void pit_migrate_timers(struct vcpu *v);
void pit_deinit(struct domain *d);
void rtc_init(struct vcpu *v, int base);
void rtc_migrate_timers(struct vcpu *v);
void rtc_deinit(struct domain *d);
int is_rtc_periodic_irq(void *opaque);
void pmtimer_init(struct vcpu *v, int base);

void hpet_migrate_timers(struct vcpu *v);
void hpet_init(struct vcpu *v);
void hpet_deinit(struct domain *d);

#endif /* __ASM_X86_HVM_VPT_H__ */
