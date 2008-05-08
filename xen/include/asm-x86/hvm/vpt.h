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
#include <asm/hvm/irq.h>
#include <public/hvm/save.h>

struct HPETState;
struct HPET_timer_fn_info {
    struct HPETState *hs;
    unsigned int tn;
};

struct hpet_registers {
    /* Memory-mapped, software visible registers */
    uint64_t capability;        /* capabilities */
    uint64_t config;            /* configuration */
    uint64_t isr;               /* interrupt status reg */
    uint64_t mc64;              /* main counter */
    struct {                    /* timers */
        uint64_t config;        /* configuration/cap */
        uint64_t cmp;           /* comparator */
        uint64_t fsb;           /* FSB route, not supported now */
    } timers[HPET_TIMER_NUM];

    /* Hidden register state */
    uint64_t period[HPET_TIMER_NUM]; /* Last value written to comparator */
};

typedef struct HPETState {
    struct hpet_registers hpet;
    struct vcpu *vcpu;
    uint64_t tsc_freq;
    uint64_t hpet_to_ns_scale; /* hpet ticks to ns (multiplied by 2^10) */
    uint64_t hpet_to_ns_limit; /* max hpet ticks convertable to ns      */
    uint64_t mc_offset;
    struct timer timers[HPET_TIMER_NUM];
    struct HPET_timer_fn_info timer_fn_info[HPET_TIMER_NUM]; 
    spinlock_t lock;
} HPETState;


/*
 * Abstract layer of periodic time, one short time.
 */
typedef void time_cb(struct vcpu *v, void *opaque);

struct periodic_time {
    struct list_head list;
    bool_t on_list;
    bool_t one_shot;
    bool_t do_not_freeze;
    bool_t irq_issued;
    bool_t warned_timeout_too_short;
#define PTSRC_isa    1 /* ISA time source */
#define PTSRC_lapic  2 /* LAPIC time source */
    u8 source;                  /* PTSRC_ */
    u8 irq;
    struct vcpu *vcpu;          /* vcpu timer interrupt delivers to */
    u32 pending_intr_nr;        /* pending timer interrupts */
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
    /* Channel 0 IRQ handling. */
    struct periodic_time pt0;
    spinlock_t lock;
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
    int32_t time_offset_seconds;
    spinlock_t lock;
} RTCState;

#define FREQUENCE_PMTIMER  3579545  /* Timer should run at 3.579545 MHz */
typedef struct PMTState {
    struct hvm_hw_pmtimer pm;   /* 32bit timer value */
    struct vcpu *vcpu;          /* Keeps sync with this vcpu's guest-time */
    uint64_t last_gtime;        /* Last (guest) time we updated the timer */
    uint64_t scale;             /* Multiplier to get from tsc to timer ticks */
    struct timer timer;         /* To make sure we send SCIs */
    spinlock_t lock;
} PMTState;

struct pl_time {    /* platform time */
    struct PITState  vpit;
    struct RTCState  vrtc;
    struct HPETState vhpet;
    struct PMTState  vpmt;
};

#define ticks_per_sec(v) (v->domain->arch.hvm_domain.tsc_frequency)

void pt_save_timer(struct vcpu *v);
void pt_restore_timer(struct vcpu *v);
void pt_update_irq(struct vcpu *v);
void pt_intr_post(struct vcpu *v, struct hvm_intack intack);
void pt_reset(struct vcpu *v);
void pt_migrate(struct vcpu *v);

/* Is given periodic timer active? */
#define pt_active(pt) ((pt)->on_list)

/*
 * Create/destroy a periodic (or one-shot!) timer.
 * The given periodic timer structure must be initialised with zero bytes,
 * except for the 'source' field which must be initialised with the
 * correct PTSRC_ value. The initialised timer structure can then be passed
 * to {create,destroy}_periodic_time() and number of times and in any order.
 * Note that, for a given periodic timer, invocations of these functions MUST
 * be serialised.
 */
void create_periodic_time(
    struct vcpu *v, struct periodic_time *pt, uint64_t period,
    uint8_t irq, char one_shot, time_cb *cb, void *data);
void destroy_periodic_time(struct periodic_time *pt);

int pv_pit_handler(int port, int data, int write);
void pit_init(struct vcpu *v, unsigned long cpu_khz);
void pit_stop_channel0_irq(PITState * pit);
void pit_deinit(struct domain *d);
void rtc_init(struct vcpu *v, int base);
void rtc_migrate_timers(struct vcpu *v);
void rtc_deinit(struct domain *d);
void pmtimer_init(struct vcpu *v);
void pmtimer_deinit(struct domain *d);

void hpet_migrate_timers(struct vcpu *v);
void hpet_init(struct vcpu *v);
void hpet_deinit(struct domain *d);

#endif /* __ASM_X86_HVM_VPT_H__ */
