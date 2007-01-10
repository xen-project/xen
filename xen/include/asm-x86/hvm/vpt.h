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


#define HPET_TIMER_NUM     3    /* 3 timers supported now */
struct HPET {
    uint64_t capability;        /* capabilities */
    uint64_t res0;              /* reserved */
    uint64_t config;            /* configuration */
    uint64_t res1;              /* reserved */
    uint64_t isr;               /* interrupt status reg */
    uint64_t res2[25];          /* reserved */
    uint64_t mc64;              /* main counter */
    uint64_t res3;              /* reserved */
    struct {                    /* timers */
        uint64_t config;        /* configuration/cap */
        uint64_t cmp;           /* comparator */
        uint64_t hpet_fsb[2];   /* FSB route, not supported now */
    } timers[HPET_TIMER_NUM];
};

struct HPETState;
struct HPET_timer_fn_info {
    struct HPETState       *hs;
    unsigned int    tn;
};

typedef struct HPETState {
    struct HPET     hpet;
    struct vcpu     *vcpu;
    uint64_t        tsc_freq;
    uint64_t        mc_offset;
    uint64_t        period[HPET_TIMER_NUM];
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
    void *priv;                 /* ponit back to platform time source */
};


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
    struct periodic_time pt;
} PITChannelState;

typedef struct PITState {
    PITChannelState channels[3];
    int speaker_data_on;
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
    struct periodic_time pt;
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
void create_periodic_time(struct periodic_time *pt, uint64_t period,
                          uint8_t irq, char one_shot, time_cb *cb, void *data);
void destroy_periodic_time(struct periodic_time *pt);

int pv_pit_handler(int port, int data, int write);
void pit_init(struct vcpu *v, unsigned long cpu_khz);
void pit_stop_channel0_irq(PITState * pit);
void pit_migrate_timers(struct vcpu *v);
void pit_deinit(struct domain *d);
void rtc_init(struct vcpu *v, int base, int irq);
void rtc_migrate_timers(struct vcpu *v);
void rtc_deinit(struct domain *d);
int is_rtc_periodic_irq(void *opaque);
void pmtimer_init(struct vcpu *v, int base);
void pmtimer_migrate_timers(struct vcpu *v);
void pmtimer_deinit(struct domain *d);

void hpet_migrate_timers(struct vcpu *v);
void hpet_init(struct vcpu *v);
void hpet_deinit(struct domain *d);

#endif /* __ASM_X86_HVM_VPT_H__ */
