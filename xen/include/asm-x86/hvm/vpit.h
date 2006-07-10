/*
 * vpit.h: Virtual PIT definitions
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

#ifndef __ASM_X86_HVM_VPIT_H__
#define __ASM_X86_HVM_VPIT_H__

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <xen/timer.h>
#include <asm/hvm/vpic.h>

#define PIT_FREQ 1193181
#define PIT_BASE        0x40

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
   
/*
 * Abstract layer of periodic time, one short time.
 */
struct periodic_time {
    char enabled;               /* enabled */
    char one_shot;              /* one shot time */
    char irq;
    char first_injected;        /* flag to prevent shadow window */
    u32 pending_intr_nr;        /* the couner for pending timer interrupts */
    u32 period;                 /* frequency in ns */
    u64 period_cycles;          /* frequency in cpu cycles */
    s_time_t scheduled;         /* scheduled timer interrupt */
    u64 last_plt_gtime;         /* platform time when last IRQ is injected */
    struct timer timer;         /* ac_timer */
    void *priv;                 /* ponit back to platform time source */
};

typedef struct PITState {
    PITChannelState channels[3];
    int speaker_data_on;
    int dummy_refresh_clock;
} PITState;

struct pl_time {    /* platform time */
    struct periodic_time periodic_tm;
    struct PITState      vpit;
    /* TODO: RTC/ACPI time */
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

/* to hook the ioreq packet to get the PIT initialization info */
extern void hvm_hooks_assist(struct vcpu *v);
extern void pickup_deactive_ticks(struct periodic_time *vpit);
extern u64 hvm_get_guest_time(struct vcpu *v);
extern struct periodic_time *create_periodic_time(PITChannelState *v, u32 period, char irq, char one_shot);
extern void destroy_periodic_time(struct periodic_time *pt);
void pit_init(struct vcpu *v, unsigned long cpu_khz);
void pt_timer_fn(void *data);
void pit_time_fired(struct vcpu *v, void *priv);

#endif /* __ASM_X86_HVM_VPIT_H__ */
