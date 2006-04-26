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

#define PIT_BASE 0x40
#define HVM_PIT_ACCEL_MODE 2

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
    s64 next_transition_time;
    int irq;
    struct hvm_time_info *hvm_time;
    u32 period; /* period(ns) based on count */
} PITChannelState;

struct hvm_time_info {
    /* extra info for the mode 2 channel */
    struct timer pit_timer;
    struct vcpu *vcpu;          /* which vcpu the ac_timer bound to */
    u64 period_cycles;          /* pit frequency in cpu cycles */
    s_time_t count_advance;     /* accumulated count advance since last fire */
    s_time_t count_point;        /* last point accumulating count advance */
    unsigned int pending_intr_nr; /* the couner for pending timer interrupts */
    int first_injected;         /* flag to prevent shadow window */
    s64 cache_tsc_offset;       /* cache of VMCS TSC_OFFSET offset */
    u64 last_pit_gtime;         /* guest time when last pit is injected */
};

typedef struct hvm_virpit {
    PITChannelState channels[3];
    struct hvm_time_info time_info;
    int speaker_data_on;
    int dummy_refresh_clock;
}hvm_virpit;


static __inline__ s_time_t get_pit_scheduled(
    struct vcpu *v,
    struct hvm_virpit *vpit)
{
    struct PITChannelState *s = &(vpit->channels[0]);
    if ( is_irq_enabled(v, 0) ) {
        return s->next_transition_time;
    }
    else
        return -1;
}

/* to hook the ioreq packet to get the PIT initialization info */
extern void pit_init(struct hvm_virpit *pit, struct vcpu *v);
extern void pickup_deactive_ticks(struct hvm_virpit *vpit);

#endif /* __ASM_X86_HVM_VPIT_H__ */
