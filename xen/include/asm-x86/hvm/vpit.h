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

#define LSByte          0
#define MSByte          1
#define LSByte_multiple 2
#define MSByte_multiple 3

struct hvm_virpit {
    /* for simulation of counter 0 in mode 2 */
    u64 period_cycles;          /* pit frequency in cpu cycles */
    s_time_t count_advance;     /* accumulated count advance since last fire */
    s_time_t count_point;        /* last point accumulating count advance */
    s_time_t scheduled;         /* scheduled timer interrupt */
    struct timer pit_timer;     /* periodic timer for mode 2*/
    unsigned int channel;       /* the pit channel, counter 0~2 */
    unsigned int pending_intr_nr; /* the couner for pending timer interrupts */
    u32 period;                 /* pit frequency in ns */
    int first_injected;         /* flag to prevent shadow window */
    s64 cache_tsc_offset;       /* cache of VMCS TSC_OFFSET offset */
    u64 last_pit_gtime;         /* guest time when last pit is injected */

    /* virtual PIT state for handle related I/O */
    int read_state;
    int count_LSB_latched;
    int count_MSB_latched;

    unsigned int count;  /* the 16 bit channel count */
    unsigned int init_val; /* the init value for the counter */
};

static __inline__ s_time_t get_pit_scheduled(
    struct vcpu *v,
    struct hvm_virpit *vpit)
{
    if ( is_irq_enabled(v, 0) ) {
        return vpit->scheduled;
    }
    else
        return -1;
}

/* to hook the ioreq packet to get the PIT initialization info */
extern void hvm_hooks_assist(struct vcpu *v);
void pickup_deactive_ticks(struct hvm_virpit *vpit);

#endif /* __ASM_X86_HVM_VPIT_H__ */
