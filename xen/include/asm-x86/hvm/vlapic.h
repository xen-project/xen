/*
 * hvm_vlapic.h: virtualize LAPIC definitions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2006 Keir Fraser, XenSource Inc.
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

#ifndef __ASM_X86_HVM_VLAPIC_H__
#define __ASM_X86_HVM_VLAPIC_H__

#include <asm/msr.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/vpt.h>

#define MAX_VECTOR      256

#define vcpu_vlapic(vcpu)   (&(vcpu)->arch.hvm_vcpu.vlapic)
#define vlapic_vcpu(vpic)   (container_of((vpic), struct vcpu, \
                                          arch.hvm_vcpu.vlapic))
#define vlapic_domain(vpic) (vlapic_vcpu(vlapic)->domain)

#define VLAPIC_ID(vlapic)   \
    (GET_APIC_ID(vlapic_get_reg(vlapic, APIC_ID)))

/*
 * APIC can be disabled in two ways:
 *  1. 'Hardware disable': via IA32_APIC_BASE_MSR[11]
 *     CPU should behave as if it does not have an APIC.
 *  2. 'Software disable': via APIC_SPIV[8].
 *     APIC is visible but does not respond to interrupt messages.
 */
#define VLAPIC_HW_DISABLED              0x1
#define VLAPIC_SW_DISABLED              0x2
#define vlapic_sw_disabled(vlapic) ((vlapic)->hw.disabled & VLAPIC_SW_DISABLED)
#define vlapic_hw_disabled(vlapic) ((vlapic)->hw.disabled & VLAPIC_HW_DISABLED)
#define vlapic_disabled(vlapic)    ((vlapic)->hw.disabled)
#define vlapic_enabled(vlapic)     (!vlapic_disabled(vlapic))

struct vlapic {
    struct hvm_hw_lapic      hw;
    struct hvm_hw_lapic_regs *regs;
    struct periodic_time     pt;
    s_time_t                 timer_last_update;
    struct page_info         *regs_page;
};

static inline uint32_t vlapic_get_reg(struct vlapic *vlapic, uint32_t reg)
{
    return *((uint32_t *)(&vlapic->regs->data[reg]));
}

static inline void vlapic_set_reg(
    struct vlapic *vlapic, uint32_t reg, uint32_t val)
{
    *((uint32_t *)(&vlapic->regs->data[reg])) = val;
}

int vlapic_set_irq(struct vlapic *vlapic, uint8_t vec, uint8_t trig);

int vlapic_find_highest_irr(struct vlapic *vlapic);

int vlapic_has_interrupt(struct vcpu *v);
int cpu_get_apic_interrupt(struct vcpu *v, int *mode);

int  vlapic_init(struct vcpu *v);
void vlapic_destroy(struct vcpu *v);

void vlapic_reset(struct vlapic *vlapic);

void vlapic_msr_set(struct vlapic *vlapic, uint64_t value);

int vlapic_accept_pic_intr(struct vcpu *v);

struct vlapic *apic_round_robin(
    struct domain *d, uint8_t vector, uint32_t bitmap);

int vlapic_match_logical_addr(struct vlapic *vlapic, uint8_t mda);

int is_lvtt(struct vcpu *v, int vector);
int is_lvtt_enabled(struct vcpu *v);

#endif /* __ASM_X86_HVM_VLAPIC_H__ */
