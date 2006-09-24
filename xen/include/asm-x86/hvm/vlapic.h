/*
 * hvm_vlapic.h: virtualize LAPIC definitions.
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

#ifndef __ASM_X86_HVM_VLAPIC_H__
#define __ASM_X86_HVM_VLAPIC_H__

#include <asm/msr.h>
#include <public/hvm/ioreq.h>

#define MAX_VECTOR      256

#define VEC_POS(v) ((v)%32)
#define REG_POS(v) (((v)/32)* 0x10)
#define vlapic_test_and_set_vector(vec, bitmap)                 \
    test_and_set_bit(VEC_POS(vec), (bitmap) + REG_POS(vec))
#define vlapic_test_and_clear_vector(vec, bitmap)               \
    test_and_clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec))
#define vlapic_set_vector(vec, bitmap)                          \
    set_bit(VEC_POS(vec), (bitmap) + REG_POS(vec))
#define vlapic_clear_vector(vec, bitmap)                        \
    clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec))

static inline int vlapic_find_highest_vector(u32 *bitmap)
{
    int word_offset = MAX_VECTOR / 32;

    /* Work backwards through the bitmap (first 32-bit word in every four). */
    while ( (word_offset != 0) && (bitmap[(--word_offset)*4] == 0) )
        continue;

    return (fls(bitmap[word_offset*4]) - 1) + (word_offset * 32);
}

#define VLAPIC(v)                       (v->arch.hvm_vcpu.vlapic)

#define VLAPIC_VERSION                  0x00050014

#define VLOCAL_APIC_MEM_LENGTH          (1 << 12)

#define VLAPIC_LVT_NUM                  6

#define VLAPIC_ID(vlapic)   \
    (GET_APIC_ID(vlapic_get_reg(vlapic, APIC_ID)))

/* followed define is not in apicdef.h */
#define APIC_SHORT_MASK                  0xc0000
#define APIC_DEST_NOSHORT                0x0
#define APIC_DEST_MASK                  0x800

#define vlapic_lvt_enabled(vlapic, lvt_type)    \
    (!(vlapic_get_reg(vlapic, lvt_type) & APIC_LVT_MASKED))

#define vlapic_lvt_vector(vlapic, lvt_type)     \
    (vlapic_get_reg(vlapic, lvt_type) & APIC_VECTOR_MASK)

#define vlapic_lvt_dm(vlapic, lvt_type)           \
    (vlapic_get_reg(vlapic, lvt_type) & APIC_MODE_MASK)

#define vlapic_lvtt_period(vlapic)     \
    (vlapic_get_reg(vlapic, APIC_LVTT) & APIC_LVT_TIMER_PERIODIC)

#define _VLAPIC_GLOB_DISABLE            0x0
#define VLAPIC_GLOB_DISABLE_MASK        0x1
#define VLAPIC_SOFTWARE_DISABLE_MASK    0x2
#define _VLAPIC_BSP_ACCEPT_PIC          0x3

#define vlapic_enabled(vlapic)              \
    (!((vlapic)->status &                   \
       (VLAPIC_GLOB_DISABLE_MASK | VLAPIC_SOFTWARE_DISABLE_MASK)))

#define vlapic_global_enabled(vlapic)       \
    (!(test_bit(_VLAPIC_GLOB_DISABLE, &(vlapic)->status)))

#define LVT_MASK \
    APIC_LVT_MASKED | APIC_SEND_PENDING | APIC_VECTOR_MASK

#define LINT_MASK   \
    LVT_MASK | APIC_MODE_MASK | APIC_INPUT_POLARITY |\
    APIC_LVT_REMOTE_IRR | APIC_LVT_LEVEL_TRIGGER

typedef struct direct_intr_info {
    int deliver_mode;
    int source[6];
} direct_intr_info_t;

struct vlapic {
    uint32_t           status;
    uint32_t           vcpu_id;
    uint64_t           apic_base_msr;
    unsigned long      base_address;
    uint32_t           timer_divide_count;
    struct timer       vlapic_timer;
    int                intr_pending_count[MAX_VECTOR];
    s_time_t           timer_last_update;
    direct_intr_info_t direct_intr;
    uint32_t           err_status;
    uint32_t           err_write_count;
    struct vcpu        *vcpu;
    struct domain      *domain;
    struct page_info   *regs_page;
    void               *regs;
};

static inline int vlapic_set_irq(struct vlapic *vlapic,
                                 uint8_t vec, uint8_t trig)
{
    int ret;

    ret = vlapic_test_and_set_vector(vec, vlapic->regs + APIC_IRR);
    if ( trig )
        vlapic_set_vector(vec, vlapic->regs + APIC_TMR);

    /* We may need to wake up target vcpu, besides set pending bit here */
    return ret;
}

static inline uint32_t vlapic_get_reg(struct vlapic *vlapic, uint32_t reg)
{
    return  *( (uint32_t *)(vlapic->regs + reg));
}

static inline void vlapic_set_reg(struct vlapic *vlapic,
  uint32_t reg, uint32_t val)
{
    *((uint32_t *)(vlapic->regs + reg)) = val;
}


void vlapic_post_injection(struct vcpu* v, int vector, int deliver_mode);

int cpu_has_apic_interrupt(struct vcpu* v);
int cpu_get_apic_interrupt(struct vcpu* v, int *mode);

extern int vlapic_init(struct vcpu *vc);

extern void vlapic_msr_set(struct vlapic *vlapic, uint64_t value);

int vlapic_accept_pic_intr(struct vcpu *v);

struct vlapic* apic_round_robin(struct domain *d,
                                uint8_t dest_mode,
                                uint8_t vector,
                                uint32_t bitmap);

s_time_t get_apictime_scheduled(struct vcpu *v);

int hvm_apic_support(struct domain *d);

#endif /* __ASM_X86_HVM_VLAPIC_H__ */
