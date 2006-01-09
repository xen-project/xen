/*
 * vmx_vlapic.h: virtualize LAPIC definitions.
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
 *
 */

#ifndef VMX_VLAPIC_H
#define VMX_VLAPIC_H

#include <asm/msr.h>
#include <public/hvm/ioreq.h>

#if defined(__i386__) || defined(__x86_64__)
static inline int __fls(uint32_t word)
{
    int bit;

    __asm__("bsrl %1,%0"
      :"=r" (bit)
      :"rm" (word));
    return word ? bit : -1;
}
#else
#define __fls(x)    generic_fls(x)
static __inline__ int generic_fls(uint32_t x)
{
    int r = 31;

    if (!x)
        return -1;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}
#endif

static __inline__ int find_highest_bit(uint32_t *data, int length)
{
    while(length && !data[--length]);
    return __fls(data[length]) +  32 * length;
}

#define VLAPIC(v)                       (v->arch.arch_vmx.vlapic)

#define VAPIC_ID_MASK                   0xff
#define VAPIC_LDR_MASK                  (VAPIC_ID_MASK << 24)
#define VLAPIC_VERSION                  0x00050014

#define VLAPIC_BASE_MSR_MASK            0x00000000fffff900ULL
#define VLAPIC_BASE_MSR_INIT_BASE_ADDR  0xfee00000U
#define VLAPIC_BASE_MSR_BASE_ADDR_MASK  0xfffff000U
#define VLAPIC_BASE_MSR_INIT_VALUE      (VLAPIC_BASE_MSR_INIT_BASE_ADDR | \
                                         MSR_IA32_APICBASE_ENABLE)
#define VLOCAL_APIC_MEM_LENGTH          (1 << 12)

#define VLAPIC_LVT_TIMER                0
#define VLAPIC_LVT_THERMAL              1
#define VLAPIC_LVT_PERFORM              2
#define VLAPIC_LVT_LINT0                3
#define VLAPIC_LVT_LINT1                4
#define VLAPIC_LVT_ERROR                5
#define VLAPIC_LVT_NUM                  6

#define VLAPIC_LVT_BIT_MASK             (1 << 16)
#define VLAPIC_LVT_BIT_VECTOR           0xff
#define VLAPIC_LVT_BIT_DELIMOD          (0x7 << 8)
#define VLAPIC_LVT_BIT_DELISTATUS       (1 << 12)
#define VLAPIC_LVT_BIT_POLARITY         (1 << 13)
#define VLAPIC_LVT_BIT_IRR              (1 << 14)
#define VLAPIC_LVT_BIT_TRIG             (1 << 15)
#define VLAPIC_LVT_TIMERMODE            (1 << 17)

#define VLAPIC_DELIV_MODE_FIXED          0x0
#define VLAPIC_DELIV_MODE_LPRI           0x1
#define VLAPIC_DELIV_MODE_SMI            0x2
#define VLAPIC_DELIV_MODE_RESERVED       0x3
#define VLAPIC_DELIV_MODE_NMI            0x4
#define VLAPIC_DELIV_MODE_INIT           0x5
#define VLAPIC_DELIV_MODE_STARTUP        0x6
#define VLAPIC_DELIV_MODE_EXT            0x7



#define VLAPIC_NO_SHORTHAND             0x0
#define VLAPIC_SHORTHAND_SELF           0x1
#define VLAPIC_SHORTHAND_INCLUDE_SELF   0x2
#define VLAPIC_SHORTHAND_EXCLUDE_SELF   0x3

#define vlapic_lvt_timer_enabled(vlapic)    \
  (!(vlapic->lvt[VLAPIC_LVT_TIMER] & VLAPIC_LVT_BIT_MASK))

#define vlapic_lvt_vector(vlapic, type)   \
  (vlapic->lvt[type] & VLAPIC_LVT_BIT_VECTOR)

#define vlapic_lvt_dm(value)        ((value >> 8) && 7)
#define vlapic_lvt_timer_period(vlapic) \
  (vlapic->lvt[VLAPIC_LVT_TIMER] & VLAPIC_LVT_TIMERMODE)

#define vlapic_isr_status(vlapic,vector)    \
  test_bit(vector, &vlapic->isr[0])

#define vlapic_irr_status(vlapic,vector)    \
  test_bit(vector, &vlapic->irr[0])

#define vlapic_set_isr(vlapic,vector) \
  test_and_set_bit(vector, &vlapic->isr[0])

#define vlapic_set_irr(vlapic,vector)      \
  test_and_set_bit(vector, &vlapic->irr[0])

#define vlapic_clear_irr(vlapic,vector)      \
  clear_bit(vector, &vlapic->irr[0])
#define vlapic_clear_isr(vlapic,vector)     \
  clear_bit(vector, &vlapic->isr[0])

#define vlapic_enabled(vlapic)               \
  (!(vlapic->status &                           \
     (VLAPIC_GLOB_DISABLE_MASK | VLAPIC_SOFTWARE_DISABLE_MASK)))

#define vlapic_global_enabled(vlapic)               \
  !(test_bit(_VLAPIC_GLOB_DISABLE, &(vlapic)->status))

#define VLAPIC_IRR(t) ((t)->irr[0])
#define VLAPIC_ID(t)  ((t)->id)

typedef struct direct_intr_info {
    int deliver_mode;
    int source[6];
} direct_intr_info_t;

#define VLAPIC_INIT_SIPI_SIPI_STATE_NORM          0
#define VLAPIC_INIT_SIPI_SIPI_STATE_WAIT_SIPI     1

struct vlapic
{
    //FIXME check what would be 64 bit on EM64T
    uint32_t           version;
#define _VLAPIC_GLOB_DISABLE            0x0
#define VLAPIC_GLOB_DISABLE_MASK        0x1
#define VLAPIC_SOFTWARE_DISABLE_MASK    0x2
#define _VLAPIC_BSP_ACCEPT_PIC          0x3
    uint32_t           status;
    uint32_t           id;
    uint32_t           vcpu_id;
    unsigned long      base_address;
    uint32_t           isr[8];
    uint32_t           irr[INTR_LEN_32];
    uint32_t           tmr[INTR_LEN_32];
    uint32_t           task_priority;
    uint32_t           processor_priority;
    uint32_t           logical_dest;
    uint32_t           dest_format;
    uint32_t           spurious_vec;
    uint32_t           lvt[6];
    uint32_t           timer_initial;
    uint32_t           timer_current;
    uint32_t           timer_divconf;
    uint32_t           timer_divide_counter;
    struct ac_timer    vlapic_timer;
    int                intr_pending_count[MAX_VECTOR];
    s_time_t           timer_current_update;
    uint32_t           icr_high;
    uint32_t           icr_low;
    direct_intr_info_t direct_intr;
    uint32_t           err_status;
    unsigned long      init_ticks;
    uint32_t           err_write_count;
    uint64_t           apic_base_msr;
    uint32_t           init_sipi_sipi_state;
    struct vcpu        *vcpu;
    struct domain      *domain;
};

static inline int vlapic_set_irq(struct vlapic *t, uint8_t vec, uint8_t trig)
{
    int ret;

    ret = test_and_set_bit(vec, &t->irr[0]);
    if (trig)
	test_and_set_bit(vec, &t->tmr[0]);

    /* We may need to wake up target vcpu, besides set pending bit here */
    return ret;
}

static inline int  vlapic_timer_active(struct vlapic *vlapic)
{
    return  active_ac_timer(&(vlapic->vlapic_timer));
}

int vlapic_find_highest_irr(struct vlapic *vlapic);

int vlapic_find_highest_isr(struct vlapic *vlapic);

static uint32_t inline vlapic_get_base_address(struct vlapic *vlapic)
{
    return (vlapic->apic_base_msr & VLAPIC_BASE_MSR_BASE_ADDR_MASK);
}

void vlapic_post_injection(struct vcpu* v, int vector, int deliver_mode);

int cpu_get_apic_interrupt(struct vcpu* v, int *mode);

extern uint32_t vlapic_update_ppr(struct vlapic *vlapic);

int vlapic_update(struct vcpu *v);

extern int vlapic_init(struct vcpu *vc);

extern void vlapic_msr_set(struct vlapic *vlapic, uint64_t value);

int vlapic_accept_pic_intr(struct vcpu *v);

struct vlapic* apic_round_robin(struct domain *d,
                                uint8_t dest_mode,
                                uint8_t vector,
                                uint32_t bitmap);
s_time_t get_apictime_scheduled(struct vcpu *v);
int vmx_apic_support(struct domain *d);

#endif /* VMX_VLAPIC_H */

