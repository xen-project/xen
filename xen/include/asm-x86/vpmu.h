/*
 * vpmu.h: PMU virtualization for HVM domain.
 *
 * Copyright (c) 2007, Intel Corporation.
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Haitao Shan <haitao.shan@intel.com>
 */

#ifndef __ASM_X86_HVM_VPMU_H_
#define __ASM_X86_HVM_VPMU_H_

#include <public/pmu.h>

#define vcpu_vpmu(vcpu)   (&(vcpu)->arch.vpmu)
#define vpmu_vcpu(vpmu)   container_of((vpmu), struct vcpu, arch.vpmu)
#define vpmu_available(vcpu) vpmu_is_set(vcpu_vpmu(vcpu), VPMU_AVAILABLE)

#define MSR_TYPE_COUNTER            0
#define MSR_TYPE_CTRL               1
#define MSR_TYPE_GLOBAL             2
#define MSR_TYPE_ARCH_COUNTER       3
#define MSR_TYPE_ARCH_CTRL          4

/* Start of PMU register bank */
#define vpmu_reg_pointer(ctxt, offset) ((void *)((uintptr_t)ctxt + \
                                                 (uintptr_t)ctxt->offset))

/* Arch specific operations shared by all vpmus */
struct arch_vpmu_ops {
    int (*do_wrmsr)(unsigned int msr, uint64_t msr_content,
                    uint64_t supported);
    int (*do_rdmsr)(unsigned int msr, uint64_t *msr_content);
    int (*do_interrupt)(struct cpu_user_regs *regs);
    void (*arch_vpmu_destroy)(struct vcpu *v);
    int (*arch_vpmu_save)(struct vcpu *v, bool_t to_guest);
    int (*arch_vpmu_load)(struct vcpu *v, bool_t from_guest);
    void (*arch_vpmu_dump)(const struct vcpu *);
};

int core2_vpmu_init(void);
int vmx_vpmu_initialise(struct vcpu *);
int amd_vpmu_init(void);
int svm_vpmu_initialise(struct vcpu *);

struct vpmu_struct {
    u32 flags;
    u32 last_pcpu;
    u32 hw_lapic_lvtpc;
    void *context;      /* May be shared with PV guest */
    void *priv_context; /* hypervisor-only */
    const struct arch_vpmu_ops *arch_vpmu_ops;
    struct xen_pmu_data *xenpmu_data;
    spinlock_t vpmu_lock;
};

/* VPMU states */
#define VPMU_CONTEXT_ALLOCATED              0x1
#define VPMU_CONTEXT_LOADED                 0x2
#define VPMU_RUNNING                        0x4
#define VPMU_CONTEXT_SAVE                   0x8   /* Force context save */
#define VPMU_FROZEN                         0x10  /* Stop counters while VCPU is not running */
#define VPMU_PASSIVE_DOMAIN_ALLOCATED       0x20
/* PV(H) guests: VPMU registers are accessed by guest from shared page */
#define VPMU_CACHED                         0x40
#define VPMU_AVAILABLE                      0x80

/* Intel-specific VPMU features */
#define VPMU_CPU_HAS_DS                     0x100 /* Has Debug Store */
#define VPMU_CPU_HAS_BTS                    0x200 /* Has Branch Trace Store */

static inline void vpmu_set(struct vpmu_struct *vpmu, const u32 mask)
{
    vpmu->flags |= mask;
}
static inline void vpmu_reset(struct vpmu_struct *vpmu, const u32 mask)
{
    vpmu->flags &= ~mask;
}
static inline void vpmu_clear(struct vpmu_struct *vpmu)
{
    /* VPMU_AVAILABLE should be altered by get/put_vpmu(). */
    vpmu->flags &= VPMU_AVAILABLE;
}
static inline bool_t vpmu_is_set(const struct vpmu_struct *vpmu, const u32 mask)
{
    return !!(vpmu->flags & mask);
}
static inline bool_t vpmu_are_all_set(const struct vpmu_struct *vpmu,
                                      const u32 mask)
{
    return !!((vpmu->flags & mask) == mask);
}

void vpmu_lvtpc_update(uint32_t val);
int vpmu_do_msr(unsigned int msr, uint64_t *msr_content,
                uint64_t supported, bool_t is_write);
void vpmu_do_interrupt(struct cpu_user_regs *regs);
void vpmu_initialise(struct vcpu *v);
void vpmu_destroy(struct vcpu *v);
void vpmu_save(struct vcpu *v);
int vpmu_load(struct vcpu *v, bool_t from_guest);
void vpmu_dump(struct vcpu *v);

static inline int vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content,
                                uint64_t supported)
{
    return vpmu_do_msr(msr, &msr_content, supported, 1);
}
static inline int vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    return vpmu_do_msr(msr, msr_content, 0, 0);
}

extern unsigned int vpmu_mode;
extern unsigned int vpmu_features;

/* Context switch */
static inline void vpmu_switch_from(struct vcpu *prev)
{
    if ( vpmu_mode & (XENPMU_MODE_SELF | XENPMU_MODE_HV) )
        vpmu_save(prev);
}

static inline void vpmu_switch_to(struct vcpu *next)
{
    if ( vpmu_mode & (XENPMU_MODE_SELF | XENPMU_MODE_HV) )
        vpmu_load(next, 0);
}

#endif /* __ASM_X86_HVM_VPMU_H_*/

