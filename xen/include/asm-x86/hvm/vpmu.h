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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Author: Haitao Shan <haitao.shan@intel.com>
 */

#ifndef __ASM_X86_HVM_VPMU_H_
#define __ASM_X86_HVM_VPMU_H_

/*
 * Flag bits given as a string on the hypervisor boot parameter 'vpmu'.
 * See arch/x86/hvm/vpmu.c.
 */
#define VPMU_BOOT_ENABLED 0x1    /* vpmu generally enabled. */
#define VPMU_BOOT_BTS     0x2    /* Intel BTS feature wanted. */


#define msraddr_to_bitpos(x) (((x)&0xffff) + ((x)>>31)*0x2000)
#define vcpu_vpmu(vcpu)   (&((vcpu)->arch.hvm_vcpu.vpmu))
#define vpmu_vcpu(vpmu)   (container_of((vpmu), struct vcpu, \
                                          arch.hvm_vcpu.vpmu))
#define vpmu_domain(vpmu) (vpmu_vcpu(vpmu)->domain)

#define MSR_TYPE_COUNTER            0
#define MSR_TYPE_CTRL               1
#define MSR_TYPE_GLOBAL             2
#define MSR_TYPE_ARCH_COUNTER       3
#define MSR_TYPE_ARCH_CTRL          4


/* Arch specific operations shared by all vpmus */
struct arch_vpmu_ops {
    int (*do_wrmsr)(unsigned int msr, uint64_t msr_content,
                    uint64_t supported);
    int (*do_rdmsr)(unsigned int msr, uint64_t *msr_content);
    int (*do_interrupt)(struct cpu_user_regs *regs);
    void (*do_cpuid)(unsigned int input,
                     unsigned int *eax, unsigned int *ebx,
                     unsigned int *ecx, unsigned int *edx);
    void (*arch_vpmu_destroy)(struct vcpu *v);
    int (*arch_vpmu_save)(struct vcpu *v);
    void (*arch_vpmu_load)(struct vcpu *v);
    void (*arch_vpmu_dump)(const struct vcpu *);
};

int vmx_vpmu_initialise(struct vcpu *, unsigned int flags);
int svm_vpmu_initialise(struct vcpu *, unsigned int flags);

struct vpmu_struct {
    u32 flags;
    u32 last_pcpu;
    u32 hw_lapic_lvtpc;
    void *context;
    struct arch_vpmu_ops *arch_vpmu_ops;
};

/* VPMU states */
#define VPMU_CONTEXT_ALLOCATED              0x1
#define VPMU_CONTEXT_LOADED                 0x2
#define VPMU_RUNNING                        0x4
#define VPMU_CONTEXT_SAVE                   0x8   /* Force context save */
#define VPMU_FROZEN                         0x10  /* Stop counters while VCPU is not running */
#define VPMU_PASSIVE_DOMAIN_ALLOCATED       0x20

/* VPMU features */
#define VPMU_CPU_HAS_DS                     0x100 /* Has Debug Store */
#define VPMU_CPU_HAS_BTS                    0x200 /* Has Branch Trace Store */


#define vpmu_set(_vpmu, _x)    ((_vpmu)->flags |= (_x))
#define vpmu_reset(_vpmu, _x)  ((_vpmu)->flags &= ~(_x))
#define vpmu_is_set(_vpmu, _x) ((_vpmu)->flags & (_x))
#define vpmu_clear(_vpmu)      ((_vpmu)->flags = 0)

int vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content, uint64_t supported);
int vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content);
void vpmu_do_interrupt(struct cpu_user_regs *regs);
void vpmu_do_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                       unsigned int *ecx, unsigned int *edx);
void vpmu_initialise(struct vcpu *v);
void vpmu_destroy(struct vcpu *v);
void vpmu_save(struct vcpu *v);
void vpmu_load(struct vcpu *v);
void vpmu_dump(struct vcpu *v);

extern int acquire_pmu_ownership(int pmu_ownership);
extern void release_pmu_ownership(int pmu_ownership);

#endif /* __ASM_X86_HVM_VPMU_H_*/

