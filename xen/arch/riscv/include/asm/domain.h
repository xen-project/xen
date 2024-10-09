/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__DOMAIN_H
#define ASM__RISCV__DOMAIN_H

#include <xen/xmalloc.h>
#include <public/hvm/params.h>

struct hvm_domain
{
    uint64_t              params[HVM_NR_PARAMS];
};

struct arch_vcpu_io {
};

struct arch_vcpu {
};

struct arch_domain {
    struct hvm_domain hvm;
};

#include <xen/sched.h>

static inline struct vcpu_guest_context *alloc_vcpu_guest_context(void)
{
    return xmalloc(struct vcpu_guest_context);
}

static inline void free_vcpu_guest_context(struct vcpu_guest_context *vgc)
{
    xfree(vgc);
}

struct guest_memory_policy {};
static inline void update_guest_memory_policy(struct vcpu *v,
                                              struct guest_memory_policy *gmp)
{}

static inline void arch_vcpu_block(struct vcpu *v) {}

#endif /* ASM__RISCV__DOMAIN_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
