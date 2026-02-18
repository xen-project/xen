/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__DOMAIN_H
#define ASM__RISCV__DOMAIN_H

#include <xen/mm.h>
#include <xen/spinlock.h>
#include <xen/xmalloc.h>
#include <public/hvm/params.h>

#include <asm/p2m.h>

struct vcpu_vmid {
    uint64_t generation;
    uint16_t vmid;
};

struct hvm_domain
{
    uint64_t              params[HVM_NR_PARAMS];
};

struct arch_vcpu_io {
};

struct arch_vcpu {
    struct vcpu_vmid vmid;

    /*
     * Callee saved registers for Xen's state used to switch from
     * prev's stack to the next's stack during context switch.
     */
    struct
    {
        register_t s0;
        register_t s1;
        register_t s2;
        register_t s3;
        register_t s4;
        register_t s5;
        register_t s6;
        register_t s7;
        register_t s8;
        register_t s9;
        register_t s10;
        register_t s11;
        register_t sp;
        register_t ra;
    } xen_saved_context;

    struct cpu_info *cpu_info;
};

struct paging_domain {
    spinlock_t lock;
    /* Free pages from the pre-allocated pool */
    struct page_list_head freelist;
    /* Number of pages from the pre-allocated pool */
    unsigned long total_pages;
};

struct arch_domain {
    struct hvm_domain hvm;

    /* Virtual MMU */
    struct p2m_domain p2m;

    struct paging_domain paging;
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
