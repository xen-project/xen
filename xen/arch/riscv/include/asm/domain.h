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

    register_t hcounteren;
    register_t hedeleg;
    register_t hideleg;
    register_t henvcfg;
    register_t hstateen0;
    register_t hvip;

    register_t vsatp;

    /*
     * VCPU interrupts
     *
     * We have a lockless approach for tracking pending VCPU interrupts
     * implemented using atomic bitops. The irqs_pending bitmap represent
     * pending interrupts whereas irqs_pending_mask represent bits changed
     * in irqs_pending. Our approach is modeled around multiple producer
     * and single consumer problem where the consumer is the VCPU itself.
     *
     * DECLARE_BITMAP() is needed here to support 64 vCPU local interrupts
     * on RV32 host.
     */
#define RISCV_VCPU_NR_IRQS MAX(BITS_PER_LONG, 64)
    DECLARE_BITMAP(irqs_pending, RISCV_VCPU_NR_IRQS);
    DECLARE_BITMAP(irqs_pending_mask, RISCV_VCPU_NR_IRQS);
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

int vcpu_set_interrupt(struct vcpu *v, unsigned int irq);
int vcpu_unset_interrupt(struct vcpu *v, unsigned int irq);

void vcpu_sync_interrupts(struct vcpu *curr);

#endif /* ASM__RISCV__DOMAIN_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
