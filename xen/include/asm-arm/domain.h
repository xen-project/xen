#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <xen/config.h>
#include <xen/cache.h>
#include <asm/page.h>
#include <asm/p2m.h>

/* Represents state corresponding to a block of 32 interrupts */
struct vgic_irq_rank {
    spinlock_t lock; /* Covers access to all other members of this struct */
    uint32_t ienable, iactive, ipend, pendsgi;
    uint32_t icfg[2];
    uint32_t ipriority[8];
    uint32_t itargets[8];
};

struct pending_irq
{
    int irq;
    struct irq_desc *desc; /* only set it the irq corresponds to a physical irq */
    uint8_t priority;
    struct list_head link;
};

struct arch_domain
{
    struct p2m_domain p2m;

    struct {
        /*
         * Covers access to other members of this struct _except_ for
         * shared_irqs where each member contains its own locking.
         *
         * If both class of lock is required then this lock must be
         * taken first. If multiple rank locks are required (including
         * the per-vcpu private_irqs rank) then they must be taken in
         * rank order.
         */
        spinlock_t lock;
        int ctlr;
        int nr_lines;
        struct vgic_irq_rank *shared_irqs;
        struct pending_irq *pending_irqs;
    } vgic;
}  __cacheline_aligned;

struct arch_vcpu
{
    struct cpu_user_regs user_regs;

    uint32_t sctlr;
    uint32_t ttbr0, ttbr1, ttbcr;

    struct {
        struct vgic_irq_rank private_irqs;
        struct list_head inflight_irqs;
        spinlock_t lock;
    } vgic;
}  __cacheline_aligned;

void vcpu_show_execution_state(struct vcpu *);
void vcpu_show_registers(const struct vcpu *);

#endif /* __ASM_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
