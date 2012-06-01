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
    /* inflight is used to append instances of pending_irq to
     * vgic.inflight_irqs */
    struct list_head inflight;
    /* lr_queue is used to append instances of pending_irq to
     * gic.lr_pending */
    struct list_head lr_queue;
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
    struct {
        uint32_t    r4;
        uint32_t    r5;
        uint32_t    r6;
        uint32_t    r7;
        uint32_t    r8;
        uint32_t    r9;
        uint32_t    sl;
        uint32_t    fp;
        uint32_t    sp;
        uint32_t    pc;
    } saved_context;

    void *stack;

    /*
     * Points into ->stack, more convenient than doing pointer arith
     * all the time.
     */
    struct cpu_info *cpu_info;

    uint32_t sctlr;
    uint32_t ttbr0, ttbr1, ttbcr;

    struct {
        struct vgic_irq_rank private_irqs;
        /* This list is ordered by IRQ priority and it is used to keep
         * track of the IRQs that the VGIC injected into the guest.
         * Depending on the availability of LR registers, the IRQs might
         * actually be in an LR, and therefore injected into the guest,
         * or queued in gic.lr_pending.
         * As soon as an IRQ is EOI'd by the guest and removed from the
         * corresponding LR it is also removed from this list. */
        struct list_head inflight_irqs;
        spinlock_t lock;
    } vgic;

    struct {
        struct timer timer;
        uint32_t ctl;
        s_time_t offset;
        s_time_t cval;
    } vtimer;
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
