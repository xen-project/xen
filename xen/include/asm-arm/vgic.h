/*
 * ARM Virtual Generic Interrupt Controller support
 *
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ASM_ARM_VGIC_H__
#define __ASM_ARM_VGIC_H__

#ifdef CONFIG_NEW_VGIC
#include <asm/new_vgic.h>
#else

#include <xen/radix-tree.h>
#include <xen/rbtree.h>

struct pending_irq
{
    /*
     * The following two states track the lifecycle of the guest irq.
     * However because we are not sure and we don't want to track
     * whether an irq added to an LR register is PENDING or ACTIVE, the
     * following states are just an approximation.
     *
     * GIC_IRQ_GUEST_QUEUED: the irq is asserted and queued for
     * injection into the guest's LRs.
     *
     * GIC_IRQ_GUEST_VISIBLE: the irq has been added to an LR register,
     * therefore the guest is aware of it. From the guest point of view
     * the irq can be pending (if the guest has not acked the irq yet)
     * or active (after acking the irq).
     *
     * In order for the state machine to be fully accurate, for level
     * interrupts, we should keep the interrupt's pending state until
     * the guest deactivates the irq. However because we are not sure
     * when that happens, we instead track whether there is an interrupt
     * queued using GIC_IRQ_GUEST_QUEUED. We clear it when we add it to
     * an LR register. We set it when we receive another interrupt
     * notification.  Therefore it is possible to set
     * GIC_IRQ_GUEST_QUEUED while the irq is GIC_IRQ_GUEST_VISIBLE. We
     * could also change the state of the guest irq in the LR register
     * from active to active and pending, but for simplicity we simply
     * inject a second irq after the guest EOIs the first one.
     *
     *
     * An additional state is used to keep track of whether the guest
     * irq is enabled at the vgicd level:
     *
     * GIC_IRQ_GUEST_ENABLED: the guest IRQ is enabled at the VGICD
     * level (GICD_ICENABLER/GICD_ISENABLER).
     *
     * GIC_IRQ_GUEST_MIGRATING: the irq is being migrated to a different
     * vcpu while it is still inflight and on an GICH_LR register on the
     * old vcpu.
     *
     * GIC_IRQ_GUEST_PRISTINE_LPI: the IRQ is a newly mapped LPI, which
     * has never been in an LR before. This means that any trace of an
     * LPI with the same number in an LR must be from an older LPI, which
     * has been unmapped before.
     *
     */
#define GIC_IRQ_GUEST_QUEUED   0
#define GIC_IRQ_GUEST_ACTIVE   1
#define GIC_IRQ_GUEST_VISIBLE  2
#define GIC_IRQ_GUEST_ENABLED  3
#define GIC_IRQ_GUEST_MIGRATING   4
#define GIC_IRQ_GUEST_PRISTINE_LPI  5
    unsigned long status;
    struct irq_desc *desc; /* only set if the irq corresponds to a physical irq */
    unsigned int irq;
#define GIC_INVALID_LR         (uint8_t)~0
    uint8_t lr;
    uint8_t priority;
    uint8_t lpi_priority;       /* Caches the priority if this is an LPI. */
    uint8_t lpi_vcpu_id;        /* The VCPU for an LPI. */
    /* inflight is used to append instances of pending_irq to
     * vgic.inflight_irqs */
    struct list_head inflight;
    /* lr_queue is used to append instances of pending_irq to
     * lr_pending. lr_pending is a per vcpu queue, therefore lr_queue
     * accesses are protected with the vgic lock.
     * TODO: when implementing irq migration, taking only the current
     * vgic lock is not going to be enough. */
    struct list_head lr_queue;
};

#define NR_INTERRUPT_PER_RANK   32
#define INTERRUPT_RANK_MASK (NR_INTERRUPT_PER_RANK - 1)

/* Represents state corresponding to a block of 32 interrupts */
struct vgic_irq_rank {
    spinlock_t lock; /* Covers access to all other members of this struct */

    uint8_t index;

    uint32_t ienable;
    uint32_t icfg[2];

    /*
     * Provide efficient access to the priority of an vIRQ while keeping
     * the emulation simple.
     * Note, this is working fine as long as Xen is using little endian.
     */
    union {
        uint8_t priority[32];
        uint32_t ipriorityr[8];
    };

    /*
     * It's more convenient to store a target VCPU per vIRQ
     * than the register ITARGETSR/IROUTER itself.
     * Use atomic operations to read/write the vcpu fields to avoid
     * taking the rank lock.
     */
    uint8_t vcpu[32];
};

struct vgic_dist {
    /* Version of the vGIC */
    enum gic_version version;
    /* GIC HW version specific vGIC driver handler */
    const struct vgic_ops *handler;
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
    uint32_t ctlr;
    int nr_spis; /* Number of SPIs */
    unsigned long *allocated_irqs; /* bitmap of IRQs allocated */
    struct vgic_irq_rank *shared_irqs;
    /*
     * SPIs are domain global, SGIs and PPIs are per-VCPU and stored in
     * struct arch_vcpu.
     */
    struct pending_irq *pending_irqs;
    /* Base address for guest GIC */
    paddr_t dbase; /* Distributor base address */
#ifdef CONFIG_GICV3
    /* GIC V3 addressing */
    /* List of contiguous occupied by the redistributors */
    struct vgic_rdist_region {
        paddr_t base;                   /* Base address */
        paddr_t size;                   /* Size */
        unsigned int first_cpu;         /* First CPU handled */
    } *rdist_regions;
    int nr_regions;                     /* Number of rdist regions */
    unsigned long int nr_lpis;
    uint64_t rdist_propbase;
    struct rb_root its_devices;         /* Devices mapped to an ITS */
    spinlock_t its_devices_lock;        /* Protects the its_devices tree */
    struct radix_tree_root pend_lpi_tree; /* Stores struct pending_irq's */
    rwlock_t pend_lpi_tree_lock;        /* Protects the pend_lpi_tree */
    struct list_head vits_list;         /* List of virtual ITSes */
    unsigned int intid_bits;
    /*
     * TODO: if there are more bool's being added below, consider
     * a flags variable instead.
     */
    bool rdists_enabled;                /* Is any redistributor enabled? */
    bool has_its;
#endif
};

struct vgic_cpu {
    /*
     * SGIs and PPIs are per-VCPU, SPIs are domain global and in
     * struct arch_domain.
     */
    struct pending_irq pending_irqs[32];
    struct vgic_irq_rank *private_irqs;

    /* This list is ordered by IRQ priority and it is used to keep
     * track of the IRQs that the VGIC injected into the guest.
     * Depending on the availability of LR registers, the IRQs might
     * actually be in an LR, and therefore injected into the guest,
     * or queued in gic.lr_pending.
     * As soon as an IRQ is EOI'd by the guest and removed from the
     * corresponding LR it is also removed from this list. */
    struct list_head inflight_irqs;
    /* lr_pending is used to queue IRQs (struct pending_irq) that the
     * vgic tried to inject in the guest (calling gic_set_guest_irq) but
     * no LRs were available at the time.
     * As soon as an LR is freed we remove the first IRQ from this
     * list and write it to the LR register.
     * lr_pending is a subset of vgic.inflight_irqs. */
    struct list_head lr_pending;
    spinlock_t lock;

    /* GICv3: redistributor base and flags for this vCPU */
    paddr_t rdist_base;
    uint64_t rdist_pendbase;
#define VGIC_V3_RDIST_LAST      (1 << 0)        /* last vCPU of the rdist */
#define VGIC_V3_LPIS_ENABLED    (1 << 1)
    uint8_t flags;
};

struct sgi_target {
    uint8_t aff1;
    uint16_t list;
};

static inline void sgi_target_init(struct sgi_target *sgi_target)
{
    sgi_target->aff1 = 0;
    sgi_target->list = 0;
}

struct vgic_ops {
    /* Initialize vGIC */
    int (*vcpu_init)(struct vcpu *v);
    /* Domain specific initialization of vGIC */
    int (*domain_init)(struct domain *d);
    /* Release resources that were allocated by domain_init */
    void (*domain_free)(struct domain *d);
    /* vGIC sysreg/cpregs emulate */
    bool (*emulate_reg)(struct cpu_user_regs *regs, union hsr hsr);
    /* lookup the struct pending_irq for a given LPI interrupt */
    struct pending_irq *(*lpi_to_pending)(struct domain *d, unsigned int vlpi);
    int (*lpi_get_priority)(struct domain *d, uint32_t vlpi);
};

/* Number of ranks of interrupt registers for a domain */
#define DOMAIN_NR_RANKS(d) (((d)->arch.vgic.nr_spis+31)/32)

#define vgic_lock(v)   spin_lock_irq(&(v)->domain->arch.vgic.lock)
#define vgic_unlock(v) spin_unlock_irq(&(v)->domain->arch.vgic.lock)

#define vgic_lock_rank(v, r, flags)   spin_lock_irqsave(&(r)->lock, flags)
#define vgic_unlock_rank(v, r, flags) spin_unlock_irqrestore(&(r)->lock, flags)

/*
 * Rank containing GICD_<FOO><n> for GICD_<FOO> with
 * <b>-bits-per-interrupt
 */
static inline int REG_RANK_NR(int b, uint32_t n)
{
    switch ( b )
    {
    /*
     * IRQ ranks are of size 32. So n cannot be shifted beyond 5 for 32
     * and above. For 64-bit n is already shifted DBAT_DOUBLE_WORD
     * by the caller
     */
    case 64:
    case 32: return n >> 5;
    case 16: return n >> 4;
    case 8: return n >> 3;
    case 4: return n >> 2;
    case 2: return n >> 1;
    case 1: return n;
    default: BUG();
    }
}

enum gic_sgi_mode;

/*
 * Offset of GICD_<FOO><n> with its rank, for GICD_<FOO> size <s> with
 * <b>-bits-per-interrupt.
 */
#define REG_RANK_INDEX(b, n, s) ((((n) >> s) & ((b)-1)) % 32)


extern struct vcpu *vgic_get_target_vcpu(struct vcpu *v, unsigned int virq);
extern void vgic_remove_irq_from_queues(struct vcpu *v, struct pending_irq *p);
extern void gic_remove_from_lr_pending(struct vcpu *v, struct pending_irq *p);
extern void vgic_init_pending_irq(struct pending_irq *p, unsigned int virq);
extern struct pending_irq *irq_to_pending(struct vcpu *v, unsigned int irq);
extern struct pending_irq *spi_to_pending(struct domain *d, unsigned int irq);
extern struct vgic_irq_rank *vgic_rank_offset(struct vcpu *v, int b, int n, int s);
extern struct vgic_irq_rank *vgic_rank_irq(struct vcpu *v, unsigned int irq);
extern void vgic_disable_irqs(struct vcpu *v, uint32_t r, int n);
extern void vgic_enable_irqs(struct vcpu *v, uint32_t r, int n);
extern void register_vgic_ops(struct domain *d, const struct vgic_ops *ops);
int vgic_v2_init(struct domain *d, int *mmio_count);
int vgic_v3_init(struct domain *d, int *mmio_count);

extern bool vgic_to_sgi(struct vcpu *v, register_t sgir,
                        enum gic_sgi_mode irqmode, int virq,
                        const struct sgi_target *target);
extern bool vgic_migrate_irq(struct vcpu *old, struct vcpu *new, unsigned int irq);

#endif /* !CONFIG_NEW_VGIC */

/*** Common VGIC functions used by Xen arch code ****/

/*
 * In the moment vgic_num_irqs() just covers SPIs and the private IRQs,
 * as it's mostly used for allocating the pending_irq and irq_desc array,
 * in which LPIs don't participate.
 */
#define vgic_num_irqs(d)        ((d)->arch.vgic.nr_spis + 32)

/*
 * Allocate a guest VIRQ
 *  - spi == 0 => allocate a PPI. It will be the same on every vCPU
 *  - spi == 1 => allocate an SPI
 */
extern int vgic_allocate_virq(struct domain *d, bool spi);
/* Reserve a specific guest vIRQ */
extern bool vgic_reserve_virq(struct domain *d, unsigned int virq);
extern void vgic_free_virq(struct domain *d, unsigned int virq);

static inline int vgic_allocate_ppi(struct domain *d)
{
    return vgic_allocate_virq(d, false /* ppi */);
}

static inline int vgic_allocate_spi(struct domain *d)
{
    return vgic_allocate_virq(d, true /* spi */);
}

struct irq_desc *vgic_get_hw_irq_desc(struct domain *d, struct vcpu *v,
                                      unsigned int virq);
int vgic_connect_hw_irq(struct domain *d, struct vcpu *v, unsigned int virq,
                        struct irq_desc *desc, bool connect);

bool vgic_evtchn_irq_pending(struct vcpu *v);

int domain_vgic_register(struct domain *d, int *mmio_count);
int domain_vgic_init(struct domain *d, unsigned int nr_spis);
void domain_vgic_free(struct domain *d);
int vcpu_vgic_init(struct vcpu *vcpu);
int vcpu_vgic_free(struct vcpu *vcpu);

void vgic_inject_irq(struct domain *d, struct vcpu *v, unsigned int virq,
                     bool level);

extern void vgic_clear_pending_irqs(struct vcpu *v);

extern bool vgic_emulate(struct cpu_user_regs *regs, union hsr hsr);

/* Maximum vCPUs for a specific vGIC version, or 0 for unsupported. */
unsigned int vgic_max_vcpus(unsigned int domctl_vgic_version);

void vgic_v2_setup_hw(paddr_t dbase, paddr_t cbase, paddr_t csize,
                      paddr_t vbase, uint32_t aliased_offset);

#ifdef CONFIG_GICV3
struct rdist_region;
void vgic_v3_setup_hw(paddr_t dbase,
                      unsigned int nr_rdist_regions,
                      const struct rdist_region *regions,
                      unsigned int intid_bits);
#endif

void vgic_sync_to_lrs(void);
void vgic_sync_from_lrs(struct vcpu *v);

int vgic_vcpu_pending_irq(struct vcpu *v);

#endif /* __ASM_ARM_VGIC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
