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

#include <xen/bitops.h>
#include <asm/mmio.h>

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
     */
#define GIC_IRQ_GUEST_QUEUED   0
#define GIC_IRQ_GUEST_ACTIVE   1
#define GIC_IRQ_GUEST_VISIBLE  2
#define GIC_IRQ_GUEST_ENABLED  3
#define GIC_IRQ_GUEST_MIGRATING   4
    unsigned long status;
    struct irq_desc *desc; /* only set it the irq corresponds to a physical irq */
    unsigned int irq;
#define GIC_INVALID_LR         (uint8_t)~0
    uint8_t lr;
    uint8_t priority;
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
    /* vGIC sysreg emulation */
    int (*emulate_sysreg)(struct cpu_user_regs *regs, union hsr hsr);
    /* Maximum number of vCPU supported */
    const unsigned int max_vcpus;
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

#define VGIC_REG_MASK(size) ((~0UL) >> (BITS_PER_LONG - ((1 << (size)) * 8)))

/*
 * The check on the size supported by the register has to be done by
 * the caller of vgic_regN_*.
 *
 * vgic_reg_* should never be called directly. Instead use the vgic_regN_*
 * according to size of the emulated register
 *
 * Note that the alignment fault will always be taken in the guest
 * (see B3.12.7 DDI0406.b).
 */
static inline register_t vgic_reg_extract(unsigned long reg,
                                          unsigned int offset,
                                          enum dabt_size size)
{
    reg >>= 8 * offset;
    reg &= VGIC_REG_MASK(size);

    return reg;
}

static inline void vgic_reg_update(unsigned long *reg, register_t val,
                                   unsigned int offset,
                                   enum dabt_size size)
{
    unsigned long mask = VGIC_REG_MASK(size);
    int shift = offset * 8;

    *reg &= ~(mask << shift);
    *reg |= ((unsigned long)val & mask) << shift;
}

static inline void vgic_reg_setbits(unsigned long *reg, register_t bits,
                                    unsigned int offset,
                                    enum dabt_size size)
{
    unsigned long mask = VGIC_REG_MASK(size);
    int shift = offset * 8;

    *reg |= ((unsigned long)bits & mask) << shift;
}

static inline void vgic_reg_clearbits(unsigned long *reg, register_t bits,
                                      unsigned int offset,
                                      enum dabt_size size)
{
    unsigned long mask = VGIC_REG_MASK(size);
    int shift = offset * 8;

    *reg &= ~(((unsigned long)bits & mask) << shift);
}

/* N-bit register helpers */
#define VGIC_REG_HELPERS(sz, offmask)                                   \
static inline register_t vgic_reg##sz##_extract(uint##sz##_t reg,       \
                                                const mmio_info_t *info)\
{                                                                       \
    return vgic_reg_extract(reg, info->gpa & offmask,                   \
                            info->dabt.size);                           \
}                                                                       \
                                                                        \
static inline void vgic_reg##sz##_update(uint##sz##_t *reg,             \
                                         register_t val,                \
                                         const mmio_info_t *info)       \
{                                                                       \
    unsigned long tmp = *reg;                                           \
                                                                        \
    vgic_reg_update(&tmp, val, info->gpa & offmask,                     \
                    info->dabt.size);                                   \
                                                                        \
    *reg = tmp;                                                         \
}                                                                       \
                                                                        \
static inline void vgic_reg##sz##_setbits(uint##sz##_t *reg,            \
                                          register_t bits,              \
                                          const mmio_info_t *info)      \
{                                                                       \
    unsigned long tmp = *reg;                                           \
                                                                        \
    vgic_reg_setbits(&tmp, bits, info->gpa & offmask,                   \
                     info->dabt.size);                                  \
                                                                        \
    *reg = tmp;                                                         \
}                                                                       \
                                                                        \
static inline void vgic_reg##sz##_clearbits(uint##sz##_t *reg,          \
                                            register_t bits,            \
                                            const mmio_info_t *info)    \
{                                                                       \
    unsigned long tmp = *reg;                                           \
                                                                        \
    vgic_reg_clearbits(&tmp, bits, info->gpa & offmask,                 \
                       info->dabt.size);                                \
                                                                        \
    *reg = tmp;                                                         \
}

/*
 * 64 bits registers are only supported on platform with 64-bit long.
 * This is also allow us to optimize the 32 bit case by using
 * unsigned long rather than uint64_t
 */
#if BITS_PER_LONG == 64
VGIC_REG_HELPERS(64, 0x7);
#endif
VGIC_REG_HELPERS(32, 0x3);

#undef VGIC_REG_HELPERS

enum gic_sgi_mode;

/*
 * Offset of GICD_<FOO><n> with its rank, for GICD_<FOO> size <s> with
 * <b>-bits-per-interrupt.
 */
#define REG_RANK_INDEX(b, n, s) ((((n) >> s) & ((b)-1)) % 32)

#define vgic_num_irqs(d)        ((d)->arch.vgic.nr_spis + 32)

extern int domain_vgic_init(struct domain *d, unsigned int nr_spis);
extern void domain_vgic_free(struct domain *d);
extern int vcpu_vgic_init(struct vcpu *v);
extern struct vcpu *vgic_get_target_vcpu(struct vcpu *v, unsigned int virq);
extern void vgic_vcpu_inject_irq(struct vcpu *v, unsigned int virq);
extern void vgic_vcpu_inject_spi(struct domain *d, unsigned int virq);
extern void vgic_clear_pending_irqs(struct vcpu *v);
extern struct pending_irq *irq_to_pending(struct vcpu *v, unsigned int irq);
extern struct pending_irq *spi_to_pending(struct domain *d, unsigned int irq);
extern struct vgic_irq_rank *vgic_rank_offset(struct vcpu *v, int b, int n, int s);
extern struct vgic_irq_rank *vgic_rank_irq(struct vcpu *v, unsigned int irq);
extern int vgic_emulate(struct cpu_user_regs *regs, union hsr hsr);
extern void vgic_disable_irqs(struct vcpu *v, uint32_t r, int n);
extern void vgic_enable_irqs(struct vcpu *v, uint32_t r, int n);
extern void register_vgic_ops(struct domain *d, const struct vgic_ops *ops);
int vgic_v2_init(struct domain *d, int *mmio_count);
int vgic_v3_init(struct domain *d, int *mmio_count);

extern int domain_vgic_register(struct domain *d, int *mmio_count);
extern int vcpu_vgic_free(struct vcpu *v);
extern int vgic_to_sgi(struct vcpu *v, register_t sgir,
                       enum gic_sgi_mode irqmode, int virq,
                       const struct sgi_target *target);
extern void vgic_migrate_irq(struct vcpu *old, struct vcpu *new, unsigned int irq);

/* Reserve a specific guest vIRQ */
extern bool_t vgic_reserve_virq(struct domain *d, unsigned int virq);

/*
 * Allocate a guest VIRQ
 *  - spi == 0 => allocate a PPI. It will be the same on every vCPU
 *  - spi == 1 => allocate an SPI
 */
extern int vgic_allocate_virq(struct domain *d, bool_t spi);

static inline int vgic_allocate_ppi(struct domain *d)
{
    return vgic_allocate_virq(d, 0 /* ppi */);
}

static inline int vgic_allocate_spi(struct domain *d)
{
    return vgic_allocate_virq(d, 1 /* spi */);
}

extern void vgic_free_virq(struct domain *d, unsigned int virq);

void vgic_v2_setup_hw(paddr_t dbase, paddr_t cbase, paddr_t csize,
                      paddr_t vbase, uint32_t aliased_offset);

#ifdef CONFIG_HAS_GICV3
struct rdist_region;
void vgic_v3_setup_hw(paddr_t dbase,
                      unsigned int nr_rdist_regions,
                      const struct rdist_region *regions,
                      uint32_t rdist_stride);
#endif

#endif /* __ASM_ARM_VGIC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
