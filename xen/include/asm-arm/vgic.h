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

/* Represents state corresponding to a block of 32 interrupts */
struct vgic_irq_rank {
    spinlock_t lock; /* Covers access to all other members of this struct */
    uint32_t ienable, iactive, ipend, pendsgi;
    uint32_t icfg[2];
    uint32_t ipriority[8];
    uint32_t itargets[8];
};

/* Number of ranks of interrupt registers for a domain */
#define DOMAIN_NR_RANKS(d) (((d)->arch.vgic.nr_lines+31)/32)

#define vgic_lock(v)   spin_lock_irq(&(v)->domain->arch.vgic.lock)
#define vgic_unlock(v) spin_unlock_irq(&(v)->domain->arch.vgic.lock)

#define vgic_lock_rank(v, r) spin_lock(&(r)->lock)
#define vgic_unlock_rank(v, r) spin_unlock(&(r)->lock)

/*
 * Rank containing GICD_<FOO><n> for GICD_<FOO> with
 * <b>-bits-per-interrupt
 */
static inline int REG_RANK_NR(int b, uint32_t n)
{
    switch ( b )
    {
    case 8: return n >> 3;
    case 4: return n >> 2;
    case 2: return n >> 1;
    case 1: return n;
    default: BUG();
    }
}

static inline uint32_t vgic_byte_read(uint32_t val, int sign, int offset)
{
    int byte = offset & 0x3;

    val = val >> (8*byte);
    if ( sign && (val & 0x80) )
        val |= 0xffffff00;
    else
        val &= 0x000000ff;
    return val;
}

static inline void vgic_byte_write(uint32_t *reg, uint32_t var, int offset)
{
    int byte = offset & 0x3;

    var &= (0xff << (8*byte));

    *reg &= ~(0xff << (8*byte));
    *reg |= var;
}

/*
 * Offset of GICD_<FOO><n> with its rank, for GICD_<FOO> with
 * <b>-bits-per-interrupt.
 */
#define REG_RANK_INDEX(b, n) (((n) >> 2) & ((b)-1))

extern int domain_vgic_init(struct domain *d);
extern void domain_vgic_free(struct domain *d);
extern int vcpu_vgic_init(struct vcpu *v);
extern void vgic_vcpu_inject_irq(struct vcpu *v, unsigned int irq);
extern void vgic_clear_pending_irqs(struct vcpu *v);

extern int vcpu_vgic_free(struct vcpu *v);
#endif /* __ASM_ARM_VGIC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
