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

/* Represents state corresponding to a block of 32 interrupts */
struct vgic_irq_rank {
    spinlock_t lock; /* Covers access to all other members of this struct */
    uint32_t ienable, iactive, ipend, pendsgi;
    uint32_t icfg[2];
    uint32_t ipriority[8];
    uint32_t itargets[8];
};

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
