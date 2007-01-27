/******************************************************************************
 * irq.h
 * 
 * Interrupt distribution and delivery logic.
 * 
 * Copyright (c) 2006, K A Fraser, XenSource Inc.
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
 */

#ifndef __ASM_X86_HVM_IRQ_H__
#define __ASM_X86_HVM_IRQ_H__

#include <xen/types.h>
#include <xen/spinlock.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vioapic.h>
#include <public/hvm/save.h>

#define hvm_pci_intx_gsi(dev, intx)  \
    (((((dev)<<2) + ((dev)>>3) + (intx)) & 31) + 16)
#define hvm_pci_intx_link(dev, intx) \
    (((dev) + (intx)) & 3)

#define hvm_isa_irq_to_gsi(isa_irq) ((isa_irq) ? : 2)

/* Modify state of a PCI INTx wire. */
void hvm_pci_intx_assert(
    struct domain *d, unsigned int device, unsigned int intx);
void hvm_pci_intx_deassert(
    struct domain *d, unsigned int device, unsigned int intx);

/* Modify state of an ISA device's IRQ wire. */
void hvm_isa_irq_assert(
    struct domain *d, unsigned int isa_irq);
void hvm_isa_irq_deassert(
    struct domain *d, unsigned int isa_irq);

void hvm_set_pci_link_route(struct domain *d, u8 link, u8 isa_irq);

void hvm_set_callback_irq_level(void);
void hvm_set_callback_via(struct domain *d, uint64_t via);

int cpu_get_interrupt(struct vcpu *v, int *type);
int cpu_has_pending_irq(struct vcpu *v);
int get_isa_irq_vector(struct vcpu *vcpu, int irq, int type);
int is_isa_irq_masked(struct vcpu *v, int isa_irq);

#endif /* __ASM_X86_HVM_IRQ_H__ */
