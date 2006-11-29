/*
 *  Copyright (C) 2001  MandrakeSoft S.A.
 *
 *    MandrakeSoft S.A.
 *    43, rue d'Aboukir
 *    75002 Paris - France
 *    http://www.linux-mandrake.com/
 *    http://www.mandrakesoft.com/
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifndef __ASM_X86_HVM_VIOAPIC_H__
#define __ASM_X86_HVM_VIOAPIC_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/smp.h>

#ifdef __ia64__
#define VIOAPIC_IS_IOSAPIC 1
#define VIOAPIC_NUM_PINS  24
#else
#define VIOAPIC_NUM_PINS  48 /* 16 ISA IRQs, 32 non-legacy PCI IRQS. */
#endif

#if !VIOAPIC_IS_IOSAPIC
#define VIOAPIC_VERSION_ID 0x11 /* IOAPIC version */
#else
#define VIOAPIC_VERSION_ID 0x21 /* IOSAPIC version */
#endif

#define VIOAPIC_EDGE_TRIG  0
#define VIOAPIC_LEVEL_TRIG 1

#define VIOAPIC_DEFAULT_BASE_ADDRESS  0xfec00000
#define VIOAPIC_MEM_LENGTH            0x100

/* Direct registers. */
#define VIOAPIC_REG_SELECT  0x00
#define VIOAPIC_REG_WINDOW  0x10
#define VIOAPIC_REG_EOI     0x40 /* IA64 IOSAPIC only */

/* Indirect registers. */
#define VIOAPIC_REG_APIC_ID 0x00 /* x86 IOAPIC only */
#define VIOAPIC_REG_VERSION 0x01
#define VIOAPIC_REG_ARB_ID  0x02 /* x86 IOAPIC only */

#define domain_vioapic(d) (&(d)->arch.hvm_domain.irq.vioapic)
#define vioapic_domain(v) (container_of((v), struct domain, \
                                        arch.hvm_domain.irq.vioapic))

union vioapic_redir_entry
{
    uint64_t bits;
    struct {
        uint8_t vector;
        uint8_t delivery_mode:3;
        uint8_t dest_mode:1;
        uint8_t delivery_status:1;
        uint8_t polarity:1;
        uint8_t remote_irr:1;
        uint8_t trig_mode:1;
        uint8_t mask:1;
        uint8_t reserve:7;
#if !VIOAPIC_IS_IOSAPIC
        uint8_t reserved[4];
        uint8_t dest_id;
#else
        uint8_t reserved[3];
        uint16_t dest_id;
#endif
    } fields;
};

struct vioapic {
    uint32_t ioregsel, id;
    unsigned long base_address;
    union vioapic_redir_entry redirtbl[VIOAPIC_NUM_PINS];
};

void vioapic_init(struct domain *d);
void vioapic_irq_positive_edge(struct domain *d, unsigned int irq);
void vioapic_update_EOI(struct domain *d, int vector);

#endif /* __ASM_X86_HVM_VIOAPIC_H__ */
