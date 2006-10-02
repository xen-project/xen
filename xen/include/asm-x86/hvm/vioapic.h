/*
 *
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

#ifndef __ASM_X86_HVM_IOAPIC_H__
#define __ASM_X86_HVM_IOAPIC_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/smp.h>

#ifndef __ia64__
#define IOAPIC_VERSION_ID 0x11
#else
#define IOAPIC_VERSION_ID 0x21
#endif

#define IOAPIC_NUM_PINS 24
#define MAX_LAPIC_NUM   32

#define IOAPIC_LEVEL_TRIGGER 1

#define IOAPIC_DEFAULT_BASE_ADDRESS  0xfec00000
#define IOAPIC_MEM_LENGTH            0x100

#define IOAPIC_ENABLE_MASK  0x0
#define IOAPIC_ENABLE_FLAG  (1 << IOAPIC_ENABLE_MASK)
#define IOAPICEnabled(s)    (s->flags & IOAPIC_ENABLE_FLAG)

#define IOAPIC_REG_SELECT  0x0
#define IOAPIC_REG_WINDOW  0x10

#ifdef __ia64__
#define IOAPIC_REG_ASSERTION    0x20
#define IOAPIC_REG_EOI          0x40
#endif

#ifndef __ia64__
#define IOAPIC_REG_APIC_ID 0x0
#define IOAPIC_REG_ARB_ID  0x2
#endif

#define IOAPIC_REG_VERSION 0x1

typedef union RedirStatus
{
    uint64_t value;
    struct {
        uint8_t vector;
        uint8_t deliver_mode:3;
        uint8_t destmode:1;
        uint8_t delivestatus:1;
        uint8_t polarity:1;
        uint8_t remoteirr:1;
        uint8_t trigmod:1;
        uint8_t mask:1;         /* interrupt mask*/
        uint8_t reserve:7;
#ifndef __ia64__
        uint8_t reserved[4];
        uint8_t dest_id;
#else
        uint8_t reserved[3];
        uint16_t dest_id;
#endif
    } RedirForm;
} RedirStatus;

typedef struct hvm_vioapic {
    uint32_t irr;
    uint32_t irr_xen; /* interrupts forced on by the hypervisor. */
    uint32_t isr;           /* This is used for level trigger */
    uint32_t imr;
    uint32_t ioregsel;
    uint32_t flags;
    uint32_t lapic_count;
    uint32_t id;
    uint32_t arb_id;
    unsigned long base_address;
    RedirStatus redirtbl[IOAPIC_NUM_PINS];
    struct vlapic *lapic_info[MAX_LAPIC_NUM];
    struct domain *domain;
} hvm_vioapic_t;

hvm_vioapic_t *hvm_vioapic_init(struct domain *d);

void hvm_vioapic_do_irqs_clear(struct domain *d, uint16_t irqs);
void hvm_vioapic_do_irqs(struct domain *d, uint16_t irqs);
void hvm_vioapic_set_xen_irq(struct domain *d, int irq, int level);
void hvm_vioapic_set_irq(struct domain *d, int irq, int level);

int hvm_vioapic_add_lapic(struct vlapic *vlapic, struct vcpu *v);

void ioapic_update_EOI(struct domain *d, int vector);

#ifdef HVM_DOMAIN_SAVE_RESTORE
void ioapic_save(QEMUFile* f, void* opaque);
int ioapic_load(QEMUFile* f, void* opaque, int version_id);
#endif

#endif /* __ASM_X86_HVM_IOAPIC_H__ */
