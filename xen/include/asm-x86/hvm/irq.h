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
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vioapic.h>
#include <public/hvm/save.h>

struct dev_intx_gsi_link {
    struct list_head list;
    uint8_t device;
    uint8_t intx;
    uint8_t gsi;
    uint8_t link;
};

struct hvm_mirq_dpci_mapping {
    uint8_t valid;
    int pending;
    struct list_head digl_list;
    struct domain *dom;
};

struct hvm_girq_dpci_mapping {
    uint8_t valid;
    uint8_t device;
    uint8_t intx;
    uint8_t machine_gsi;
};

#define NR_ISAIRQS  16
#define NR_LINK     4
struct hvm_irq_dpci {
    spinlock_t dirq_lock;
    /* Machine IRQ to guest device/intx mapping. */
    struct hvm_mirq_dpci_mapping mirq[NR_IRQS];
    /* Guest IRQ to guest device/intx mapping. */
    struct hvm_girq_dpci_mapping girq[NR_IRQS];
    DECLARE_BITMAP(dirq_mask, NR_IRQS);
    /* Record of mapped ISA IRQs */
    DECLARE_BITMAP(isairq_map, NR_ISAIRQS);
    /* Record of mapped Links */
    DECLARE_BITMAP(link_map, NR_LINK);
    struct timer hvm_timer[NR_IRQS];
};

struct hvm_irq {
    /*
     * Virtual interrupt wires for a single PCI bus.
     * Indexed by: device*4 + INTx#.
     */
    struct hvm_hw_pci_irqs pci_intx;

    /*
     * Virtual interrupt wires for ISA devices.
     * Indexed by ISA IRQ (assumes no ISA-device IRQ sharing).
     */
    struct hvm_hw_isa_irqs isa_irq;

    /*
     * PCI-ISA interrupt router.
     * Each PCI <device:INTx#> is 'wire-ORed' into one of four links using
     * the traditional 'barber's pole' mapping ((device + INTx#) & 3).
     * The router provides a programmable mapping from each link to a GSI.
     */
    struct hvm_hw_pci_link pci_link;

    /* Virtual interrupt and via-link for paravirtual platform driver. */
    uint32_t callback_via_asserted;
    union {
        enum {
            HVMIRQ_callback_none,
            HVMIRQ_callback_gsi,
            HVMIRQ_callback_pci_intx
        } callback_via_type;
    };
    union {
        uint32_t gsi;
        struct { uint8_t dev, intx; } pci;
    } callback_via;

    /* Number of INTx wires asserting each PCI-ISA link. */
    u8 pci_link_assert_count[4];

    /*
     * Number of wires asserting each GSI.
     * 
     * GSIs 0-15 are the ISA IRQs. ISA devices map directly into this space
     * except ISA IRQ 0, which is connected to GSI 2.
     * PCI links map into this space via the PCI-ISA bridge.
     * 
     * GSIs 16+ are used only be PCI devices. The mapping from PCI device to
     * GSI is as follows: ((device*4 + device/8 + INTx#) & 31) + 16
     */
    u8 gsi_assert_count[VIOAPIC_NUM_PINS];

    /*
     * GSIs map onto PIC/IO-APIC in the usual way:
     *  0-7:  Master 8259 PIC, IO-APIC pins 0-7
     *  8-15: Slave  8259 PIC, IO-APIC pins 8-15
     *  16+ : IO-APIC pins 16+
     */

    /* Last VCPU that was delivered a LowestPrio interrupt. */
    u8 round_robin_prev_vcpu;

    struct hvm_irq_dpci *dpci;
};

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

void hvm_maybe_deassert_evtchn_irq(void);
void hvm_assert_evtchn_irq(struct vcpu *v);
void hvm_set_callback_via(struct domain *d, uint64_t via);

/* Check/Acknowledge next pending interrupt. */
struct hvm_intack hvm_vcpu_has_pending_irq(struct vcpu *v);
struct hvm_intack hvm_vcpu_ack_pending_irq(struct vcpu *v,
                                           struct hvm_intack intack);

#endif /* __ASM_X86_HVM_IRQ_H__ */
