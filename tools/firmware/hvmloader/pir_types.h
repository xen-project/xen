/*
 * pir_types.h - data structure definitions for Xen HVM $PIR support
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Citrix Systems, 2011
 *
 * See the PCI Interrupt Routing spec for more detail:
 *   http://www.microsoft.com/taiwan/whdc/archive/pciirq.mspx
 */

#ifndef PIR_TYPES_H
#define PIR_TYPES_H

#include <stdint.h>

#define NR_PIR_SLOTS 6

struct pir_slot {
    uint8_t bus;
    uint8_t dev;
    uint8_t link_a;
    uint16_t bitmap_a;
    uint8_t link_b;
    uint16_t bitmap_b;
    uint8_t link_c;
    uint16_t bitmap_c;
    uint8_t link_d;
    uint16_t bitmap_d;
    uint8_t slot;
    uint8_t reserved;
} __attribute__ ((packed));

struct pir_table {
    char signature[4];
    uint16_t version;
    uint16_t length;
    uint8_t router_bus;
    uint8_t router_devfn;
    uint16_t pci_irqs;
    uint16_t router_vid;
    uint16_t router_did;
    uint32_t miniport_data;
    uint8_t reserved[11];
    uint8_t checksum;
    struct pir_slot slots[0];
} __attribute__ ((packed));

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
