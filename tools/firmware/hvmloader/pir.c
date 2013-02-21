/*
 * pir.c: Support for genrating $PIR tables.
 *
 * Copyright (c) 2011 Citrix Systems Inc
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include "config.h"
#include "pir_types.h"
#include "util.h"

/*
 * The structure of these tables is described in
 * http://www.microsoft.com/taiwan/whdc/archive/pciirq.mspx
 */
unsigned long create_pir_tables(void)
{
    int length = sizeof(struct pir_table)
        + sizeof(struct pir_slot) * NR_PIR_SLOTS;
    struct pir_table *pir = scratch_alloc(length, 0);
    int i, checksum;

    memset(pir, 0, length);

    memcpy(pir->signature, "$PIR", 4);
    pir->version = 0x0100;
    pir->length = length;

    pir->router_bus = 0;
    pir->router_devfn = PCI_ISA_DEVFN;
    pir->router_vid = 0x8086;
    pir->router_did = 0x122e;

    pir->pci_irqs = 0x0000;

    for ( i = 0 ; i < NR_PIR_SLOTS; i++ )
    {
        struct pir_slot *slot = &pir->slots[i];
        slot->slot = i;
        slot->bus = 0;
        slot->dev = i<<3;
        slot->link_a = 0x60 + (i+1)%4;
        slot->bitmap_a = PCI_ISA_IRQ_MASK;
        slot->link_b = 0x60 + (i+2)%4;
        slot->bitmap_b = PCI_ISA_IRQ_MASK;
        slot->link_c = 0x60 + (i+3)%4;
        slot->bitmap_c = PCI_ISA_IRQ_MASK;
        slot->link_d = 0x60 + (i+4)%4;
        slot->bitmap_d = PCI_ISA_IRQ_MASK;
    }

    checksum = 0;
    for ( i = 0; i < length; i++ )
        checksum += ((int8_t *)pir)[i];
    pir->checksum = -checksum;

    return (unsigned long)pir;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
