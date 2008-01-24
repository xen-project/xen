/*
 * Copyright (c) 2007, Neocleus Corporation.
 * Copyright (c) 2007, Intel Corporation.
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
 *
 * Alex Novik <alex@neocleus.com>
 * Allen Kay <allen.m.kay@intel.com>
 * Guy Zana <guy@neocleus.com>
 *
 * This file implements direct PCI assignment to a HVM guest
 */

#include "vl.h"
#include "pass-through.h"
#include "pci/header.h"
#include "pci/pci.h"

extern FILE *logfile;

static int token_value(char *token)
{
    token = strchr(token, 'x') + 1;
    return strtol(token, NULL, 16);
}

static int next_bdf(char **str, int *seg, int *bus, int *dev, int *func)
{
    char *token;

    if ( !(*str) || !strchr(*str, ',') )
        return 0;

    token = *str;
    *seg  = token_value(token);
    token = strchr(token, ',') + 1;
    *bus  = token_value(token);
    token = strchr(token, ',') + 1;
    *dev  = token_value(token);
    token = strchr(token, ',') + 1;
    *func  = token_value(token);
    token = strchr(token, ',');
    *str = token ? token + 1 : NULL;

    return 1;
}

/* Being called each time a mmio region has been updated */
void pt_iomem_map(PCIDevice *d, int i, uint32_t e_phys, uint32_t e_size,
                  int type)
{
    struct pt_dev *assigned_device  = (struct pt_dev *)d; 
    uint32_t old_ebase = assigned_device->bases[i].e_physbase;
    int first_map = ( assigned_device->bases[i].e_size == 0 );
    int ret = 0;

    assigned_device->bases[i].e_physbase = e_phys;
    assigned_device->bases[i].e_size= e_size;

    PT_LOG("e_phys=%08x maddr=%08x type=%d len=%08x index=%d\n",
        e_phys, assigned_device->bases[i].access.maddr, type, e_size, i);

    if ( e_size == 0 )
        return;

    if ( !first_map )
    {
        /* Remove old mapping */
        ret = xc_domain_memory_mapping(xc_handle, domid,
                old_ebase >> XC_PAGE_SHIFT,
                assigned_device->bases[i].access.maddr >> XC_PAGE_SHIFT,
                (e_size+XC_PAGE_SIZE-1) >> XC_PAGE_SHIFT,
                DPCI_REMOVE_MAPPING);
        if ( ret != 0 )
        {
            PT_LOG("Error: remove old mapping failed!\n");
            return;
        }
    }

    /* Create new mapping */
    ret = xc_domain_memory_mapping(xc_handle, domid,
            assigned_device->bases[i].e_physbase >> XC_PAGE_SHIFT,
            assigned_device->bases[i].access.maddr >> XC_PAGE_SHIFT,
            (e_size+XC_PAGE_SIZE-1) >> XC_PAGE_SHIFT,
            DPCI_ADD_MAPPING);
    if ( ret != 0 )
        PT_LOG("Error: create new mapping failed!\n");

}

/* Being called each time a pio region has been updated */
void pt_ioport_map(PCIDevice *d, int i,
                   uint32_t e_phys, uint32_t e_size, int type)
{
    struct pt_dev *assigned_device  = (struct pt_dev *)d;
    uint32_t old_ebase = assigned_device->bases[i].e_physbase;
    int first_map = ( assigned_device->bases[i].e_size == 0 );
    int ret = 0;

    assigned_device->bases[i].e_physbase = e_phys;
    assigned_device->bases[i].e_size= e_size;

    PT_LOG("e_phys=%04x pio_base=%04x len=%04x index=%d\n",
        (uint16_t)e_phys, (uint16_t)assigned_device->bases[i].access.pio_base,
        (uint16_t)e_size, i);

    if ( e_size == 0 )
        return;

    if ( !first_map )
    {
        /* Remove old mapping */
        ret = xc_domain_ioport_mapping(xc_handle, domid, old_ebase,
                    assigned_device->bases[i].access.pio_base, e_size,
                    DPCI_REMOVE_MAPPING);
        if ( ret != 0 )
        {
            PT_LOG("Error: remove old mapping failed!\n");
            return;
        }
    }

    /* Create new mapping */
    ret = xc_domain_ioport_mapping(xc_handle, domid, e_phys,
                assigned_device->bases[i].access.pio_base, e_size,
                DPCI_ADD_MAPPING);
    if ( ret != 0 )
        PT_LOG("Error: create new mapping failed!\n");

}

static void pt_pci_write_config(PCIDevice *d, uint32_t address, uint32_t val,
                                int len)
{
    struct pt_dev *assigned_device = (struct pt_dev *)d;
    struct pci_dev *pci_dev = assigned_device->pci_dev;

#ifdef PT_DEBUG_PCI_CONFIG_ACCESS
    PT_LOG("(%x.%x): address=%04x val=0x%08x len=%d\n",
       (d->devfn >> 3) & 0x1F, (d->devfn & 0x7), address, val, len);
#endif

    /* Pre-write hooking */
    switch ( address ) {
    case 0x0C ... 0x3F:
        pci_default_write_config(d, address, val, len);
        return;
    }

    /* PCI config pass-through */
    if (address == 0x4) {
        switch (len){
        case 1:
            pci_write_byte(pci_dev, address, val);
            break;
        case 2:
            pci_write_word(pci_dev, address, val);
            break;
        case 4:
            pci_write_long(pci_dev, address, val);
            break;
        }
    }

    if (address == 0x4) {
        /* Post-write hooking */
        pci_default_write_config(d, address, val, len);
    }
}

static uint32_t pt_pci_read_config(PCIDevice *d, uint32_t address, int len)
{
    struct pt_dev *assigned_device = (struct pt_dev *)d;
    struct pci_dev *pci_dev = assigned_device->pci_dev;
    uint32_t val = 0xFF;

    /* Pre-hooking */
    switch ( address ) {
    case 0x0C ... 0x3F:
        val = pci_default_read_config(d, address, len);
        goto exit;
    }

    switch ( len ) {
    case 1:
        val = pci_read_byte(pci_dev, address);
        break;
    case 2:
        val = pci_read_word(pci_dev, address);
        break;
    case 4:
        val = pci_read_long(pci_dev, address);
        break;
    }

exit:

#ifdef PT_DEBUG_PCI_CONFIG_ACCESS
    PT_LOG("(%x.%x): address=%04x val=0x%08x len=%d\n",
       (d->devfn >> 3) & 0x1F, (d->devfn & 0x7), address, val, len);
#endif

    return val;
}

static int pt_register_regions(struct pt_dev *assigned_device)
{
    int i = 0;
    uint32_t bar_data = 0;
    struct pci_dev *pci_dev = assigned_device->pci_dev;
    PCIDevice *d = &assigned_device->dev;

    /* Register PIO/MMIO BARs */
    for ( i = 0; i < PCI_BAR_ENTRIES; i++ )
    {
        if ( pci_dev->base_addr[i] )
        {
            assigned_device->bases[i].e_physbase = pci_dev->base_addr[i];
            assigned_device->bases[i].access.u = pci_dev->base_addr[i];

            /* Register current region */
            bar_data = *((uint32_t*)(d->config + PCI_BASE_ADDRESS_0) + i);
            if ( bar_data & PCI_ADDRESS_SPACE_IO )
                pci_register_io_region((PCIDevice *)assigned_device, i,
                    (uint32_t)pci_dev->size[i], PCI_ADDRESS_SPACE_IO,
                    pt_ioport_map);
            else if ( bar_data & PCI_ADDRESS_SPACE_MEM_PREFETCH )
                pci_register_io_region((PCIDevice *)assigned_device, i,
                    (uint32_t)pci_dev->size[i], PCI_ADDRESS_SPACE_MEM_PREFETCH,
                    pt_iomem_map);
            else
                pci_register_io_region((PCIDevice *)assigned_device, i, 
                    (uint32_t)pci_dev->size[i], PCI_ADDRESS_SPACE_MEM,
                    pt_iomem_map);

            PT_LOG("IO region registered (size=0x%08x base_addr=0x%08x)\n",
                (uint32_t)(pci_dev->size[i]),
                (uint32_t)(pci_dev->base_addr[i]));
        }
    }

    /* Register expansion ROM address */
    if ( pci_dev->rom_base_addr && pci_dev->rom_size )
    {
        assigned_device->bases[PCI_ROM_SLOT].e_physbase =
            pci_dev->rom_base_addr;
        assigned_device->bases[PCI_ROM_SLOT].access.maddr =
            pci_dev->rom_base_addr;
        pci_register_io_region((PCIDevice *)assigned_device, PCI_ROM_SLOT,
            pci_dev->rom_size, PCI_ADDRESS_SPACE_MEM_PREFETCH,
            pt_iomem_map);

        PT_LOG("Expansion ROM registered (size=0x%08x base_addr=0x%08x)\n",
            (uint32_t)(pci_dev->rom_size), (uint32_t)(pci_dev->rom_base_addr));
    }

    return 0;
}

struct pt_dev * register_real_device(PCIBus *e_bus,
        const char *e_dev_name, int e_devfn, uint8_t r_bus, uint8_t r_dev,
        uint8_t r_func, uint32_t machine_irq, struct pci_access *pci_access)
{
    int rc, i;
    struct pt_dev *assigned_device = NULL;
    struct pci_dev *pci_dev;
    uint8_t e_device, e_intx;
    struct pci_config_cf8 machine_bdf;

    PT_LOG("Assigning real physical device %02x:%02x.%x ...\n",
        r_bus, r_dev, r_func);

    /* Find real device structure */
    for (pci_dev = pci_access->devices; pci_dev != NULL;
         pci_dev = pci_dev->next)
    {
        if ((r_bus == pci_dev->bus) && (r_dev == pci_dev->dev)
            && (r_func == pci_dev->func))
            break;
    }
    if ( pci_dev == NULL )
    {
        PT_LOG("Error: couldn't locate device in libpci structures\n");
        return NULL;
    }

    /* Register device */
    assigned_device = (struct pt_dev *) pci_register_device(e_bus, e_dev_name,
                                sizeof(struct pt_dev), e_devfn,
                                pt_pci_read_config, pt_pci_write_config);
    if ( assigned_device == NULL )
    {
        PT_LOG("Error: couldn't register real device\n");
        return NULL;
    }

    assigned_device->pci_dev = pci_dev;

    /* Assign device */
    machine_bdf.reg = 0;
    machine_bdf.bus = r_bus;
    machine_bdf.dev = r_dev;
    machine_bdf.func = r_func;
    rc = xc_assign_device(xc_handle, domid, machine_bdf.value);
    if ( rc < 0 )
        PT_LOG("Error: xc_assign_device error %d\n", rc);

    /* Initialize virtualized PCI configuration (Extended 256 Bytes) */
    for ( i = 0; i < PCI_CONFIG_SIZE; i++ )
        assigned_device->dev.config[i] = pci_read_byte(pci_dev, i);

    /* Handle real device's MMIO/PIO BARs */
    pt_register_regions(assigned_device);

    /* Bind interrupt */
    e_device = (assigned_device->dev.devfn >> 3) & 0x1f;
    e_intx = assigned_device->dev.config[0x3d]-1;

    if ( PT_MACHINE_IRQ_AUTO == machine_irq )
        machine_irq = pci_dev->irq;

    /* bind machine_irq to device */
    if ( 0 != machine_irq )
    {
        rc = xc_domain_bind_pt_pci_irq(xc_handle, domid, machine_irq, 0,
                                       e_device, e_intx);
        if ( rc < 0 )
        {
            /* TBD: unregister device in case of an error */
            PT_LOG("Error: Binding of interrupt failed! rc=%d\n", rc);
        }
    }
    else {
        /* Disable PCI intx assertion (turn on bit10 of devctl) */
        assigned_device->dev.config[0x05] |= 0x04;
        pci_write_word(pci_dev, 0x04,
            *(uint16_t *)(&assigned_device->dev.config[0x04]));
    }

    PT_LOG("Real physical device %02x:%02x.%x registered successfuly!\n", 
        r_bus, r_dev, r_func);

    return assigned_device;
}

int pt_init(PCIBus *e_bus, char *direct_pci)
{
    int seg, b, d, f;
    struct pt_dev *pt_dev;
    struct pci_access *pci_access;

    /* Initialize libpci */
    pci_access = pci_alloc();
    if ( pci_access == NULL )
    {
        PT_LOG("pci_access is NULL\n");
        return -1;
    }
    pci_init(pci_access);
    pci_scan_bus(pci_access);

    /* Assign given devices to guest */
    while ( next_bdf(&direct_pci, &seg, &b, &d, &f) )
    {
        /* Register real device with the emulated bus */
        pt_dev = register_real_device(e_bus, "DIRECT PCI", PT_VIRT_DEVFN_AUTO,
            b, d, f, PT_MACHINE_IRQ_AUTO, pci_access);
        if ( pt_dev == NULL )
        {
            PT_LOG("Error: Registration failed (%02x:%02x.%x)\n", b, d, f);
            return -1;
        }
    }

    /* Success */
    return 0;
}
