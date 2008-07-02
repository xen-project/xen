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
#include "pt-msi.h"

extern FILE *logfile;

struct php_dev {
    struct pt_dev *pt_dev;
    uint8_t valid;
    uint8_t r_bus;
    uint8_t r_dev;
    uint8_t r_func;
};
struct dpci_infos {

    struct php_dev php_devs[PHP_SLOT_LEN];

    PCIBus *e_bus;
    struct pci_access *pci_access;

} dpci_infos;

static int token_value(char *token)
{
    return strtol(token, NULL, 16);
}

static int next_bdf(char **str, int *seg, int *bus, int *dev, int *func)
{
    char *token, *delim = ":.-";

    if ( !(*str) ||
          ( !strchr(*str, ':') && !strchr(*str, '.')) )
        return 0;

    token  = strsep(str, delim);
    *seg = token_value(token);

    token  = strsep(str, delim);
    *bus  = token_value(token);

    token  = strsep(str, delim);
    *dev  = token_value(token);

    token  = strsep(str, delim);
    *func  = token_value(token);

    return 1;
}

/* Insert a new pass-through device into a specific pci slot.
 * input  dom:bus:dev.func@slot, chose free one if slot == 0
 * return -1: required slot not available
 *         0: no free hotplug slots, but normal slot should okay
 *        >0: the new hotplug slot
 */
static int __insert_to_pci_slot(int bus, int dev, int func, int slot)
{
    int i, php_slot;

    /* preferred virt pci slot */
    if ( slot >= PHP_SLOT_START && slot < PHP_SLOT_END )
    {
        php_slot = PCI_TO_PHP_SLOT(slot);
        if ( !dpci_infos.php_devs[php_slot].valid )
        {
            goto found;
        }
        else
            return -1;
    }

    if ( slot != 0 )
        return -1;

    /* slot == 0, pick up a free one */
    for ( i = 0; i < PHP_SLOT_LEN; i++ )
    {
        if ( !dpci_infos.php_devs[i].valid )
        {
            php_slot = i;
            goto found;
        }
    }

    /* not found */
    return 0;

found:
    dpci_infos.php_devs[php_slot].valid  = 1;
    dpci_infos.php_devs[php_slot].r_bus  = bus;
    dpci_infos.php_devs[php_slot].r_dev  = dev;
    dpci_infos.php_devs[php_slot].r_func = func;
    return PHP_TO_PCI_SLOT(php_slot);
}

/* Insert a new pass-through device into a specific pci slot.
 * input  dom:bus:dev.func@slot
 */
int insert_to_pci_slot(char *bdf_slt)
{
    int seg, bus, dev, func, slot;
    char *bdf_str, *slt_str, *delim="@";

    bdf_str = strsep(&bdf_slt, delim);
    slt_str = bdf_slt;
    slot = token_value(slt_str);

    if ( !next_bdf(&bdf_str, &seg, &bus, &dev, &func))
    {
        return -1;
    }

    return __insert_to_pci_slot(bus, dev, func, slot);

}

/* Test if a pci slot has a device
 * 1:  present
 * 0:  not present
 * -1: invalide pci slot input
 */
int test_pci_slot(int slot)
{
    int php_slot;

    if ( slot < PHP_SLOT_START || slot >= PHP_SLOT_END )
        return -1;

    php_slot = PCI_TO_PHP_SLOT(slot);
    if ( dpci_infos.php_devs[php_slot].valid )
        return 1;
    else
        return 0;
}

/* find the pci slot for pass-through dev with specified BDF */
int bdf_to_slot(char *bdf_str)
{
    int seg, bus, dev, func, i;

    if ( !next_bdf(&bdf_str, &seg, &bus, &dev, &func))
    {
        return -1;
    }

    /* locate the virtual pci slot for this VTd device */
    for ( i = 0; i < PHP_SLOT_LEN; i++ )
    {
        if ( dpci_infos.php_devs[i].valid &&
           dpci_infos.php_devs[i].r_bus == bus &&
           dpci_infos.php_devs[i].r_dev  == dev &&
           dpci_infos.php_devs[i].r_func == func )
        {
            return PHP_TO_PCI_SLOT(i);
        }
    }

    return -1;
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
        add_msix_mapping(assigned_device, i);
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

    ret = remove_msix_mapping(assigned_device, i);
    if ( ret != 0 )
        PT_LOG("Error: remove MSX-X mmio mapping failed!\n");
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

    if ( pt_msi_write(assigned_device, address, val, len) )
        return;

    if ( pt_msix_write(assigned_device, address, val, len) )
        return;

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

    pt_msi_read(assigned_device, address, len, &val);
    pt_msix_read(assigned_device, address, len, &val);
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

static int pt_unregister_regions(struct pt_dev *assigned_device)
{
    int i, type, ret;
    uint32_t e_size;
    PCIDevice *d = (PCIDevice*)assigned_device;

    for ( i = 0; i < PCI_NUM_REGIONS; i++ )
    {
        e_size = assigned_device->bases[i].e_size;
        if ( e_size == 0 )
            continue;

        type = d->io_regions[i].type;

        if ( type == PCI_ADDRESS_SPACE_MEM ||
             type == PCI_ADDRESS_SPACE_MEM_PREFETCH )
        {
            ret = xc_domain_memory_mapping(xc_handle, domid,
                    assigned_device->bases[i].e_physbase >> XC_PAGE_SHIFT,
                    assigned_device->bases[i].access.maddr >> XC_PAGE_SHIFT,
                    (e_size+XC_PAGE_SIZE-1) >> XC_PAGE_SHIFT,
                    DPCI_REMOVE_MAPPING);
            if ( ret != 0 )
            {
                PT_LOG("Error: remove old mem mapping failed!\n");
                continue;
            }

        }
        else if ( type == PCI_ADDRESS_SPACE_IO )
        {
            ret = xc_domain_ioport_mapping(xc_handle, domid,
                        assigned_device->bases[i].e_physbase,
                        assigned_device->bases[i].access.pio_base,
                        e_size,
                        DPCI_REMOVE_MAPPING);
            if ( ret != 0 )
            {
                PT_LOG("Error: remove old io mapping failed!\n");
                continue;
            }

        }
        
    }

}

uint8_t find_cap_offset(struct pci_dev *pci_dev, uint8_t cap)
{
    int id;
    int max_cap = 48;
    int pos = PCI_CAPABILITY_LIST;
    int status;

    status = pci_read_byte(pci_dev, PCI_STATUS);
    if ( (status & PCI_STATUS_CAP_LIST) == 0 )
        return 0;

    while ( max_cap-- )
    {
        pos = pci_read_byte(pci_dev, pos);
        if ( pos < 0x40 )
            break;

        pos &= ~3;
        id = pci_read_byte(pci_dev, pos + PCI_CAP_LIST_ID);

        if ( id == 0xff )
            break;
        if ( id == cap )
            return pos;

        pos += PCI_CAP_LIST_NEXT;
    }
    return 0;
}

struct pt_dev * register_real_device(PCIBus *e_bus,
        const char *e_dev_name, int e_devfn, uint8_t r_bus, uint8_t r_dev,
        uint8_t r_func, uint32_t machine_irq, struct pci_access *pci_access)
{
    int rc = -1, i, pos;
    struct pt_dev *assigned_device = NULL;
    struct pci_dev *pci_dev;
    uint8_t e_device, e_intx;
    struct pci_config_cf8 machine_bdf;
    int free_pci_slot = -1;

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
    pci_fill_info(pci_dev, PCI_FILL_IRQ | PCI_FILL_BASES | PCI_FILL_ROM_BASE | PCI_FILL_SIZES);

    if ( e_devfn == PT_VIRT_DEVFN_AUTO ) {
        /*indicate a static assignment(not hotplug), so find a free PCI hot plug slot */
        free_pci_slot = __insert_to_pci_slot(r_bus, r_dev, r_func, 0);
        if ( free_pci_slot > 0 )
            e_devfn = free_pci_slot  << 3;
        else
            PT_LOG("Error: no free virtual PCI hot plug slot, thus no live migration.\n");
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

    if ( free_pci_slot > 0 )
        dpci_infos.php_devs[PCI_TO_PHP_SLOT(free_pci_slot)].pt_dev = assigned_device;

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

    if ( (pos = find_cap_offset(pci_dev, PCI_CAP_ID_MSI)) )
        pt_msi_init(assigned_device, pos);

    if ( (pos = find_cap_offset(pci_dev, PCI_CAP_ID_MSIX)) )
        pt_msix_init(assigned_device, pos);

    /* Handle real device's MMIO/PIO BARs */
    pt_register_regions(assigned_device);

    /* Bind interrupt */
    e_device = (assigned_device->dev.devfn >> 3) & 0x1f;
    e_intx = assigned_device->dev.config[0x3d]-1;

    if ( PT_MACHINE_IRQ_AUTO == machine_irq )
    {
        int pirq = pci_dev->irq;

        machine_irq = pci_dev->irq;
        rc = xc_physdev_map_pirq(xc_handle, domid, MAP_PIRQ_TYPE_GSI,
                                machine_irq, &pirq);

        if ( rc )
        {
            /* TBD: unregister device in case of an error */
            PT_LOG("Error: Mapping irq failed, rc = %d\n", rc);
        }
        else
            machine_irq = pirq;
    }

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

int unregister_real_device(int php_slot)
{
    struct php_dev *php_dev;
    struct pci_dev *pci_dev;
    uint8_t e_device, e_intx;
    struct pt_dev *assigned_device = NULL;
    uint32_t machine_irq;
    uint32_t bdf = 0;
    int rc = -1;

    if ( php_slot < 0 || php_slot >= PHP_SLOT_LEN )
       return -1;

    php_dev = &dpci_infos.php_devs[php_slot];
    assigned_device = php_dev->pt_dev;

    if ( !assigned_device || !php_dev->valid )
        return -1;

    pci_dev = assigned_device->pci_dev;

    /* hide pci dev from qemu */
    pci_hide_device((PCIDevice*)assigned_device);

    /* Unbind interrupt */
    e_device = (assigned_device->dev.devfn >> 3) & 0x1f;
    e_intx = assigned_device->dev.config[0x3d]-1;
    machine_irq = pci_dev->irq;

    if ( machine_irq != 0 ) {
        rc = xc_domain_unbind_pt_irq(xc_handle, domid, machine_irq, PT_IRQ_TYPE_PCI, 0,
                                       e_device, e_intx, 0);
        if ( rc < 0 )
        {
            /* TBD: unregister device in case of an error */
            PT_LOG("Error: Unbinding of interrupt failed! rc=%d\n", rc);
        }
    }

    /* unregister real device's MMIO/PIO BARs */
    pt_unregister_regions(assigned_device);
    
    /* deassign the dev to dom0 */
    bdf |= (pci_dev->bus  & 0xff) << 16;
    bdf |= (pci_dev->dev  & 0x1f) << 11;
    bdf |= (pci_dev->func & 0x1f) << 8;
    if ( (rc = xc_deassign_device(xc_handle, domid, bdf)) != 0)
        PT_LOG("Error: Revoking the device failed! rc=%d\n", rc);

    /* mark this slot as free */
    php_dev->valid = 0;
    php_dev->pt_dev = NULL;
    qemu_free(assigned_device);

    return 0;
}

int power_on_php_slot(int php_slot)
{
    struct php_dev *php_dev = &dpci_infos.php_devs[php_slot];
    int pci_slot = php_slot + PHP_SLOT_START;
    struct pt_dev *pt_dev;
    pt_dev = 
        register_real_device(dpci_infos.e_bus,
            "DIRECT PCI",
            pci_slot << 3,
            php_dev->r_bus,
            php_dev->r_dev,
            php_dev->r_func,
            PT_MACHINE_IRQ_AUTO,
            dpci_infos.pci_access);

    php_dev->pt_dev = pt_dev;

    return 0;

}

int power_off_php_slot(int php_slot)
{
    return unregister_real_device(php_slot);
}

int pt_init(PCIBus *e_bus, char *direct_pci)
{
    int seg, b, d, f, php_slot = 0;
    struct pt_dev *pt_dev;
    struct pci_access *pci_access;
    char *vslots;
    char slot_str[8];

    /* Initialize libpci */
    pci_access = pci_alloc();
    if ( pci_access == NULL )
    {
        PT_LOG("pci_access is NULL\n");
        return -1;
    }
    pci_init(pci_access);
    pci_scan_bus(pci_access);

    memset(&dpci_infos, 0, sizeof(struct dpci_infos));
    dpci_infos.pci_access = pci_access;
    dpci_infos.e_bus      = e_bus;

    if ( strlen(direct_pci) == 0 ) {
        return 0;
    }

    /* the virtual pci slots of all pass-through devs
     * with hex format: xx;xx...;
     */
    vslots = qemu_mallocz ( strlen(direct_pci) / 3 );

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

        /* Record the virtual slot info */
        if ( php_slot < PHP_SLOT_LEN &&
              dpci_infos.php_devs[php_slot].pt_dev == pt_dev )
        {
            sprintf(slot_str, "0x%x;", PHP_TO_PCI_SLOT(php_slot));
        }
        else
            sprintf(slot_str, "0x%x;", 0);

        strcat(vslots, slot_str);
        php_slot++;
    }

    /* Write virtual slots info to xenstore for Control panel use */
    xenstore_write_vslots(vslots);

    qemu_free(vslots);

    /* Success */
    return 0;
}
