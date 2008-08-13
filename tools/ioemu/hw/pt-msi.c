/*
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
 * Jiang Yunhong <yunhong.jiang@intel.com>
 *
 * This file implements direct PCI assignment to a HVM guest
 */

#include "pt-msi.h"
#include <sys/mman.h>

/* MSI virtuailization functions */

/*
 * setup physical msi, but didn't enable it
 */
int pt_msi_setup(struct pt_dev *dev)
{
    int pirq = -1;

    if ( !(dev->msi->flags & MSI_FLAG_UNINIT) )
    {
        PT_LOG("setup physical after initialized?? \n");
        return -1;
    }

    if ( xc_physdev_map_pirq_msi(xc_handle, domid, AUTO_ASSIGN, &pirq,
                                 dev->pci_dev->dev << 3 | dev->pci_dev->func,
                                 dev->pci_dev->bus, 0, 0) )
    {
        PT_LOG("error map msi\n");
        return -1;
    }

    if ( pirq < 0 )
    {
        PT_LOG("invalid pirq number\n");
        return -1;
    }

    dev->msi->pirq = pirq;
    PT_LOG("msi mapped with pirq %x\n", pirq);

    return 0;
}

uint32_t __get_msi_gflags(uint32_t data, uint64_t addr)
{
    uint32_t result = 0;
    int rh, dm, dest_id, deliv_mode, trig_mode;

    rh = (addr >> MSI_ADDR_REDIRECTION_SHIFT) & 0x1;
    dm = (addr >> MSI_ADDR_DESTMODE_SHIFT) & 0x1;
    dest_id = (addr >> MSI_TARGET_CPU_SHIFT) & 0xff;
    deliv_mode = (data >> MSI_DATA_DELIVERY_SHIFT) & 0x7;
    trig_mode = (data >> MSI_DATA_TRIGGER_SHIFT) & 0x1;

    result |= dest_id | (rh << GFLAGS_SHIFT_RH) | (dm << GFLAGS_SHIFT_DM) | \
                (deliv_mode << GLFAGS_SHIFT_DELIV_MODE) |
                (trig_mode << GLFAGS_SHIFT_TRG_MODE);

    return result;
}

/*
 * Update msi mapping, usually called when MSI enabled,
 * except the first time
 */
int pt_msi_update(struct pt_dev *d)
{
    uint8_t gvec = 0;
    uint32_t gflags = 0;
    uint64_t addr = 0;
    
    /* get vector, address, flags info, etc. */
    gvec = d->msi->data & 0xFF;
    addr = (uint64_t)d->msi->addr_hi << 32 | d->msi->addr_lo;
    gflags = __get_msi_gflags(d->msi->data, addr);
    
    PT_LOG("now update msi with pirq %x gvec %x\n", d->msi->pirq, gvec);
    return xc_domain_update_msi_irq(xc_handle, domid, gvec,
                                     d->msi->pirq, gflags);
}

/* MSI-X virtulization functions */
static void mask_physical_msix_entry(struct pt_dev *dev, int entry_nr, int mask)
{
    void *phys_off;

    phys_off = dev->msix->phys_iomem_base + 16 * entry_nr + 12;
    *(uint32_t *)phys_off = mask;
}

static int pt_msix_update_one(struct pt_dev *dev, int entry_nr)
{
    struct msix_entry_info *entry = &dev->msix->msix_entry[entry_nr];
    int pirq = entry->pirq;
    int gvec = entry->io_mem[2] & 0xff;
    uint64_t gaddr = *(uint64_t *)&entry->io_mem[0];
    uint32_t gflags = __get_msi_gflags(entry->io_mem[2], gaddr);
    int ret;

    if ( !entry->flags )
        return 0;

    /* Check if this entry is already mapped */
    if ( entry->pirq == -1 )
    {
        ret = xc_physdev_map_pirq_msi(xc_handle, domid, AUTO_ASSIGN, &pirq,
                                dev->pci_dev->dev << 3 | dev->pci_dev->func,
                                dev->pci_dev->bus, entry_nr,
                                dev->msix->table_base);
        if ( ret )
        {
            PT_LOG("error map msix entry %x\n", entry_nr);
            return ret;
        }
        entry->pirq = pirq;
    }

    PT_LOG("now update msix entry %x with pirq %x gvec %x\n",
            entry_nr, pirq, gvec);

    ret = xc_domain_update_msi_irq(xc_handle, domid, gvec, pirq, gflags);
    if ( ret )
    {
        PT_LOG("error update msix irq info for entry %d\n", entry_nr);
        return ret;
    }

    entry->flags = 0;

    return 0;
}

int pt_msix_update(struct pt_dev *dev)
{
    struct pt_msix_info *msix = dev->msix;
    int i;

    for ( i = 0; i < msix->total_entries; i++ )
    {
        pt_msix_update_one(dev, i);
    }

    return 0;
}

static void pci_msix_invalid_write(void *opaque, target_phys_addr_t addr,
                                   uint32_t val)
{
    PT_LOG("invalid write to MSI-X table, \
            only dword access is allowed.\n");
}

static void pci_msix_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    struct pt_dev *dev = (struct pt_dev *)opaque;
    struct pt_msix_info *msix = dev->msix;
    struct msix_entry_info *entry;
    int entry_nr, offset;

    if ( addr % 4 )
    {
        PT_LOG("unaligned dword access to MSI-X table, addr %016lx\n",
                addr);
        return;
    }

    entry_nr = (addr - msix->mmio_base_addr) / 16;
    entry = &msix->msix_entry[entry_nr];
    offset = ((addr - msix->mmio_base_addr) % 16) / 4;

    if ( offset != 3 && msix->enabled && !(entry->io_mem[3] & 0x1) )
    {
        PT_LOG("can not update msix entry %d since MSI-X is already \
                function now.\n", entry_nr);
        return;
    }

    if ( offset != 3 && entry->io_mem[offset] != val )
        entry->flags = 1;
    entry->io_mem[offset] = val;

    if ( offset == 3 )
    {
        if ( msix->enabled && !(val & 0x1) )
            pt_msix_update_one(dev, entry_nr);
        mask_physical_msix_entry(dev, entry_nr, entry->io_mem[3] & 0x1);
    }
}

static CPUWriteMemoryFunc *pci_msix_write[] = {
    pci_msix_invalid_write,
    pci_msix_invalid_write,
    pci_msix_writel
};

static uint32_t pci_msix_invalid_read(void *opaque, target_phys_addr_t addr)
{
    PT_LOG("invalid read to MSI-X table, \
            only dword access is allowed.\n");
    return 0;
}

static uint32_t pci_msix_readl(void *opaque, target_phys_addr_t addr)
{
    struct pt_dev *dev = (struct pt_dev *)opaque;
    struct pt_msix_info *msix = dev->msix;
    int entry_nr, offset;

    if ( addr % 4 )
    {
        PT_LOG("unaligned dword access to MSI-X table, addr %016lx\n",
                addr);
        return 0;
    }

    entry_nr = (addr - msix->mmio_base_addr) / 16;
    offset = ((addr - msix->mmio_base_addr) % 16) / 4;

    return msix->msix_entry[entry_nr].io_mem[offset];
}

static CPUReadMemoryFunc *pci_msix_read[] = {
    pci_msix_invalid_read,
    pci_msix_invalid_read,
    pci_msix_readl
};

int add_msix_mapping(struct pt_dev *dev, int bar_index)
{
    if ( !(dev->msix && dev->msix->bar_index == bar_index) )
        return 0;

    return xc_domain_memory_mapping(xc_handle, domid,
                dev->msix->mmio_base_addr >> XC_PAGE_SHIFT,
                (dev->bases[bar_index].access.maddr
                + dev->msix->table_off) >> XC_PAGE_SHIFT,
                (dev->msix->total_entries * 16
                + XC_PAGE_SIZE -1) >> XC_PAGE_SHIFT,
                DPCI_ADD_MAPPING);
}

int remove_msix_mapping(struct pt_dev *dev, int bar_index)
{
    if ( !(dev->msix && dev->msix->bar_index == bar_index) )
        return 0;

    dev->msix->mmio_base_addr = dev->bases[bar_index].e_physbase
                                + dev->msix->table_off;

    cpu_register_physical_memory(dev->msix->mmio_base_addr,
                                 dev->msix->total_entries * 16,
                                 dev->msix->mmio_index);

    return xc_domain_memory_mapping(xc_handle, domid,
                dev->msix->mmio_base_addr >> XC_PAGE_SHIFT,
                (dev->bases[bar_index].access.maddr
                + dev->msix->table_off) >> XC_PAGE_SHIFT,
                (dev->msix->total_entries * 16
                + XC_PAGE_SIZE -1) >> XC_PAGE_SHIFT,
                DPCI_REMOVE_MAPPING);
}

int pt_msix_init(struct pt_dev *dev, int pos)
{
    uint8_t id;
    uint16_t control;
    int i, total_entries, table_off, bar_index;
    struct pci_dev *pd = dev->pci_dev;

    id = pci_read_byte(pd, pos + PCI_CAP_LIST_ID);

    if ( id != PCI_CAP_ID_MSIX )
    {
        PT_LOG("error id %x pos %x\n", id, pos);
        return -1;
    }

    control = pci_read_word(pd, pos + 2);
    total_entries = control & 0x7ff;
    total_entries += 1;

    dev->msix = malloc(sizeof(struct pt_msix_info)
                       + total_entries*sizeof(struct msix_entry_info));
    if ( !dev->msix )
    {
        PT_LOG("error allocation pt_msix_info\n");
        return -1;
    }
    memset(dev->msix, 0, sizeof(struct pt_msix_info)
                         + total_entries*sizeof(struct msix_entry_info));
    dev->msix->total_entries = total_entries;
    for ( i = 0; i < total_entries; i++ )
        dev->msix->msix_entry[i].pirq = -1;

    dev->msix->mmio_index =
        cpu_register_io_memory(0, pci_msix_read, pci_msix_write, dev);

    table_off = pci_read_long(pd, pos + PCI_MSIX_TABLE);
    bar_index = dev->msix->bar_index = table_off & PCI_MSIX_BIR;
    table_off &= table_off & ~PCI_MSIX_BIR;
    dev->msix->table_base = dev->pci_dev->base_addr[bar_index];
    PT_LOG("get MSI-X table bar base %llx\n",
           (unsigned long long)dev->msix->table_base);

    dev->msix->fd = open("/dev/mem", O_RDWR);
    dev->msix->phys_iomem_base = mmap(0, total_entries * 16,
                          PROT_WRITE | PROT_READ, MAP_SHARED | MAP_LOCKED,
                          dev->msix->fd, dev->msix->table_base + table_off);
    PT_LOG("mapping physical MSI-X table to %lx\n",
           (unsigned long)dev->msix->phys_iomem_base);
    return 0;
}

void pt_msix_delete(struct pt_dev *dev)
{
    /* unmap the MSI-X memory mapped register area */
    if (dev->msix->phys_iomem_base)
    {
        PT_LOG("unmapping physical MSI-X table from %lx\n",
           (unsigned long)dev->msix->phys_iomem_base);
        munmap(dev->msix->phys_iomem_base, dev->msix->total_entries * 16);
    }

    free(dev->msix);
}
