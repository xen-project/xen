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
#define PT_MSI_CTRL_WR_MASK_HI      (0x1)
#define PT_MSI_CTRL_WR_MASK_LO      (0x8E)
#define PT_MSI_DATA_WR_MASK         (0x38)
int pt_msi_init(struct pt_dev *dev, int pos)
{
    uint8_t id;
    uint16_t flags;
    struct pci_dev *pd = dev->pci_dev;
    PCIDevice *d = (struct PCIDevice *)dev;

    id = pci_read_byte(pd, pos + PCI_CAP_LIST_ID);

    if ( id != PCI_CAP_ID_MSI )
    {
        PT_LOG("pt_msi_init: error id %x pos %x\n", id, pos);
        return -1;
    }

    dev->msi = malloc(sizeof(struct pt_msi_info));
    if ( !dev->msi )
    {
        PT_LOG("pt_msi_init: error allocation pt_msi_info\n");
        return -1;
    }
    memset(dev->msi, 0, sizeof(struct pt_msi_info));

    dev->msi->offset = pos;
    dev->msi->size = 0xa;

    flags = pci_read_byte(pd, pos + PCI_MSI_FLAGS);
    if ( flags & PCI_MSI_FLAGS_ENABLE )
    {
        PT_LOG("pt_msi_init: MSI enabled already, disable first\n");
        pci_write_byte(pd, pos + PCI_MSI_FLAGS, flags & ~PCI_MSI_FLAGS_ENABLE);
    }
    dev->msi->flags |= (flags | MSI_FLAG_UNINIT);

    if ( flags & PCI_MSI_FLAGS_64BIT )
        dev->msi->size += 4;
    if ( flags & PCI_MSI_FLAGS_PVMASK )
        dev->msi->size += 10;

    /* All register is 0 after reset, except first 4 byte */
    *(uint32_t *)(&d->config[pos]) = pci_read_long(pd, pos);
    d->config[pos + 2] &=  PT_MSI_CTRL_WR_MASK_LO;
    d->config[pos + 3] &=  PT_MSI_CTRL_WR_MASK_HI;

    return 0;
}

/*
 * setup physical msi, but didn't enable it
 */
static int pt_msi_setup(struct pt_dev *dev)
{
    int pirq = -1;

    if ( !(dev->msi->flags & MSI_FLAG_UNINIT) )
    {
        PT_LOG("setup physical after initialized?? \n");
        return -1;
    }

    if ( xc_physdev_map_pirq_msi(xc_handle, domid, MAP_PIRQ_TYPE_MSI,
                            AUTO_ASSIGN, &pirq,
							dev->pci_dev->dev << 3 | dev->pci_dev->func,
							dev->pci_dev->bus, 0, 1) )
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

/*
 * caller should make sure mask is supported
 */
static uint32_t get_msi_gmask(struct pt_dev *d)
{
    struct PCIDevice *pd = (struct PCIDevice *)d;

    if ( d->msi->flags & PCI_MSI_FLAGS_64BIT )
        return *(uint32_t *)(pd->config + d->msi->offset + 0xc);
    else
        return *(uint32_t *)(pd->config + d->msi->offset + 0x10);

}

static uint16_t get_msi_gdata(struct pt_dev *d)
{
    struct PCIDevice *pd = (struct PCIDevice *)d;

    if ( d->msi->flags & PCI_MSI_FLAGS_64BIT )
        return *(uint16_t *)(pd->config + d->msi->offset + PCI_MSI_DATA_64);
    else
        return *(uint16_t *)(pd->config + d->msi->offset + PCI_MSI_DATA_32);
}

static uint64_t get_msi_gaddr(struct pt_dev *d)
{
    struct PCIDevice *pd = (struct PCIDevice *)d;
    uint32_t addr_hi;
    uint64_t addr = 0;

    addr =(uint64_t)(*(uint32_t *)(pd->config +
                     d->msi->offset + PCI_MSI_ADDRESS_LO));

    if ( d->msi->flags & PCI_MSI_FLAGS_64BIT )
    {
        addr_hi = *(uint32_t *)(pd->config + d->msi->offset
                                + PCI_MSI_ADDRESS_HI);
        addr |= (uint64_t)addr_hi << 32;
    }
    return addr;
}

static uint8_t get_msi_gctrl(struct pt_dev *d)
{
    struct PCIDevice *pd = (struct PCIDevice *)d;

    return  *(uint8_t *)(pd->config + d->msi->offset + PCI_MSI_FLAGS);
}

static uint32_t __get_msi_gflags(uint32_t data, uint64_t addr)
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

static uint32_t get_msi_gflags(struct pt_dev *d)
{
    uint16_t data = get_msi_gdata(d);
    uint64_t addr = get_msi_gaddr(d);

    return __get_msi_gflags(data, addr);
}

/*
 * This may be arch different
 */
static inline uint8_t get_msi_gvec(struct pt_dev *d)
{
    return get_msi_gdata(d) & 0xff;
}

/*
 * Update msi mapping, usually called when MSI enabled,
 * except the first time
 */
static int pt_msi_update(struct pt_dev *d)
{
    PT_LOG("now update msi with pirq %x gvec %x\n",
            d->msi->pirq, get_msi_gvec(d));
    return xc_domain_update_msi_irq(xc_handle, domid, get_msi_gvec(d),
                                     d->msi->pirq, get_msi_gflags(d));
}

static int pt_msi_enable(struct pt_dev *d, int enable)
{
    uint16_t ctrl;
    struct pci_dev *pd = d->pci_dev;

    if ( !pd )
        return -1;

    ctrl = pci_read_word(pd, d->msi->offset + PCI_MSI_FLAGS);

    if ( enable )
        ctrl |= PCI_MSI_FLAGS_ENABLE;
    else
        ctrl &= ~PCI_MSI_FLAGS_ENABLE;

    pci_write_word(pd, d->msi->offset + PCI_MSI_FLAGS, ctrl);
    return 0;
}

static int pt_msi_control_update(struct pt_dev *d, uint16_t old_ctrl)
{
    uint16_t new_ctrl;
    PCIDevice *pd = (PCIDevice *)d;

    new_ctrl = get_msi_gctrl(d);

    PT_LOG("old_ctrl %x new_Ctrl %x\n", old_ctrl, new_ctrl);

    if ( new_ctrl & PCI_MSI_FLAGS_ENABLE )
    {
        if ( d->msi->flags & MSI_FLAG_UNINIT )
        {
            /* Init physical one */
            PT_LOG("setup msi for dev %x\n", pd->devfn);
            if ( pt_msi_setup(d) )
            {
                PT_LOG("pt_msi_setup error!!!\n");
                return -1;
            }
            pt_msi_update(d);

            d->msi->flags &= ~MSI_FLAG_UNINIT;
            d->msi->flags |= PT_MSI_MAPPED;

            /* Enable physical MSI only after bind */
            pt_msi_enable(d, 1);
        }
        else if ( !(old_ctrl & PCI_MSI_FLAGS_ENABLE) )
            pt_msi_enable(d, 1);
    }
    else if ( old_ctrl & PCI_MSI_FLAGS_ENABLE )
        pt_msi_enable(d, 0);

    /* Currently no support for multi-vector */
    if ( (new_ctrl & PCI_MSI_FLAGS_QSIZE) != 0x0 )
        PT_LOG("try to set more than 1 vector ctrl %x\n", new_ctrl);

    return 0;
}

static int
pt_msi_map_update(struct pt_dev *d, uint32_t old_data, uint64_t old_addr)
{
    uint32_t data;
    uint64_t addr;

    data = get_msi_gdata(d);
    addr = get_msi_gaddr(d);

    PT_LOG("old_data %x old_addr %lx data %x addr %lx\n",
            old_data, old_addr, data, addr);

    if ( data != old_data || addr != old_addr )
        if ( get_msi_gctrl(d) & PCI_MSI_FLAGS_ENABLE )
            pt_msi_update(d);

    return 0;
}

static int pt_msi_mask_update(struct pt_dev *d, uint32_t old_mask)
{
    struct pci_dev *pd = d->pci_dev;
    uint32_t mask;
    int offset;

    if ( !(d->msi->flags & PCI_MSI_FLAGS_PVMASK) )
        return -1;

    mask = get_msi_gmask(d);

    if ( d->msi->flags & PCI_MSI_FLAGS_64BIT )
        offset = d->msi->offset + 0xc;
    else
        offset = d->msi->offset + 0x10;

    if ( old_mask != mask )
        pci_write_long(pd, offset, mask);

    return 0;
}

#define ACCESSED_DATA 0x2
#define ACCESSED_MASK 0x4
#define ACCESSED_ADDR 0x8
#define ACCESSED_CTRL 0x10

int pt_msi_write(struct pt_dev *d, uint32_t addr, uint32_t val, uint32_t len)
{
    struct pci_dev *pd;
    int i, cur = addr;
    uint8_t value, flags = 0;
    uint16_t old_ctrl = 0, old_data = 0;
    uint32_t old_mask = 0;
    uint64_t old_addr = 0;
    PCIDevice *dev = (PCIDevice *)d;
    int can_write = 1;

    if ( !d || !d->msi )
        return 0;

    if ( (addr >= (d->msi->offset + d->msi->size) ) ||
         (addr + len) < d->msi->offset)
        return 0;

    PT_LOG("addr %x val %x len %x offset %x size %x\n",
            addr, val, len, d->msi->offset, d->msi->size);

    pd = d->pci_dev;
    old_ctrl = get_msi_gctrl(d);
    old_addr = get_msi_gaddr(d);
    old_data = get_msi_gdata(d);

    if ( d->msi->flags & PCI_MSI_FLAGS_PVMASK )
        old_mask = get_msi_gmask(d);

    for ( i = 0; i < len; i++, cur++ )
    {
        int off;
        uint8_t orig_value;

        if ( cur < d->msi->offset )
            continue;
        else if ( cur >= (d->msi->offset + d->msi->size) )
            break;

        off = cur - d->msi->offset;
        value = (val >> (i * 8)) & 0xff;

        switch ( off )
        {
            case 0x0 ... 0x1:
                can_write = 0;
                break;
            case 0x2:
            case 0x3:
                flags |= ACCESSED_CTRL;

                orig_value = pci_read_byte(pd, d->msi->offset + off);

                orig_value &= (off == 2) ? PT_MSI_CTRL_WR_MASK_LO:
                                      PT_MSI_CTRL_WR_MASK_HI;

                orig_value |= value & ( (off == 2) ? ~PT_MSI_CTRL_WR_MASK_LO:
                                              ~PT_MSI_CTRL_WR_MASK_HI);
                value = orig_value;
                break;
            case 0x4 ... 0x7:
                flags |= ACCESSED_ADDR;
                /* bit 4 ~ 11 is reserved for MSI in x86 */
                if ( off == 0x4 )
                    value &= 0x0f;
                if ( off == 0x5 )
                    value &= 0xf0;
                break;
            case 0x8 ... 0xb:
                if ( d->msi->flags & PCI_MSI_FLAGS_64BIT )
                {
                    /* Up 32bit is reserved in x86 */
                    flags |= ACCESSED_ADDR;
                    if ( value )
                        PT_LOG("Write up32 addr with %x \n", value);
                }
                else
                {
                    if ( off == 0xa || off == 0xb )
                        can_write = 0;
                    else
                        flags |= ACCESSED_DATA;
                    if ( off == 0x9 )
                        value &= ~PT_MSI_DATA_WR_MASK;
                }
                break;
            case 0xc ... 0xf:
                if ( d->msi->flags & PCI_MSI_FLAGS_64BIT )
                {
                    if ( off == 0xe || off == 0xf )
                        can_write = 0;
                    else
                    {
                        flags |= ACCESSED_DATA;
                        if (off == 0xd)
                            value &= ~PT_MSI_DATA_WR_MASK;
                    }
                }
                else
                {
                    if ( d->msi->flags & PCI_MSI_FLAGS_PVMASK )
                        flags |= ACCESSED_MASK;
                    else
                        PT_LOG("why comes to MASK without mask support??\n");
                }
                break;
            case 0x10 ... 0x13:
                if ( d->msi->flags & PCI_MSI_FLAGS_64BIT )
                {
                    if ( d->msi->flags & PCI_MSI_FLAGS_PVMASK )
                        flags |= ACCESSED_MASK;
                    else
                        PT_LOG("why comes to MASK without mask support??\n");
                }
                else
                    can_write = 0;
                break;
            case 0x14 ... 0x18:
                can_write = 0;
                break;
            default:
                PT_LOG("Non MSI register!!!\n");
                break;
        }

        if ( can_write )
            dev->config[cur] = value;
    }

    if ( flags & ACCESSED_DATA || flags & ACCESSED_ADDR )
        pt_msi_map_update(d, old_data, old_addr);

    if ( flags & ACCESSED_MASK )
        pt_msi_mask_update(d, old_mask);

    /* This will enable physical one, do it in last step */
    if ( flags & ACCESSED_CTRL )
        pt_msi_control_update(d, old_ctrl);

    return 1;
}

int pt_msi_read(struct pt_dev *d, int addr, int len, uint32_t *val)
{
    int e_addr = addr, e_len = len, offset = 0, i;
    uint8_t e_val = 0;
    PCIDevice *pd = (PCIDevice *)d;

    if ( !d || !d->msi )
        return 0;

    if ( (addr > (d->msi->offset + d->msi->size) ) ||
         (addr + len) <= d->msi->offset )
        return 0;

    PT_LOG("pt_msi_read addr %x len %x val %x offset %x size %x\n",
            addr, len, *val, d->msi->offset, d->msi->size);

    if ( (addr + len ) > (d->msi->offset + d->msi->size) )
        e_len -= addr + len - d->msi->offset - d->msi->size;

    if ( addr < d->msi->offset )
    {
        e_addr = d->msi->offset;
        offset = d->msi->offset - addr;
        e_len -= offset;
    }

    for ( i = 0; i < e_len; i++ )
    {
        e_val = *(uint8_t *)(&pd->config[e_addr] + i);
        *val &= ~(0xff << ( (offset + i) * 8));
        *val |= (e_val << ( (offset + i) * 8));
    }

    return e_len;
}

/* MSI-X virtulization functions */
#define PT_MSIX_CTRL_WR_MASK_HI      (0xC0)
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
        ret = xc_physdev_map_pirq_msi(xc_handle, domid, MAP_PIRQ_TYPE_MSI,
                                AUTO_ASSIGN, &pirq,
                                dev->pci_dev->dev << 3 | dev->pci_dev->func,
                                dev->pci_dev->bus, entry_nr, 0);
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

static int pt_msix_update(struct pt_dev *dev)
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

    if ( offset != 3 && msix->enabled && entry->io_mem[3] & 0x1 )
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
        if ( !(val & 0x1) )
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
    uint16_t flags, control;
    int i, total_entries, table_off, bar_index;
    uint64_t bar_base;
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
    dev->msix->offset = pos;
    for ( i = 0; i < total_entries; i++ )
        dev->msix->msix_entry[i].pirq = -1;

    dev->msix->mmio_index =
        cpu_register_io_memory(0, pci_msix_read, pci_msix_write, dev);

    flags = pci_read_word(pd, pos + PCI_MSI_FLAGS);
    if ( flags & PCI_MSIX_ENABLE )
    {
        PT_LOG("MSIX enabled already, disable first\n");
        pci_write_word(pd, pos + PCI_MSI_FLAGS, flags & ~PCI_MSIX_ENABLE);
        *(uint16_t *)&dev->dev.config[pos + PCI_MSI_FLAGS]
            = flags & ~(PCI_MSIX_ENABLE | PCI_MSIX_MASK);
    }

    table_off = pci_read_long(pd, pos + PCI_MSIX_TABLE);
    bar_index = dev->msix->bar_index = table_off & PCI_MSIX_BIR;
    table_off &= table_off & ~PCI_MSIX_BIR;
    bar_base = pci_read_long(pd, 0x10 + 4 * bar_index);
    if ( (bar_base & 0x6) == 0x4 )
    {
        bar_base &= ~0xf;
        bar_base += (uint64_t)pci_read_long(pd, 0x10 + 4 * (bar_index + 1)) << 32;
    }
    PT_LOG("get MSI-X table bar base %lx\n", bar_base);

    dev->msix->fd = open("/dev/mem", O_RDWR);
    dev->msix->phys_iomem_base = mmap(0, total_entries * 16,
                          PROT_WRITE | PROT_READ, MAP_SHARED | MAP_LOCKED,
                          dev->msix->fd, bar_base + table_off);
    PT_LOG("mapping physical MSI-X table to %lx\n",
           (unsigned long)dev->msix->phys_iomem_base);
    return 0;
}

static int pt_msix_enable(struct pt_dev *d, int enable)
{
    uint16_t ctrl;
    struct pci_dev *pd = d->pci_dev;

    if ( !pd )
        return -1;

    ctrl = pci_read_word(pd, d->msix->offset + PCI_MSI_FLAGS);
    if ( enable )
        ctrl |= PCI_MSIX_ENABLE;
    else
        ctrl &= ~PCI_MSIX_ENABLE;
    pci_write_word(pd, d->msix->offset + PCI_MSI_FLAGS, ctrl);
    d->msix->enabled = !!enable;

    return 0;
}

static int pt_msix_func_mask(struct pt_dev *d, int mask)
{
    uint16_t ctrl;
    struct pci_dev *pd = d->pci_dev;

    if ( !pd )
        return -1;

    ctrl = pci_read_word(pd, d->msix->offset + PCI_MSI_FLAGS);

    if ( mask )
        ctrl |= PCI_MSIX_MASK;
    else
        ctrl &= ~PCI_MSIX_MASK;

    pci_write_word(pd, d->msix->offset + PCI_MSI_FLAGS, ctrl);
    return 0;
}

static int pt_msix_control_update(struct pt_dev *d)
{
    PCIDevice *pd = (PCIDevice *)d;
    uint16_t ctrl = *(uint16_t *)(&pd->config[d->msix->offset + 2]);

    if ( ctrl & PCI_MSIX_ENABLE && !(ctrl & PCI_MSIX_MASK ) )
        pt_msix_update(d);

    pt_msix_func_mask(d, ctrl & PCI_MSIX_MASK);
    pt_msix_enable(d, ctrl & PCI_MSIX_ENABLE);

    return 0;
}

int pt_msix_write(struct pt_dev *d, uint32_t addr, uint32_t val, uint32_t len)
{
    struct pci_dev *pd;
    int i, cur = addr;
    uint8_t value;
    PCIDevice *dev = (PCIDevice *)d;

    if ( !d || !d->msix )
        return 0;

    if ( (addr >= (d->msix->offset + 4) ) ||
         (addr + len) < d->msix->offset)
        return 0;

    PT_LOG("addr %x val %x len %x offset %x\n",
            addr, val, len, d->msix->offset);

    pd = d->pci_dev;

    for ( i = 0; i < len; i++, cur++ )
    {
        uint8_t orig_value;

        if ( cur != d->msix->offset + 3 )
            continue;

        value = (val >> (i * 8)) & 0xff;

        orig_value = pci_read_byte(pd, cur);
        value = (orig_value & ~PT_MSIX_CTRL_WR_MASK_HI) |
                (value & PT_MSIX_CTRL_WR_MASK_HI);
        dev->config[cur] = value;
        pt_msix_control_update(d);
        return 1;
    }

    return 0;
}

int pt_msix_read(struct pt_dev *d, int addr, int len, uint32_t *val)
{
    int e_addr = addr, e_len = len, offset = 0, i;
    uint8_t e_val = 0;
    PCIDevice *pd = (PCIDevice *)d;

    if ( !d || !d->msix )
        return 0;

    if ( (addr > (d->msix->offset + 3) ) ||
         (addr + len) <= d->msix->offset )
        return 0;

    if ( (addr + len ) > (d->msix->offset + 3) )
        e_len -= addr + len - d->msix->offset - 3;

    if ( addr < d->msix->offset )
    {
        e_addr = d->msix->offset;
        offset = d->msix->offset - addr;
        e_len -= offset;
    }

    for ( i = 0; i < e_len; i++ )
    {
        e_val = *(uint8_t *)(&pd->config[e_addr] + i);
        *val &= ~(0xff << ( (offset + i) * 8));
        *val |= (e_val << ( (offset + i) * 8));
    }

    PT_LOG("addr %x len %x val %x offset %x\n",
            addr, len, *val, d->msix->offset);

    return e_len;
}

