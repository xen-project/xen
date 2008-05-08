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
    int vector = -1, pirq = -1;

    if ( !(dev->msi->flags & MSI_FLAG_UNINIT) )
    {
        PT_LOG("setup physical after initialized?? \n");
        return -1;
    }

    if ( xc_physdev_map_pirq_msi(xc_handle, domid, MAP_PIRQ_TYPE_MSI,
                            vector, &pirq,
							dev->pci_dev->dev << 3 | dev->pci_dev->func,
							dev->pci_dev->bus, 1) )
    {
        PT_LOG("error map vector %x\n", vector);
        return -1;
    }
    dev->msi->pirq = pirq;
    PT_LOG("vector %x pirq %x\n", vector, pirq);

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

static uint32_t get_msi_gflags(struct pt_dev *d)
{
    uint32_t result = 0;
    int rh, dm, dest_id, deliv_mode, trig_mode;
    uint16_t data;
    uint64_t addr;

    data = get_msi_gdata(d);
    addr = get_msi_gaddr(d);

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
 * This may be arch different
 */
static inline uint8_t get_msi_gvec(struct pt_dev *d)
{
    return get_msi_gdata(d) & 0xff;
}

static inline uint8_t get_msi_hvec(struct pt_dev *d)
{
    struct pci_dev *pd = d->pci_dev;
    uint16_t data;

    if ( d->msi->flags & PCI_MSI_FLAGS_64BIT )
        data = pci_read_word(pd, PCI_MSI_DATA_64);
    else
        data = pci_read_word(pd, PCI_MSI_DATA_32);

    return data & 0xff;
}

/*
 * Update msi mapping, usually called when MSI enabled,
 * except the first time
 */
static int pt_msi_update(struct pt_dev *d)
{
    PT_LOG("now update msi with pirq %x gvec %x\n",
            get_msi_gvec(d), d->msi->pirq);
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
    uint16_t pctrl;
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

