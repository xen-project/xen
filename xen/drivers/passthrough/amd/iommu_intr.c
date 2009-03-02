/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Wei Wang <wei.wang2@amd.com>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <xen/sched.h>
#include <xen/hvm/iommu.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>

#define INTREMAP_TABLE_ORDER    1
static DEFINE_SPINLOCK(int_remap_table_lock);
void *int_remap_table = NULL;

static u8 *get_intremap_entry(u8 vector, u8 dm)
{
    u8 *table;
    int offset = 0;
    table = (u8*)int_remap_table;

    BUG_ON( !table );
    offset = (dm << INT_REMAP_INDEX_DM_SHIFT) & INT_REMAP_INDEX_DM_MASK;
    offset |= (vector << INT_REMAP_INDEX_VECTOR_SHIFT ) & 
        INT_REMAP_INDEX_VECTOR_MASK;

    return (u8*) (table + offset);
}

static void update_intremap_entry(u32* entry, u8 vector, u8 int_type,
    u8 dest_mode, u8 dest)
{
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, 0,
                            INT_REMAP_ENTRY_REMAPEN_MASK,
                            INT_REMAP_ENTRY_REMAPEN_SHIFT, entry);
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, *entry,
                            INT_REMAP_ENTRY_SUPIOPF_MASK,
                            INT_REMAP_ENTRY_SUPIOPF_SHIFT, entry);
    set_field_in_reg_u32(int_type, *entry,
                            INT_REMAP_ENTRY_INTTYPE_MASK,
                            INT_REMAP_ENTRY_INTTYPE_SHIFT, entry);
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, *entry,
                            INT_REMAP_ENTRY_REQEOI_MASK,
                            INT_REMAP_ENTRY_REQEOI_SHIFT, entry);
    set_field_in_reg_u32((u32)dest_mode, *entry,
                            INT_REMAP_ENTRY_DM_MASK,
                            INT_REMAP_ENTRY_DM_SHIFT, entry);
    set_field_in_reg_u32((u32)dest, *entry,
                            INT_REMAP_ENTRY_DEST_MAST,
                            INT_REMAP_ENTRY_DEST_SHIFT, entry);
    set_field_in_reg_u32((u32)vector, *entry,
                            INT_REMAP_ENTRY_VECTOR_MASK,
                            INT_REMAP_ENTRY_VECTOR_SHIFT, entry);
}

void invalidate_interrupt_table(struct amd_iommu *iommu, u16 device_id)
{
    u32 cmd[4], entry;

    cmd[3] = cmd[2] = 0;
    set_field_in_reg_u32(device_id, 0,
                         IOMMU_INV_INT_TABLE_DEVICE_ID_MASK,
                         IOMMU_INV_INT_TABLE_DEVICE_ID_SHIFT, &entry);
    cmd[0] = entry;
    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_INT_TABLE, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;
    send_iommu_command(iommu, cmd);
}

static void update_intremap_entry_from_ioapic(
    struct IO_APIC_route_entry *ioapic_rte,
    unsigned int rte_upper, unsigned int value)
{
    unsigned long flags;
    u32* entry;
    u8 delivery_mode, dest, vector, dest_mode;
    struct IO_APIC_route_entry *rte = ioapic_rte;

    spin_lock_irqsave(&int_remap_table_lock, flags);

    if ( rte_upper )
    {
        dest = (value >> 24) & 0xFF;
        delivery_mode = rte->delivery_mode;
        vector = rte->vector;
        dest_mode = rte->dest_mode;
        entry = (u32*)get_intremap_entry((u8)rte->vector,
                                        (u8)rte->delivery_mode);
        update_intremap_entry(entry, vector, delivery_mode, dest_mode, dest);
    }

    spin_unlock_irqrestore(&int_remap_table_lock, flags);
    return;
}

int __init amd_iommu_setup_intremap_table(void)
{
    if ( int_remap_table == NULL )
    {
        int_remap_table = __alloc_amd_iommu_tables(INTREMAP_TABLE_ORDER);
        if ( int_remap_table == NULL )
            return -ENOMEM;
        memset(int_remap_table, 0, PAGE_SIZE * (1UL << INTREMAP_TABLE_ORDER));
    }

    return 0;
}

void amd_iommu_ioapic_update_ire(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    struct IO_APIC_route_entry ioapic_rte = { 0 };
    unsigned int rte_upper = (reg & 1) ? 1 : 0;
    int saved_mask;

    *IO_APIC_BASE(apic) = reg;
    *(IO_APIC_BASE(apic)+4) = value;

    if ( int_remap_table == NULL )
        return;
    if ( !rte_upper )
        return;

    reg--;
    /* read both lower and upper 32-bits of rte entry */
    *IO_APIC_BASE(apic) = reg;
    *(((u32 *)&ioapic_rte) + 0) = *(IO_APIC_BASE(apic)+4);
    *IO_APIC_BASE(apic) = reg + 1;
    *(((u32 *)&ioapic_rte) + 1) = *(IO_APIC_BASE(apic)+4);

    /* mask the interrupt while we change the intremap table */
    saved_mask = ioapic_rte.mask;
    ioapic_rte.mask = 1;
    *IO_APIC_BASE(apic) = reg;
    *(IO_APIC_BASE(apic)+4) = *(((int *)&ioapic_rte)+0);
    ioapic_rte.mask = saved_mask;

    update_intremap_entry_from_ioapic(&ioapic_rte, rte_upper, value);

    /* unmask the interrupt after we have updated the intremap table */
    *IO_APIC_BASE(apic) = reg;
    *(IO_APIC_BASE(apic)+4) = *(((u32 *)&ioapic_rte)+0);
}

static void update_intremap_entry_from_msi_msg(
    struct amd_iommu *iommu, struct pci_dev *pdev, struct msi_msg *msg)
{
    unsigned long flags;
    u32* entry;
    u16 dev_id;

    u8 delivery_mode, dest, vector, dest_mode;

    dev_id = (pdev->bus << 8) | pdev->devfn;

    spin_lock_irqsave(&int_remap_table_lock, flags);
    dest_mode = (msg->address_lo >> MSI_ADDR_DESTMODE_SHIFT) & 0x1;
    delivery_mode = (msg->data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x1;
    vector = (msg->data >> MSI_DATA_VECTOR_SHIFT) & MSI_DATA_VECTOR_MASK;
    dest = (msg->address_lo >> MSI_ADDR_DEST_ID_SHIFT) & 0xff;

    entry = (u32*)get_intremap_entry((u8)vector, (u8)delivery_mode);
    update_intremap_entry(entry, vector, delivery_mode, dest_mode, dest);
    spin_unlock_irqrestore(&int_remap_table_lock, flags);

    spin_lock_irqsave(&iommu->lock, flags);
    invalidate_interrupt_table(iommu, dev_id);
    flush_command_buffer(iommu);
    spin_unlock_irqrestore(&iommu->lock, flags);

    return;
}

void amd_iommu_msi_msg_update_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct pci_dev *pdev = msi_desc->dev;
    struct amd_iommu *iommu = NULL;

    iommu = find_iommu_for_device(pdev->bus, pdev->devfn);

    if ( !iommu || !int_remap_table )
        return;

    update_intremap_entry_from_msi_msg(iommu, pdev, msg);
}

int __init deallocate_intremap_table(void)
{
    if ( int_remap_table )
    {
        __free_amd_iommu_tables(int_remap_table, INTREMAP_TABLE_ORDER);
        int_remap_table = NULL;
    }

    return 0;
}
