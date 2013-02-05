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
#include <asm/io_apic.h>

#define INTREMAP_TABLE_ORDER    1
#define INTREMAP_LENGTH 0xB
#define INTREMAP_ENTRIES (1 << INTREMAP_LENGTH)

struct ioapic_sbdf ioapic_sbdf[MAX_IO_APICS];
void *shared_intremap_table;
static DEFINE_SPINLOCK(shared_intremap_lock);

static spinlock_t* get_intremap_lock(int seg, int req_id)
{
    return (amd_iommu_perdev_intremap ?
           &get_ivrs_mappings(seg)[req_id].intremap_lock:
           &shared_intremap_lock);
}

static int get_intremap_requestor_id(int seg, int bdf)
{
    ASSERT( bdf < ivrs_bdf_entries );
    return get_ivrs_mappings(seg)[bdf].dte_requestor_id;
}

static int get_intremap_offset(u8 vector, u8 dm)
{
    int offset = 0;
    offset = (dm << INT_REMAP_INDEX_DM_SHIFT) & INT_REMAP_INDEX_DM_MASK;
    offset |= (vector << INT_REMAP_INDEX_VECTOR_SHIFT ) & 
        INT_REMAP_INDEX_VECTOR_MASK;
    return offset;
}

static u8 *get_intremap_entry(int seg, int bdf, int offset)
{
    u8 *table;

    table = (u8*)get_ivrs_mappings(seg)[bdf].intremap_table;
    ASSERT( (table != NULL) && (offset < INTREMAP_ENTRIES) );

    return (u8*) (table + offset);
}

static void free_intremap_entry(int seg, int bdf, int offset)
{
    u32* entry;
    entry = (u32*)get_intremap_entry(seg, bdf, offset);
    memset(entry, 0, sizeof(u32));
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

static void update_intremap_entry_from_ioapic(
    int bdf,
    struct amd_iommu *iommu,
    const struct IO_APIC_route_entry *rte,
    const struct IO_APIC_route_entry *old_rte)
{
    unsigned long flags;
    u32* entry;
    u8 delivery_mode, dest, vector, dest_mode;
    int req_id;
    spinlock_t *lock;
    int offset;

    req_id = get_intremap_requestor_id(iommu->seg, bdf);
    lock = get_intremap_lock(iommu->seg, req_id);

    delivery_mode = rte->delivery_mode;
    vector = rte->vector;
    dest_mode = rte->dest_mode;
    dest = rte->dest.logical.logical_dest;

    spin_lock_irqsave(lock, flags);

    offset = get_intremap_offset(vector, delivery_mode);
    if ( old_rte )
    {
        int old_offset = get_intremap_offset(old_rte->vector,
                                             old_rte->delivery_mode);

        if ( offset != old_offset )
            free_intremap_entry(iommu->seg, bdf, old_offset);
    }
    entry = (u32*)get_intremap_entry(iommu->seg, req_id, offset);
    update_intremap_entry(entry, vector, delivery_mode, dest_mode, dest);

    spin_unlock_irqrestore(lock, flags);

    if ( iommu->enabled )
    {
        spin_lock_irqsave(&iommu->lock, flags);
        amd_iommu_flush_intremap(iommu, req_id);
        spin_unlock_irqrestore(&iommu->lock, flags);
    }
}

int __init amd_iommu_setup_ioapic_remapping(void)
{
    struct IO_APIC_route_entry rte = {0};
    unsigned long flags;
    u32* entry;
    int apic, pin;
    u8 delivery_mode, dest, vector, dest_mode;
    u16 seg, bdf, req_id;
    struct amd_iommu *iommu;
    spinlock_t *lock;
    int offset;

    /* Read ioapic entries and update interrupt remapping table accordingly */
    for ( apic = 0; apic < nr_ioapics; apic++ )
    {
        for ( pin = 0; pin < nr_ioapic_entries[apic]; pin++ )
        {
            *(((int *)&rte) + 1) = io_apic_read(apic, 0x11 + 2 * pin);
            *(((int *)&rte) + 0) = io_apic_read(apic, 0x10 + 2 * pin);

            if ( rte.mask == 1 )
                continue;

            /* get device id of ioapic devices */
            bdf = ioapic_sbdf[IO_APIC_ID(apic)].bdf;
            seg = ioapic_sbdf[IO_APIC_ID(apic)].seg;
            iommu = find_iommu_for_device(seg, bdf);
            if ( !iommu )
            {
                AMD_IOMMU_DEBUG("Fail to find iommu for ioapic "
                                "device id = %04x:%04x\n", seg, bdf);
                continue;
            }

            req_id = get_intremap_requestor_id(iommu->seg, bdf);
            lock = get_intremap_lock(iommu->seg, req_id);

            delivery_mode = rte.delivery_mode;
            vector = rte.vector;
            dest_mode = rte.dest_mode;
            dest = rte.dest.logical.logical_dest;

            spin_lock_irqsave(lock, flags);
            offset = get_intremap_offset(vector, delivery_mode);
            entry = (u32*)get_intremap_entry(iommu->seg, req_id, offset);
            update_intremap_entry(entry, vector,
                                  delivery_mode, dest_mode, dest);
            spin_unlock_irqrestore(lock, flags);

            if ( iommu->enabled )
            {
                spin_lock_irqsave(&iommu->lock, flags);
                amd_iommu_flush_intremap(iommu, req_id);
                spin_unlock_irqrestore(&iommu->lock, flags);
            }
            set_bit(pin, ioapic_sbdf[IO_APIC_ID(apic)].pin_setup);
        }
    }
    return 0;
}

void amd_iommu_ioapic_update_ire(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    struct IO_APIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_entry new_rte = { 0 };
    unsigned int rte_lo = (reg & 1) ? reg - 1 : reg;
    unsigned int pin = (reg - 0x10) / 2;
    int saved_mask, seg, bdf;
    struct amd_iommu *iommu;

    if ( !iommu_intremap )
    {
        __io_apic_write(apic, reg, value);
        return;
    }

    /* get device id of ioapic devices */
    bdf = ioapic_sbdf[IO_APIC_ID(apic)].bdf;
    seg = ioapic_sbdf[IO_APIC_ID(apic)].seg;
    iommu = find_iommu_for_device(seg, bdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Fail to find iommu for ioapic device id ="
                        " %04x:%04x\n", seg, bdf);
        __io_apic_write(apic, reg, value);
        return;
    }

    /* save io-apic rte lower 32 bits */
    *((u32 *)&old_rte) =  __io_apic_read(apic, rte_lo);
    saved_mask = old_rte.mask;

    if ( reg == rte_lo )
    {
        *((u32 *)&new_rte) = value;
        /* read upper 32 bits from io-apic rte */
        *(((u32 *)&new_rte) + 1) = __io_apic_read(apic, reg + 1);
    }
    else
    {
        *((u32 *)&new_rte) = *((u32 *)&old_rte);
        *(((u32 *)&new_rte) + 1) = value;
    }

    if ( new_rte.mask &&
         !test_bit(pin, ioapic_sbdf[IO_APIC_ID(apic)].pin_setup) )
    {
        ASSERT(saved_mask);
        __io_apic_write(apic, reg, value);
        return;
    }

    /* mask the interrupt while we change the intremap table */
    if ( !saved_mask )
    {
        old_rte.mask = 1;
        __io_apic_write(apic, rte_lo, *((u32 *)&old_rte));
    }

    /* Update interrupt remapping entry */
    update_intremap_entry_from_ioapic(
        bdf, iommu, &new_rte,
        test_and_set_bit(pin,
                         ioapic_sbdf[IO_APIC_ID(apic)].pin_setup) ? &old_rte
                                                                  : NULL);

    /* Forward write access to IO-APIC RTE */
    __io_apic_write(apic, reg, value);

    /* For lower bits access, return directly to avoid double writes */
    if ( reg == rte_lo )
        return;

    /* unmask the interrupt after we have updated the intremap table */
    if ( !saved_mask )
    {
        old_rte.mask = saved_mask;
        __io_apic_write(apic, rte_lo, *((u32 *)&old_rte));
    }
}

static void update_intremap_entry_from_msi_msg(
    struct amd_iommu *iommu, struct pci_dev *pdev,
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    unsigned long flags;
    u32* entry;
    u16 bdf, req_id, alias_id;
    u8 delivery_mode, dest, vector, dest_mode;
    spinlock_t *lock;
    int offset;

    bdf = (pdev->bus << 8) | pdev->devfn;
    req_id = get_dma_requestor_id(pdev->seg, bdf);
    alias_id = get_intremap_requestor_id(pdev->seg, bdf);

    if ( msg == NULL )
    {
        lock = get_intremap_lock(iommu->seg, req_id);
        spin_lock_irqsave(lock, flags);
        free_intremap_entry(iommu->seg, req_id, msi_desc->remap_index);
        spin_unlock_irqrestore(lock, flags);

        if ( ( req_id != alias_id ) &&
             get_ivrs_mappings(pdev->seg)[alias_id].intremap_table != NULL )
        {
            lock = get_intremap_lock(iommu->seg, alias_id);
            spin_lock_irqsave(lock, flags);
            free_intremap_entry(iommu->seg, alias_id, msi_desc->remap_index);
            spin_unlock_irqrestore(lock, flags);
        }
        goto done;
    }

    lock = get_intremap_lock(iommu->seg, req_id);

    spin_lock_irqsave(lock, flags);
    dest_mode = (msg->address_lo >> MSI_ADDR_DESTMODE_SHIFT) & 0x1;
    delivery_mode = (msg->data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x1;
    vector = (msg->data >> MSI_DATA_VECTOR_SHIFT) & MSI_DATA_VECTOR_MASK;
    dest = (msg->address_lo >> MSI_ADDR_DEST_ID_SHIFT) & 0xff;
    offset = get_intremap_offset(vector, delivery_mode);
    msi_desc->remap_index = offset;

    entry = (u32*)get_intremap_entry(iommu->seg, req_id, offset);
    update_intremap_entry(entry, vector, delivery_mode, dest_mode, dest);
    spin_unlock_irqrestore(lock, flags);

    /*
     * In some special cases, a pci-e device(e.g SATA controller in IDE mode)
     * will use alias id to index interrupt remapping table.
     * We have to setup a secondary interrupt remapping entry to satisfy those
     * devices.
     */

    lock = get_intremap_lock(iommu->seg, alias_id);
    if ( ( req_id != alias_id ) &&
         get_ivrs_mappings(pdev->seg)[alias_id].intremap_table != NULL )
    {
        spin_lock_irqsave(lock, flags);
        entry = (u32*)get_intremap_entry(iommu->seg, alias_id, offset);
        update_intremap_entry(entry, vector, delivery_mode, dest_mode, dest);
        spin_unlock_irqrestore(lock, flags);
    }

done:
    if ( iommu->enabled )
    {
        spin_lock_irqsave(&iommu->lock, flags);
        amd_iommu_flush_intremap(iommu, req_id);
        if ( alias_id != req_id )
            amd_iommu_flush_intremap(iommu, alias_id);
        spin_unlock_irqrestore(&iommu->lock, flags);
    }
}

void amd_iommu_msi_msg_update_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct pci_dev *pdev = msi_desc->dev;
    struct amd_iommu *iommu = NULL;

    if ( !iommu_intremap )
        return;

    iommu = find_iommu_for_device(pdev->seg, (pdev->bus << 8) | pdev->devfn);

    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Fail to find iommu for MSI device id = 0x%x\n",
                       (pdev->bus << 8) | pdev->devfn);
        return;
    }

    if ( msi_desc->remap_index >= 0 )
        update_intremap_entry_from_msi_msg(iommu, pdev, msi_desc, NULL);

    if ( !msg )
        return;

    update_intremap_entry_from_msi_msg(iommu, pdev, msi_desc, msg);
}

void amd_iommu_read_msi_from_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
}

int __init amd_iommu_free_intremap_table(
    u16 seg, struct ivrs_mappings *ivrs_mapping)
{
    void *tb = ivrs_mapping->intremap_table;

    if ( tb )
    {
        __free_amd_iommu_tables(tb, INTREMAP_TABLE_ORDER);
        ivrs_mapping->intremap_table = NULL;
    }

    return 0;
}

void* __init amd_iommu_alloc_intremap_table(void)
{
    void *tb;
    tb = __alloc_amd_iommu_tables(INTREMAP_TABLE_ORDER);
    BUG_ON(tb == NULL);
    memset(tb, 0, PAGE_SIZE * (1UL << INTREMAP_TABLE_ORDER));
    return tb;
}
