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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/err.h>
#include <xen/sched.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <asm/io_apic.h>
#include <xen/keyhandler.h>

#define INTREMAP_TABLE_ORDER    1
#define INTREMAP_LENGTH 0xB
#define INTREMAP_ENTRIES (1 << INTREMAP_LENGTH)

struct ioapic_sbdf ioapic_sbdf[MAX_IO_APICS];
struct hpet_sbdf hpet_sbdf;
void *shared_intremap_table;
unsigned long *shared_intremap_inuse;
static DEFINE_SPINLOCK(shared_intremap_lock);

static void dump_intremap_tables(unsigned char key);

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

static unsigned int alloc_intremap_entry(int seg, int bdf, unsigned int nr)
{
    unsigned long *inuse = get_ivrs_mappings(seg)[bdf].intremap_inuse;
    unsigned int slot = find_first_zero_bit(inuse, INTREMAP_ENTRIES);

    for ( ; ; )
    {
        unsigned int end;

        if ( slot >= INTREMAP_ENTRIES )
            break;
        end = find_next_bit(inuse, INTREMAP_ENTRIES, slot + 1);
        if ( end > INTREMAP_ENTRIES )
            end = INTREMAP_ENTRIES;
        slot = (slot + nr - 1) & ~(nr - 1);
        if ( slot + nr <= end )
        {
            while ( nr-- )
                __set_bit(slot + nr, inuse);
            break;
        }
        slot = (end + nr) & ~(nr - 1);
        if ( slot >= INTREMAP_ENTRIES )
            break;
        slot = find_next_zero_bit(inuse, INTREMAP_ENTRIES, slot);
    }

    return slot;
}

static u32 *get_intremap_entry(int seg, int bdf, int offset)
{
    u32 *table = get_ivrs_mappings(seg)[bdf].intremap_table;

    ASSERT( (table != NULL) && (offset < INTREMAP_ENTRIES) );

    return table + offset;
}

static void free_intremap_entry(int seg, int bdf, int offset)
{
    u32 *entry = get_intremap_entry(seg, bdf, offset);

    memset(entry, 0, sizeof(u32));
    __clear_bit(offset, get_ivrs_mappings(seg)[bdf].intremap_inuse);
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

static inline int get_rte_index(const struct IO_APIC_route_entry *rte)
{
    return rte->vector | (rte->delivery_mode << 8);
}

static inline void set_rte_index(struct IO_APIC_route_entry *rte, int offset)
{
    rte->vector = (u8)offset;
    rte->delivery_mode = offset >> 8;
}

static int update_intremap_entry_from_ioapic(
    int bdf,
    struct amd_iommu *iommu,
    struct IO_APIC_route_entry *rte,
    bool_t lo_update,
    u16 *index)
{
    unsigned long flags;
    u32* entry;
    u8 delivery_mode, dest, vector, dest_mode;
    int req_id;
    spinlock_t *lock;
    unsigned int offset;

    req_id = get_intremap_requestor_id(iommu->seg, bdf);
    lock = get_intremap_lock(iommu->seg, req_id);

    delivery_mode = rte->delivery_mode;
    vector = rte->vector;
    dest_mode = rte->dest_mode;
    dest = rte->dest.logical.logical_dest;

    spin_lock_irqsave(lock, flags);

    offset = *index;
    if ( offset >= INTREMAP_ENTRIES )
    {
        offset = alloc_intremap_entry(iommu->seg, req_id, 1);
        if ( offset >= INTREMAP_ENTRIES )
        {
            spin_unlock_irqrestore(lock, flags);
            rte->mask = 1;
            return -ENOSPC;
        }
        *index = offset;
        lo_update = 1;
    }

    entry = get_intremap_entry(iommu->seg, req_id, offset);
    if ( !lo_update )
    {
        /*
         * Low half of incoming RTE is already in remapped format,
         * so need to recover vector and delivery mode from IRTE.
         */
        ASSERT(get_rte_index(rte) == offset);
        vector = get_field_from_reg_u32(*entry,
                                        INT_REMAP_ENTRY_VECTOR_MASK,
                                        INT_REMAP_ENTRY_VECTOR_SHIFT);
        delivery_mode = get_field_from_reg_u32(*entry,
                                               INT_REMAP_ENTRY_INTTYPE_MASK,
                                               INT_REMAP_ENTRY_INTTYPE_SHIFT);
    }
    update_intremap_entry(entry, vector, delivery_mode, dest_mode, dest);

    spin_unlock_irqrestore(lock, flags);

    if ( iommu->enabled )
    {
        spin_lock_irqsave(&iommu->lock, flags);
        amd_iommu_flush_intremap(iommu, req_id);
        spin_unlock_irqrestore(&iommu->lock, flags);
    }

    set_rte_index(rte, offset);

    return 0;
}

int __init amd_iommu_setup_ioapic_remapping(void)
{
    struct IO_APIC_route_entry rte;
    unsigned long flags;
    u32* entry;
    int apic, pin;
    u8 delivery_mode, dest, vector, dest_mode;
    u16 seg, bdf, req_id;
    struct amd_iommu *iommu;
    spinlock_t *lock;
    unsigned int offset;

    /* Read ioapic entries and update interrupt remapping table accordingly */
    for ( apic = 0; apic < nr_ioapics; apic++ )
    {
        for ( pin = 0; pin < nr_ioapic_entries[apic]; pin++ )
        {
            rte = __ioapic_read_entry(apic, pin, 1);
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
            offset = alloc_intremap_entry(seg, req_id, 1);
            BUG_ON(offset >= INTREMAP_ENTRIES);
            entry = get_intremap_entry(iommu->seg, req_id, offset);
            update_intremap_entry(entry, vector,
                                  delivery_mode, dest_mode, dest);
            spin_unlock_irqrestore(lock, flags);

            set_rte_index(&rte, offset);
            ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx[pin] = offset;
            __ioapic_write_entry(apic, pin, 1, rte);

            if ( iommu->enabled )
            {
                spin_lock_irqsave(&iommu->lock, flags);
                amd_iommu_flush_intremap(iommu, req_id);
                spin_unlock_irqrestore(&iommu->lock, flags);
            }
        }
    }

    register_keyhandler('V', &dump_intremap_tables,
                        "dump IOMMU intremap tables", 0);

    return 0;
}

void amd_iommu_ioapic_update_ire(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    struct IO_APIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_entry new_rte = { 0 };
    unsigned int rte_lo = (reg & 1) ? reg - 1 : reg;
    unsigned int pin = (reg - 0x10) / 2;
    int saved_mask, seg, bdf, rc;
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
         ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx[pin] >= INTREMAP_ENTRIES )
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
    rc = update_intremap_entry_from_ioapic(
             bdf, iommu, &new_rte, reg == rte_lo,
             &ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx[pin]);

    __io_apic_write(apic, reg, ((u32 *)&new_rte)[reg != rte_lo]);

    if ( rc )
    {
        /* Keep the entry masked. */
        printk(XENLOG_ERR "Remapping IO-APIC %#x pin %u failed (%d)\n",
               IO_APIC_ID(apic), pin, rc);
        return;
    }

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

unsigned int amd_iommu_read_ioapic_from_ire(
    unsigned int apic, unsigned int reg)
{
    unsigned int val = __io_apic_read(apic, reg);
    unsigned int pin = (reg - 0x10) / 2;
    unsigned int offset = ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx[pin];

    if ( !(reg & 1) && offset < INTREMAP_ENTRIES )
    {
        u16 bdf = ioapic_sbdf[IO_APIC_ID(apic)].bdf;
        u16 seg = ioapic_sbdf[IO_APIC_ID(apic)].seg;
        u16 req_id = get_intremap_requestor_id(seg, bdf);
        const u32 *entry = get_intremap_entry(seg, req_id, offset);

        ASSERT(offset == (val & (INTREMAP_ENTRIES - 1)));
        val &= ~(INTREMAP_ENTRIES - 1);
        val |= get_field_from_reg_u32(*entry,
                                      INT_REMAP_ENTRY_INTTYPE_MASK,
                                      INT_REMAP_ENTRY_INTTYPE_SHIFT) << 8;
        val |= get_field_from_reg_u32(*entry,
                                      INT_REMAP_ENTRY_VECTOR_MASK,
                                      INT_REMAP_ENTRY_VECTOR_SHIFT);
    }

    return val;
}

static int update_intremap_entry_from_msi_msg(
    struct amd_iommu *iommu, u16 bdf, unsigned int nr,
    int *remap_index, const struct msi_msg *msg, u32 *data)
{
    unsigned long flags;
    u32* entry;
    u16 req_id, alias_id;
    u8 delivery_mode, dest, vector, dest_mode;
    spinlock_t *lock;
    unsigned int offset, i;

    req_id = get_dma_requestor_id(iommu->seg, bdf);
    alias_id = get_intremap_requestor_id(iommu->seg, bdf);

    if ( msg == NULL )
    {
        lock = get_intremap_lock(iommu->seg, req_id);
        spin_lock_irqsave(lock, flags);
        for ( i = 0; i < nr; ++i )
            free_intremap_entry(iommu->seg, req_id, *remap_index + i);
        spin_unlock_irqrestore(lock, flags);
        goto done;
    }

    lock = get_intremap_lock(iommu->seg, req_id);

    spin_lock_irqsave(lock, flags);
    dest_mode = (msg->address_lo >> MSI_ADDR_DESTMODE_SHIFT) & 0x1;
    delivery_mode = (msg->data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x1;
    vector = (msg->data >> MSI_DATA_VECTOR_SHIFT) & MSI_DATA_VECTOR_MASK;
    dest = (msg->address_lo >> MSI_ADDR_DEST_ID_SHIFT) & 0xff;
    offset = *remap_index;
    if ( offset >= INTREMAP_ENTRIES )
    {
        ASSERT(nr);
        offset = alloc_intremap_entry(iommu->seg, bdf, nr);
        if ( offset >= INTREMAP_ENTRIES )
        {
            spin_unlock_irqrestore(lock, flags);
            return -ENOSPC;
        }
        *remap_index = offset;
    }

    entry = get_intremap_entry(iommu->seg, req_id, offset);
    update_intremap_entry(entry, vector, delivery_mode, dest_mode, dest);
    spin_unlock_irqrestore(lock, flags);

    *data = (msg->data & ~(INTREMAP_ENTRIES - 1)) | offset;

    /*
     * In some special cases, a pci-e device(e.g SATA controller in IDE mode)
     * will use alias id to index interrupt remapping table.
     * We have to setup a secondary interrupt remapping entry to satisfy those
     * devices.
     */

    if ( ( req_id != alias_id ) &&
         get_ivrs_mappings(iommu->seg)[alias_id].intremap_table != NULL )
    {
        BUG_ON(get_ivrs_mappings(iommu->seg)[req_id].intremap_table !=
               get_ivrs_mappings(iommu->seg)[alias_id].intremap_table);
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

    return 0;
}

static struct amd_iommu *_find_iommu_for_device(int seg, int bdf)
{
    struct amd_iommu *iommu;

    list_for_each_entry ( iommu, &amd_iommu_head, list )
        if ( iommu->seg == seg && iommu->bdf == bdf )
            return NULL;

    iommu = find_iommu_for_device(seg, bdf);
    if ( iommu )
        return iommu;

    AMD_IOMMU_DEBUG("No IOMMU for MSI dev = %04x:%02x:%02x.%u\n",
                    seg, PCI_BUS(bdf), PCI_SLOT(bdf), PCI_FUNC(bdf));
    return ERR_PTR(-EINVAL);
}

int amd_iommu_msi_msg_update_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct pci_dev *pdev = msi_desc->dev;
    int bdf, seg, rc;
    struct amd_iommu *iommu;
    unsigned int i, nr = 1;
    u32 data;

    bdf = pdev ? PCI_BDF2(pdev->bus, pdev->devfn) : hpet_sbdf.bdf;
    seg = pdev ? pdev->seg : hpet_sbdf.seg;

    iommu = _find_iommu_for_device(seg, bdf);
    if ( IS_ERR_OR_NULL(iommu) )
        return PTR_ERR(iommu);

    if ( msi_desc->msi_attrib.type == PCI_CAP_ID_MSI )
        nr = msi_desc->msi.nvec;

    if ( msi_desc->remap_index >= 0 && !msg )
    {
        do {
            update_intremap_entry_from_msi_msg(iommu, bdf, nr,
                                               &msi_desc->remap_index,
                                               NULL, NULL);
            if ( !pdev || !pdev->phantom_stride )
                break;
            bdf += pdev->phantom_stride;
        } while ( PCI_SLOT(bdf) == PCI_SLOT(pdev->devfn) );

        for ( i = 0; i < nr; ++i )
            msi_desc[i].remap_index = -1;
        if ( pdev )
            bdf = PCI_BDF2(pdev->bus, pdev->devfn);
    }

    if ( !msg )
        return 0;

    do {
        rc = update_intremap_entry_from_msi_msg(iommu, bdf, nr,
                                                &msi_desc->remap_index,
                                                msg, &data);
        if ( rc || !pdev || !pdev->phantom_stride )
            break;
        bdf += pdev->phantom_stride;
    } while ( PCI_SLOT(bdf) == PCI_SLOT(pdev->devfn) );

    if ( !rc )
    {
        for ( i = 1; i < nr; ++i )
            msi_desc[i].remap_index = msi_desc->remap_index + i;
        msg->data = data;
    }

    return rc;
}

void amd_iommu_read_msi_from_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    unsigned int offset = msg->data & (INTREMAP_ENTRIES - 1);
    const struct pci_dev *pdev = msi_desc->dev;
    u16 bdf = pdev ? PCI_BDF2(pdev->bus, pdev->devfn) : hpet_sbdf.bdf;
    u16 seg = pdev ? pdev->seg : hpet_sbdf.seg;
    const u32 *entry;

    if ( IS_ERR_OR_NULL(_find_iommu_for_device(seg, bdf)) )
        return;

    entry = get_intremap_entry(seg, get_dma_requestor_id(seg, bdf), offset);

    if ( msi_desc->msi_attrib.type == PCI_CAP_ID_MSI )
    {
        int nr = msi_desc->msi_attrib.entry_nr;

        ASSERT(!(offset & (msi_desc[-nr].msi.nvec - 1)));
        offset |= nr;
    }

    msg->data &= ~(INTREMAP_ENTRIES - 1);
    msg->data |= get_field_from_reg_u32(*entry,
                                        INT_REMAP_ENTRY_INTTYPE_MASK,
                                        INT_REMAP_ENTRY_INTTYPE_SHIFT) << 8;
    msg->data |= get_field_from_reg_u32(*entry,
                                        INT_REMAP_ENTRY_VECTOR_MASK,
                                        INT_REMAP_ENTRY_VECTOR_SHIFT);
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

void* __init amd_iommu_alloc_intremap_table(unsigned long **inuse_map)
{
    void *tb;
    tb = __alloc_amd_iommu_tables(INTREMAP_TABLE_ORDER);
    BUG_ON(tb == NULL);
    memset(tb, 0, PAGE_SIZE * (1UL << INTREMAP_TABLE_ORDER));
    *inuse_map = xzalloc_array(unsigned long, BITS_TO_LONGS(INTREMAP_ENTRIES));
    BUG_ON(*inuse_map == NULL);
    return tb;
}

int __init amd_setup_hpet_msi(struct msi_desc *msi_desc)
{
    spinlock_t *lock;
    unsigned long flags;
    int rc = 0;

    if ( hpet_sbdf.init == HPET_NONE )
    {
        AMD_IOMMU_DEBUG("Failed to setup HPET MSI remapping."
                        " Missing IVRS HPET info.\n");
        return -ENODEV;
    }
    if ( msi_desc->hpet_id != hpet_sbdf.id )
    {
        AMD_IOMMU_DEBUG("Failed to setup HPET MSI remapping."
                        " Wrong HPET.\n");
        return -ENODEV;
    }

    lock = get_intremap_lock(hpet_sbdf.seg, hpet_sbdf.bdf);
    spin_lock_irqsave(lock, flags);

    msi_desc->remap_index = alloc_intremap_entry(hpet_sbdf.seg,
                                                 hpet_sbdf.bdf, 1);
    if ( msi_desc->remap_index >= INTREMAP_ENTRIES )
    {
        msi_desc->remap_index = -1;
        rc = -ENXIO;
    }

    spin_unlock_irqrestore(lock, flags);

    return rc;
}

static void dump_intremap_table(const u32 *table)
{
    u32 count;

    if ( !table )
        return;

    for ( count = 0; count < INTREMAP_ENTRIES; count++ )
    {
        if ( !table[count] )
            continue;
        printk("    IRTE[%03x] %08x\n", count, table[count]);
    }
}

static int dump_intremap_mapping(u16 seg, struct ivrs_mappings *ivrs_mapping)
{
    unsigned long flags;

    if ( !ivrs_mapping )
        return 0;

    printk("  %04x:%02x:%02x:%u:\n", seg,
           PCI_BUS(ivrs_mapping->dte_requestor_id),
           PCI_SLOT(ivrs_mapping->dte_requestor_id),
           PCI_FUNC(ivrs_mapping->dte_requestor_id));

    spin_lock_irqsave(&(ivrs_mapping->intremap_lock), flags);
    dump_intremap_table(ivrs_mapping->intremap_table);
    spin_unlock_irqrestore(&(ivrs_mapping->intremap_lock), flags);

    return 0;
}

static void dump_intremap_tables(unsigned char key)
{
    unsigned long flags;

    printk("--- Dumping Per-dev IOMMU Interrupt Remapping Table ---\n");

    iterate_ivrs_entries(dump_intremap_mapping);

    printk("--- Dumping Shared IOMMU Interrupt Remapping Table ---\n");

    spin_lock_irqsave(&shared_intremap_lock, flags);
    dump_intremap_table(shared_intremap_table);
    spin_unlock_irqrestore(&shared_intremap_lock, flags);
}
