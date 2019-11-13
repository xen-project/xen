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
#include <xen/softirq.h>

union irte32 {
    uint32_t raw;
    struct {
        bool remap_en:1;
        bool sup_io_pf:1;
        unsigned int int_type:3;
        bool rq_eoi:1;
        bool dm:1;
        bool guest_mode:1; /* MBZ */
        unsigned int dest:8;
        unsigned int vector:8;
        unsigned int :8;
    } flds;
};

union irte128 {
    uint64_t raw[2];
    struct {
        bool remap_en:1;
        bool sup_io_pf:1;
        unsigned int int_type:3;
        bool rq_eoi:1;
        bool dm:1;
        bool guest_mode:1; /* MBZ */
        unsigned int dest_lo:24;
        unsigned int :32;
        unsigned int vector:8;
        unsigned int :24;
        unsigned int :24;
        unsigned int dest_hi:8;
    } full;
};

union irte_ptr {
    void *ptr;
    union irte32 *ptr32;
    union irte128 *ptr128;
};

union irte_cptr {
    const void *ptr;
    const union irte32 *ptr32;
    const union irte128 *ptr128;
} __transparent__;

#define INTREMAP_MAX_ORDER   0xB
#define INTREMAP_MAX_ENTRIES (1 << INTREMAP_MAX_ORDER)

struct ioapic_sbdf ioapic_sbdf[MAX_IO_APICS];
struct hpet_sbdf hpet_sbdf;
void *shared_intremap_table;
unsigned long *shared_intremap_inuse;
static DEFINE_SPINLOCK(shared_intremap_lock);
unsigned int nr_ioapic_sbdf;

#define intremap_page_order(irt) PFN_ORDER(virt_to_page(irt))

unsigned int amd_iommu_intremap_table_order(
    const void *irt, const struct amd_iommu *iommu)
{
    return intremap_page_order(irt) + PAGE_SHIFT -
           (iommu->ctrl.ga_en ? 4 : 2);
}

static unsigned int intremap_table_entries(
    const void *irt, const struct amd_iommu *iommu)
{
    return 1u << amd_iommu_intremap_table_order(irt, iommu);
}

unsigned int ioapic_id_to_index(unsigned int apic_id)
{
    unsigned int idx;

    for ( idx = 0 ; idx < nr_ioapic_sbdf; idx++ )
        if ( ioapic_sbdf[idx].id == apic_id )
            break;

    if ( idx == nr_ioapic_sbdf )
        return MAX_IO_APICS;

    return idx;
}

unsigned int __init get_next_ioapic_sbdf_index(void)
{
    if ( nr_ioapic_sbdf < MAX_IO_APICS )
        return nr_ioapic_sbdf++;

    return MAX_IO_APICS;
}

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

static unsigned int alloc_intremap_entry(const struct amd_iommu *iommu,
                                         unsigned int bdf, unsigned int nr)
{
    const struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(iommu->seg);
    unsigned long *inuse = ivrs_mappings[bdf].intremap_inuse;
    unsigned int nr_ents =
        intremap_table_entries(ivrs_mappings[bdf].intremap_table, iommu);
    unsigned int slot = find_first_zero_bit(inuse, nr_ents);

    for ( ; ; )
    {
        unsigned int end;

        if ( slot >= nr_ents )
            break;
        end = find_next_bit(inuse, nr_ents, slot + 1);
        if ( end > nr_ents )
            end = nr_ents;
        slot = (slot + nr - 1) & ~(nr - 1);
        if ( slot + nr <= end )
        {
            while ( nr-- )
                __set_bit(slot + nr, inuse);
            break;
        }
        slot = (end + nr) & ~(nr - 1);
        if ( slot >= nr_ents )
            break;
        slot = find_next_zero_bit(inuse, nr_ents, slot);
    }

    return slot < nr_ents ? slot : INTREMAP_MAX_ENTRIES;
}

static union irte_ptr get_intremap_entry(const struct amd_iommu *iommu,
                                         unsigned int bdf, unsigned int index)
{
    union irte_ptr table = {
        .ptr = get_ivrs_mappings(iommu->seg)[bdf].intremap_table
    };

    ASSERT(table.ptr && (index < intremap_table_entries(table.ptr, iommu)));

    if ( iommu->ctrl.ga_en )
        table.ptr128 += index;
    else
        table.ptr32 += index;

    return table;
}

static void free_intremap_entry(const struct amd_iommu *iommu,
                                unsigned int bdf, unsigned int index)
{
    union irte_ptr entry = get_intremap_entry(iommu, bdf, index);

    if ( iommu->ctrl.ga_en )
    {
        ACCESS_ONCE(entry.ptr128->raw[0]) = 0;
        /*
         * Low half (containing RemapEn) needs to be cleared first.  Note that
         * strictly speaking smp_wmb() isn't enough, as conceptually it expands
         * to just barrier() when !CONFIG_SMP.  But wmb() would be more than we
         * need, since the IOMMU is a cache-coherent entity on the bus.  And
         * given that we don't allow CONFIG_SMP to be turned off, the SMP
         * variant will do.
         */
        smp_wmb();
        entry.ptr128->raw[1] = 0;
    }
    else
        ACCESS_ONCE(entry.ptr32->raw) = 0;

    __clear_bit(index, get_ivrs_mappings(iommu->seg)[bdf].intremap_inuse);
}

static void update_intremap_entry(const struct amd_iommu *iommu,
                                  union irte_ptr entry,
                                  unsigned int vector, unsigned int int_type,
                                  unsigned int dest_mode, unsigned int dest)
{
    if ( iommu->ctrl.ga_en )
    {
        union irte128 irte = {
            .full = {
                .remap_en = true,
                .int_type = int_type,
                .dm = dest_mode,
                .dest_lo = dest,
                .dest_hi = dest >> 24,
                .vector = vector,
            },
        };

        ASSERT(!entry.ptr128->full.remap_en);
        entry.ptr128->raw[1] = irte.raw[1];
        /*
         * High half needs to be set before low one (containing RemapEn).  See
         * comment in free_intremap_entry() regarding the choice of barrier.
         */
        smp_wmb();
        ACCESS_ONCE(entry.ptr128->raw[0]) = irte.raw[0];
    }
    else
    {
        union irte32 irte = {
            .flds = {
                .remap_en = true,
                .int_type = int_type,
                .dm = dest_mode,
                .dest = dest,
                .vector = vector,
            },
        };

        ACCESS_ONCE(entry.ptr32->raw) = irte.raw;
    }
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

static inline unsigned int get_full_dest(const union irte128 *entry)
{
    return entry->full.dest_lo | ((unsigned int)entry->full.dest_hi << 24);
}

static int update_intremap_entry_from_ioapic(
    int bdf,
    struct amd_iommu *iommu,
    struct IO_APIC_route_entry *rte,
    bool_t lo_update,
    u16 *index)
{
    unsigned long flags;
    union irte_ptr entry;
    uint8_t delivery_mode, vector, dest_mode;
    int req_id;
    spinlock_t *lock;
    unsigned int dest, offset;
    bool fresh = false;

    req_id = get_intremap_requestor_id(iommu->seg, bdf);
    lock = get_intremap_lock(iommu->seg, req_id);

    delivery_mode = rte->delivery_mode;
    vector = rte->vector;
    dest_mode = rte->dest_mode;
    dest = x2apic_enabled ? rte->dest.dest32 : rte->dest.logical.logical_dest;

    spin_lock_irqsave(lock, flags);

    offset = *index;
    if ( offset >= INTREMAP_MAX_ENTRIES )
    {
        offset = alloc_intremap_entry(iommu, req_id, 1);
        if ( offset >= INTREMAP_MAX_ENTRIES )
        {
            spin_unlock_irqrestore(lock, flags);
            rte->mask = 1;
            return -ENOSPC;
        }
        *index = offset;
        fresh = true;
    }

    entry = get_intremap_entry(iommu, req_id, offset);

    /* The RemapEn fields match for all formats. */
    while ( iommu->enabled && entry.ptr32->flds.remap_en )
    {
        entry.ptr32->flds.remap_en = false;
        spin_unlock(lock);

        spin_lock(&iommu->lock);
        amd_iommu_flush_intremap(iommu, req_id);
        spin_unlock(&iommu->lock);

        spin_lock(lock);
    }

    if ( fresh )
        /* nothing */;
    else if ( !lo_update )
    {
        /*
         * Low half of incoming RTE is already in remapped format,
         * so need to recover vector and delivery mode from IRTE.
         */
        ASSERT(get_rte_index(rte) == offset);
        if ( iommu->ctrl.ga_en )
            vector = entry.ptr128->full.vector;
        else
            vector = entry.ptr32->flds.vector;
        /* The IntType fields match for both formats. */
        delivery_mode = entry.ptr32->flds.int_type;
    }
    else if ( x2apic_enabled )
    {
        /*
         * High half of incoming RTE was read from the I/O APIC and hence may
         * not hold the full destination, so need to recover full destination
         * from IRTE.
         */
        dest = get_full_dest(entry.ptr128);
    }
    update_intremap_entry(iommu, entry, vector, delivery_mode, dest_mode, dest);

    spin_unlock_irqrestore(lock, flags);

    set_rte_index(rte, offset);

    return 0;
}

void amd_iommu_ioapic_update_ire(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    struct IO_APIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_entry new_rte = { 0 };
    unsigned int rte_lo = (reg & 1) ? reg - 1 : reg;
    unsigned int pin = (reg - 0x10) / 2;
    int seg, bdf, rc;
    bool saved_mask, fresh = false;
    struct amd_iommu *iommu;
    unsigned int idx;

    if ( !iommu_intremap )
    {
        __io_apic_write(apic, reg, value);
        return;
    }

    idx = ioapic_id_to_index(IO_APIC_ID(apic));
    if ( idx == MAX_IO_APICS )
        return;

    /* get device id of ioapic devices */
    bdf = ioapic_sbdf[idx].bdf;
    seg = ioapic_sbdf[idx].seg;
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

    if ( ioapic_sbdf[idx].pin_2_idx[pin] >= INTREMAP_MAX_ENTRIES )
    {
        ASSERT(saved_mask);

        /*
         * There's nowhere except the IRTE to store a full 32-bit destination,
         * so we may not bypass entry allocation and updating of the low RTE
         * half in the (usual) case of the high RTE half getting written first.
         */
        if ( new_rte.mask && !x2apic_enabled )
        {
            __io_apic_write(apic, reg, value);
            return;
        }

        fresh = true;
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
             &ioapic_sbdf[idx].pin_2_idx[pin]);

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

    /*
     * Unmask the interrupt after we have updated the intremap table. Also
     * write the low half if a fresh entry was allocated for a high half
     * update in x2APIC mode.
     */
    if ( !saved_mask || (x2apic_enabled && fresh) )
    {
        old_rte.mask = saved_mask;
        __io_apic_write(apic, rte_lo, *((u32 *)&old_rte));
    }
}

unsigned int amd_iommu_read_ioapic_from_ire(
    unsigned int apic, unsigned int reg)
{
    unsigned int idx;
    unsigned int offset;
    unsigned int val = __io_apic_read(apic, reg);
    unsigned int pin = (reg - 0x10) / 2;
    uint16_t seg, bdf, req_id;
    const struct amd_iommu *iommu;
    union irte_ptr entry;

    idx = ioapic_id_to_index(IO_APIC_ID(apic));
    if ( idx == MAX_IO_APICS )
        return val;

    offset = ioapic_sbdf[idx].pin_2_idx[pin];
    if ( offset >= INTREMAP_MAX_ENTRIES )
        return val;

    seg = ioapic_sbdf[idx].seg;
    bdf = ioapic_sbdf[idx].bdf;
    iommu = find_iommu_for_device(seg, bdf);
    if ( !iommu )
        return val;
    req_id = get_intremap_requestor_id(seg, bdf);
    entry = get_intremap_entry(iommu, req_id, offset);

    if ( !(reg & 1) )
    {
        ASSERT(offset == (val & (INTREMAP_MAX_ENTRIES - 1)));
        val &= ~(INTREMAP_MAX_ENTRIES - 1);
        /* The IntType fields match for both formats. */
        val |= MASK_INSR(entry.ptr32->flds.int_type,
                         IO_APIC_REDIR_DELIV_MODE_MASK);
        val |= MASK_INSR(iommu->ctrl.ga_en
                         ? entry.ptr128->full.vector
                         : entry.ptr32->flds.vector,
                         IO_APIC_REDIR_VECTOR_MASK);
    }
    else if ( x2apic_enabled )
        val = get_full_dest(entry.ptr128);

    return val;
}

static int update_intremap_entry_from_msi_msg(
    struct amd_iommu *iommu, u16 bdf, unsigned int nr,
    int *remap_index, const struct msi_msg *msg, u32 *data)
{
    unsigned long flags;
    union irte_ptr entry;
    u16 req_id, alias_id;
    uint8_t delivery_mode, vector, dest_mode;
    spinlock_t *lock;
    unsigned int dest, offset, i;

    req_id = get_dma_requestor_id(iommu->seg, bdf);
    alias_id = get_intremap_requestor_id(iommu->seg, bdf);

    lock = get_intremap_lock(iommu->seg, req_id);
    spin_lock_irqsave(lock, flags);

    if ( msg == NULL )
    {
        for ( i = 0; i < nr; ++i )
            free_intremap_entry(iommu, req_id, *remap_index + i);
        spin_unlock_irqrestore(lock, flags);

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

    dest_mode = (msg->address_lo >> MSI_ADDR_DESTMODE_SHIFT) & 0x1;
    delivery_mode = (msg->data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x1;
    vector = (msg->data >> MSI_DATA_VECTOR_SHIFT) & MSI_DATA_VECTOR_MASK;

    if ( x2apic_enabled )
        dest = msg->dest32;
    else
        dest = MASK_EXTR(msg->address_lo, MSI_ADDR_DEST_ID_MASK);

    offset = *remap_index;
    if ( offset >= INTREMAP_MAX_ENTRIES )
    {
        ASSERT(nr);
        offset = alloc_intremap_entry(iommu, bdf, nr);
        if ( offset >= INTREMAP_MAX_ENTRIES )
        {
            spin_unlock_irqrestore(lock, flags);
            return -ENOSPC;
        }
        *remap_index = offset;
    }

    entry = get_intremap_entry(iommu, req_id, offset);

    /* The RemapEn fields match for all formats. */
    while ( iommu->enabled && entry.ptr32->flds.remap_en )
    {
        entry.ptr32->flds.remap_en = false;
        spin_unlock(lock);

        spin_lock(&iommu->lock);
        amd_iommu_flush_intremap(iommu, req_id);
        if ( alias_id != req_id )
            amd_iommu_flush_intremap(iommu, alias_id);
        spin_unlock(&iommu->lock);

        spin_lock(lock);
    }

    update_intremap_entry(iommu, entry, vector, delivery_mode, dest_mode, dest);
    spin_unlock_irqrestore(lock, flags);

    *data = (msg->data & ~(INTREMAP_MAX_ENTRIES - 1)) | offset;

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

    return 0;
}

static struct amd_iommu *_find_iommu_for_device(int seg, int bdf)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu ( iommu )
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
        update_intremap_entry_from_msi_msg(iommu, bdf, nr,
                                           &msi_desc->remap_index,
                                           NULL, NULL);

        for ( i = 0; i < nr; ++i )
            msi_desc[i].remap_index = -1;
    }

    if ( !msg )
        return 0;

    rc = update_intremap_entry_from_msi_msg(iommu, bdf, nr,
                                            &msi_desc->remap_index,
                                            msg, &data);
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
    unsigned int offset = msg->data & (INTREMAP_MAX_ENTRIES - 1);
    const struct pci_dev *pdev = msi_desc->dev;
    u16 bdf = pdev ? PCI_BDF2(pdev->bus, pdev->devfn) : hpet_sbdf.bdf;
    u16 seg = pdev ? pdev->seg : hpet_sbdf.seg;
    const struct amd_iommu *iommu = _find_iommu_for_device(seg, bdf);
    union irte_ptr entry;

    if ( IS_ERR_OR_NULL(iommu) )
        return;

    entry = get_intremap_entry(iommu, get_dma_requestor_id(seg, bdf), offset);

    if ( msi_desc->msi_attrib.type == PCI_CAP_ID_MSI )
    {
        int nr = msi_desc->msi_attrib.entry_nr;

        ASSERT(!(offset & (msi_desc[-nr].msi.nvec - 1)));
        offset |= nr;
    }

    msg->data &= ~(INTREMAP_MAX_ENTRIES - 1);
    /* The IntType fields match for both formats. */
    msg->data |= MASK_INSR(entry.ptr32->flds.int_type,
                           MSI_DATA_DELIVERY_MODE_MASK);
    if ( iommu->ctrl.ga_en )
    {
        msg->data |= MASK_INSR(entry.ptr128->full.vector,
                               MSI_DATA_VECTOR_MASK);
        msg->dest32 = get_full_dest(entry.ptr128);
    }
    else
    {
        msg->data |= MASK_INSR(entry.ptr32->flds.vector,
                               MSI_DATA_VECTOR_MASK);
        msg->dest32 = entry.ptr32->flds.dest;
    }
}

int amd_iommu_free_intremap_table(
    const struct amd_iommu *iommu, struct ivrs_mappings *ivrs_mapping,
    uint16_t bdf)
{
    void **tblp;

    if ( ivrs_mapping )
    {
        unsigned int i;

        /*
         * PCI device phantom functions use the same tables as their "base"
         * function: Look ahead to zap the pointers.
         */
        for ( i = 1; PCI_FUNC(bdf + i) && bdf + i < ivrs_bdf_entries; ++i )
            if ( ivrs_mapping[i].intremap_table ==
                 ivrs_mapping->intremap_table )
            {
                ivrs_mapping[i].intremap_table = NULL;
                ivrs_mapping[i].intremap_inuse = NULL;
            }

        XFREE(ivrs_mapping->intremap_inuse);
        tblp = &ivrs_mapping->intremap_table;
    }
    else
    {
        XFREE(shared_intremap_inuse);
        tblp = &shared_intremap_table;
    }

    if ( *tblp )
    {
        unsigned int order = intremap_page_order(*tblp);

        intremap_page_order(*tblp) = 0;
        __free_amd_iommu_tables(*tblp, order);
        *tblp = NULL;
    }

    return 0;
}

void *amd_iommu_alloc_intremap_table(
    const struct amd_iommu *iommu, unsigned long **inuse_map, unsigned int nr)
{
    unsigned int order;
    void *tb;

    if ( !nr )
        nr = INTREMAP_MAX_ENTRIES;

    order = iommu->ctrl.ga_en
            ? get_order_from_bytes(nr * sizeof(union irte128))
            : get_order_from_bytes(nr * sizeof(union irte32));

    tb = __alloc_amd_iommu_tables(order);
    if ( tb )
    {
        intremap_page_order(tb) = order;
        nr = intremap_table_entries(tb, iommu);
        *inuse_map = xzalloc_array(unsigned long, BITS_TO_LONGS(nr));
        if ( *inuse_map )
            memset(tb, 0, PAGE_SIZE << order);
        else
        {
            __free_amd_iommu_tables(tb, order);
            tb = NULL;
        }
    }

    return tb;
}

bool __init iov_supports_xt(void)
{
    unsigned int apic;

    if ( !iommu_enable || !iommu_intremap )
        return false;

    if ( amd_iommu_prepare(true) )
        return false;

    for ( apic = 0; apic < nr_ioapics; apic++ )
    {
        unsigned int idx = ioapic_id_to_index(IO_APIC_ID(apic));

        if ( idx == MAX_IO_APICS )
            return false;

        if ( !find_iommu_for_device(ioapic_sbdf[idx].seg,
                                    ioapic_sbdf[idx].bdf) )
        {
            AMD_IOMMU_DEBUG("No IOMMU for IO-APIC %#x (ID %x)\n",
                            apic, IO_APIC_ID(apic));
            return false;
        }
    }

    return true;
}

int __init amd_setup_hpet_msi(struct msi_desc *msi_desc)
{
    const struct amd_iommu *iommu;
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

    iommu = find_iommu_for_device(hpet_sbdf.seg, hpet_sbdf.bdf);
    if ( !iommu )
        return -ENXIO;

    lock = get_intremap_lock(hpet_sbdf.seg, hpet_sbdf.bdf);
    spin_lock_irqsave(lock, flags);

    msi_desc->remap_index = alloc_intremap_entry(iommu, hpet_sbdf.bdf, 1);
    if ( msi_desc->remap_index >= INTREMAP_MAX_ENTRIES )
    {
        msi_desc->remap_index = -1;
        rc = -ENXIO;
    }

    spin_unlock_irqrestore(lock, flags);

    return rc;
}

static void dump_intremap_table(const struct amd_iommu *iommu,
                                union irte_cptr tbl,
                                const struct ivrs_mappings *ivrs_mapping)
{
    unsigned int count, nr;

    if ( !tbl.ptr )
        return;

    nr = intremap_table_entries(tbl.ptr, iommu);

    for ( count = 0; count < nr; count++ )
    {
        if ( iommu->ctrl.ga_en
             ? !tbl.ptr128[count].raw[0] && !tbl.ptr128[count].raw[1]
             : !tbl.ptr32[count].raw )
                continue;

        if ( ivrs_mapping )
        {
            printk("  %04x:%02x:%02x:%u:\n", iommu->seg,
                   PCI_BUS(ivrs_mapping->dte_requestor_id),
                   PCI_SLOT(ivrs_mapping->dte_requestor_id),
                   PCI_FUNC(ivrs_mapping->dte_requestor_id));
            ivrs_mapping = NULL;
        }

        if ( iommu->ctrl.ga_en )
            printk("    IRTE[%03x] %016lx_%016lx\n",
                   count, tbl.ptr128[count].raw[1], tbl.ptr128[count].raw[0]);
        else
            printk("    IRTE[%03x] %08x\n", count, tbl.ptr32[count].raw);
    }
}

static int dump_intremap_mapping(const struct amd_iommu *iommu,
                                 struct ivrs_mappings *ivrs_mapping,
                                 uint16_t unused)
{
    unsigned long flags;

    if ( !ivrs_mapping )
        return 0;

    spin_lock_irqsave(&(ivrs_mapping->intremap_lock), flags);
    dump_intremap_table(iommu, ivrs_mapping->intremap_table, ivrs_mapping);
    spin_unlock_irqrestore(&(ivrs_mapping->intremap_lock), flags);

    process_pending_softirqs();

    return 0;
}

void amd_iommu_dump_intremap_tables(unsigned char key)
{
    if ( !shared_intremap_table )
    {
        printk("--- Dumping Per-dev IOMMU Interrupt Remapping Table ---\n");

        iterate_ivrs_entries(dump_intremap_mapping);
    }
    else
    {
        unsigned long flags;

        printk("--- Dumping Shared IOMMU Interrupt Remapping Table ---\n");

        spin_lock_irqsave(&shared_intremap_lock, flags);
        dump_intremap_table(list_first_entry(&amd_iommu_head, struct amd_iommu,
                                             list),
                            shared_intremap_table, NULL);
        spin_unlock_irqrestore(&shared_intremap_lock, flags);
    }
}
