/*
 * File:    msi.c
 * Purpose: PCI Message Signaled Interrupt (MSI)
 *
 * Copyright (C) 2003-2004 Intel
 * Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/sched.h>
#include <xen/acpi.h>
#include <xen/errno.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/iocap.h>
#include <xen/keyhandler.h>
#include <xen/pfn.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/desc.h>
#include <asm/msi.h>
#include <asm/fixmap.h>
#include <asm/p2m.h>
#include <mach_apic.h>
#include <io_ports.h>
#include <public/physdev.h>
#include <xen/iommu.h>
#include <xsm/xsm.h>

static s8 __read_mostly use_msi = -1;
boolean_param("msi", use_msi);

/* bitmap indicate which fixed map is free */
DEFINE_SPINLOCK(msix_fixmap_lock);
DECLARE_BITMAP(msix_fixmap_pages, FIX_MSIX_MAX_PAGES);

static int msix_fixmap_alloc(void)
{
    int i, rc = -ENOMEM;

    spin_lock(&msix_fixmap_lock);
    for ( i = 0; i < FIX_MSIX_MAX_PAGES; i++ )
        if ( !test_bit(i, &msix_fixmap_pages) )
            break;
    if ( i == FIX_MSIX_MAX_PAGES )
        goto out;
    rc = FIX_MSIX_IO_RESERV_BASE + i;
    set_bit(i, &msix_fixmap_pages);

 out:
    spin_unlock(&msix_fixmap_lock);
    return rc;
}

static void msix_fixmap_free(int idx)
{
    spin_lock(&msix_fixmap_lock);
    if ( idx >= FIX_MSIX_IO_RESERV_BASE )
        clear_bit(idx - FIX_MSIX_IO_RESERV_BASE, &msix_fixmap_pages);
    spin_unlock(&msix_fixmap_lock);
}

static int msix_get_fixmap(struct pci_dev *dev, u64 table_paddr,
                           u64 entry_paddr)
{
    long nr_page;
    int idx;

    nr_page = (entry_paddr >> PAGE_SHIFT) - (table_paddr >> PAGE_SHIFT);

    if ( nr_page < 0 || nr_page >= MAX_MSIX_TABLE_PAGES )
        return -EINVAL;

    spin_lock(&dev->msix_table_lock);
    if ( dev->msix_table_refcnt[nr_page]++ == 0 )
    {
        idx = msix_fixmap_alloc();
        if ( idx < 0 )
        {
            dev->msix_table_refcnt[nr_page]--;
            goto out;
        }
        set_fixmap_nocache(idx, entry_paddr);
        dev->msix_table_idx[nr_page] = idx;
    }
    else
        idx = dev->msix_table_idx[nr_page];

 out:
    spin_unlock(&dev->msix_table_lock);
    return idx;
}

static void msix_put_fixmap(struct pci_dev *dev, int idx)
{
    int i;
    unsigned long start;

    spin_lock(&dev->msix_table_lock);
    for ( i = 0; i < MAX_MSIX_TABLE_PAGES; i++ )
    {
        if ( dev->msix_table_idx[i] == idx )
            break;
    }
    if ( i == MAX_MSIX_TABLE_PAGES )
        goto out;

    if ( --dev->msix_table_refcnt[i] == 0 )
    {
        start = fix_to_virt(idx);
        destroy_xen_mappings(start, start + PAGE_SIZE);
        msix_fixmap_free(idx);
        dev->msix_table_idx[i] = 0;
    }

 out:
    spin_unlock(&dev->msix_table_lock);
}

/*
 * MSI message composition
 */
void msi_compose_msg(struct irq_desc *desc, struct msi_msg *msg)
{
    unsigned dest;
    int vector = desc->arch.vector;

    if ( cpumask_empty(desc->arch.cpu_mask) ) {
        dprintk(XENLOG_ERR,"%s, compose msi message error!!\n", __func__);
        return;
    }

    if ( vector ) {
        dest = cpu_mask_to_apicid(desc->arch.cpu_mask);

        msg->address_hi = MSI_ADDR_BASE_HI;
        msg->address_lo =
            MSI_ADDR_BASE_LO |
            ((INT_DEST_MODE == 0) ?
             MSI_ADDR_DESTMODE_PHYS:
             MSI_ADDR_DESTMODE_LOGIC) |
            ((INT_DELIVERY_MODE != dest_LowestPrio) ?
             MSI_ADDR_REDIRECTION_CPU:
             MSI_ADDR_REDIRECTION_LOWPRI) |
            MSI_ADDR_DEST_ID(dest);
        msg->dest32 = dest;

        msg->data =
            MSI_DATA_TRIGGER_EDGE |
            MSI_DATA_LEVEL_ASSERT |
            ((INT_DELIVERY_MODE != dest_LowestPrio) ?
             MSI_DATA_DELIVERY_FIXED:
             MSI_DATA_DELIVERY_LOWPRI) |
            MSI_DATA_VECTOR(vector);
    }
}

static void read_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
    switch ( entry->msi_attrib.type )
    {
    case PCI_CAP_ID_MSI:
    {
        struct pci_dev *dev = entry->dev;
        int pos = entry->msi_attrib.pos;
        u16 data, seg = dev->seg;
        u8 bus = dev->bus;
        u8 slot = PCI_SLOT(dev->devfn);
        u8 func = PCI_FUNC(dev->devfn);

        msg->address_lo = pci_conf_read32(seg, bus, slot, func,
                                          msi_lower_address_reg(pos));
        if ( entry->msi_attrib.is_64 )
        {
            msg->address_hi = pci_conf_read32(seg, bus, slot, func,
                                              msi_upper_address_reg(pos));
            data = pci_conf_read16(seg, bus, slot, func,
                                   msi_data_reg(pos, 1));
        }
        else
        {
            msg->address_hi = 0;
            data = pci_conf_read16(seg, bus, slot, func,
                                   msi_data_reg(pos, 0));
        }
        msg->data = data;
        break;
    }
    case PCI_CAP_ID_MSIX:
    {
        void __iomem *base;
        base = entry->mask_base;

        msg->address_lo = readl(base + PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET);
        msg->address_hi = readl(base + PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET);
        msg->data = readl(base + PCI_MSIX_ENTRY_DATA_OFFSET);
        break;
    }
    default:
        BUG();
    }

    if ( iommu_intremap )
        iommu_read_msi_from_ire(entry, msg);
}

static void write_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
    entry->msg = *msg;

    if ( iommu_intremap )
    {
        ASSERT(msg != &entry->msg);
        iommu_update_ire_from_msi(entry, msg);
    }

    switch ( entry->msi_attrib.type )
    {
    case PCI_CAP_ID_MSI:
    {
        struct pci_dev *dev = entry->dev;
        int pos = entry->msi_attrib.pos;
        u16 seg = dev->seg;
        u8 bus = dev->bus;
        u8 slot = PCI_SLOT(dev->devfn);
        u8 func = PCI_FUNC(dev->devfn);

        pci_conf_write32(seg, bus, slot, func, msi_lower_address_reg(pos),
                         msg->address_lo);
        if ( entry->msi_attrib.is_64 )
        {
            pci_conf_write32(seg, bus, slot, func, msi_upper_address_reg(pos),
                             msg->address_hi);
            pci_conf_write16(seg, bus, slot, func, msi_data_reg(pos, 1),
                             msg->data);
        }
        else
            pci_conf_write16(seg, bus, slot, func, msi_data_reg(pos, 0),
                             msg->data);
        break;
    }
    case PCI_CAP_ID_MSIX:
    {
        void __iomem *base;
        base = entry->mask_base;

        writel(msg->address_lo,
               base + PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET);
        writel(msg->address_hi,
               base + PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET);
        writel(msg->data, base + PCI_MSIX_ENTRY_DATA_OFFSET);
        break;
    }
    default:
        BUG();
    }
}

static void set_msi_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    struct msi_msg msg;
    unsigned int dest;
    struct msi_desc *msi_desc = desc->msi_desc;

    dest = set_desc_affinity(desc, mask);
    if (dest == BAD_APICID || !msi_desc)
        return;

    ASSERT(spin_is_locked(&desc->lock));

    memset(&msg, 0, sizeof(msg));
    read_msi_msg(msi_desc, &msg);

    msg.data &= ~MSI_DATA_VECTOR_MASK;
    msg.data |= MSI_DATA_VECTOR(desc->arch.vector);
    msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
    msg.address_lo |= MSI_ADDR_DEST_ID(dest);
    msg.dest32 = dest;

    write_msi_msg(msi_desc, &msg);
}

static void msi_set_enable(struct pci_dev *dev, int enable)
{
    int pos;
    u16 control, seg = dev->seg;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSI);
    if ( pos )
    {
        control = pci_conf_read16(seg, bus, slot, func, pos + PCI_MSI_FLAGS);
        control &= ~PCI_MSI_FLAGS_ENABLE;
        if ( enable )
            control |= PCI_MSI_FLAGS_ENABLE;
        pci_conf_write16(seg, bus, slot, func, pos + PCI_MSI_FLAGS, control);
    }
}

static void msix_set_enable(struct pci_dev *dev, int enable)
{
    int pos;
    u16 control, seg = dev->seg;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSIX);
    if ( pos )
    {
        control = pci_conf_read16(seg, bus, slot, func, pos + PCI_MSIX_FLAGS);
        control &= ~PCI_MSIX_FLAGS_ENABLE;
        if ( enable )
            control |= PCI_MSIX_FLAGS_ENABLE;
        pci_conf_write16(seg, bus, slot, func, pos + PCI_MSIX_FLAGS, control);
    }
}

int msi_maskable_irq(const struct msi_desc *entry)
{
    BUG_ON(!entry);
    return entry->msi_attrib.type != PCI_CAP_ID_MSI
           || entry->msi_attrib.maskbit;
}

static void msi_set_mask_bit(struct irq_desc *desc, int flag)
{
    struct msi_desc *entry = desc->msi_desc;

    ASSERT(spin_is_locked(&desc->lock));
    BUG_ON(!entry || !entry->dev);
    switch (entry->msi_attrib.type) {
    case PCI_CAP_ID_MSI:
        if (entry->msi_attrib.maskbit) {
            int pos;
            u32 mask_bits;
            u16 seg = entry->dev->seg;
            u8 bus = entry->dev->bus;
            u8 slot = PCI_SLOT(entry->dev->devfn);
            u8 func = PCI_FUNC(entry->dev->devfn);

            pos = (long)entry->mask_base;
            mask_bits = pci_conf_read32(seg, bus, slot, func, pos);
            mask_bits &= ~(1);
            mask_bits |= flag;
            pci_conf_write32(seg, bus, slot, func, pos, mask_bits);
        }
        break;
    case PCI_CAP_ID_MSIX:
    {
        int offset = PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET;
        writel(flag, entry->mask_base + offset);
        readl(entry->mask_base + offset);
        break;
    }
    default:
        BUG();
        break;
    }
    entry->msi_attrib.masked = !!flag;
}

static int msi_get_mask_bit(const struct msi_desc *entry)
{
    switch (entry->msi_attrib.type) {
    case PCI_CAP_ID_MSI:
        if (!entry->dev || !entry->msi_attrib.maskbit)
            break;
        return pci_conf_read32(entry->dev->seg, entry->dev->bus,
                               PCI_SLOT(entry->dev->devfn),
                               PCI_FUNC(entry->dev->devfn),
                               (unsigned long)entry->mask_base) & 1;
    case PCI_CAP_ID_MSIX:
        return readl(entry->mask_base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET) & 1;
    }
    return -1;
}

static void mask_msi_irq(struct irq_desc *desc)
{
    msi_set_mask_bit(desc, 1);
}

static void unmask_msi_irq(struct irq_desc *desc)
{
    msi_set_mask_bit(desc, 0);
}

static unsigned int startup_msi_irq(struct irq_desc *desc)
{
    unmask_msi_irq(desc);
    return 0;
}

static void ack_nonmaskable_msi_irq(struct irq_desc *desc)
{
    irq_complete_move(desc);
    move_native_irq(desc);
}

static void ack_maskable_msi_irq(struct irq_desc *desc)
{
    ack_nonmaskable_msi_irq(desc);
    ack_APIC_irq(); /* ACKTYPE_NONE */
}

static void end_nonmaskable_msi_irq(struct irq_desc *desc, u8 vector)
{
    ack_APIC_irq(); /* ACKTYPE_EOI */
}

/*
 * IRQ chip for MSI PCI/PCI-X/PCI-Express devices,
 * which implement the MSI or MSI-X capability structure.
 */
static hw_irq_controller pci_msi_maskable = {
    .typename     = "PCI-MSI/-X",
    .startup      = startup_msi_irq,
    .shutdown     = mask_msi_irq,
    .enable       = unmask_msi_irq,
    .disable      = mask_msi_irq,
    .ack          = ack_maskable_msi_irq,
    .set_affinity = set_msi_affinity
};

/* As above, but without having masking capability. */
static hw_irq_controller pci_msi_nonmaskable = {
    .typename     = "PCI-MSI",
    .startup      = irq_startup_none,
    .shutdown     = irq_shutdown_none,
    .enable       = irq_enable_none,
    .disable      = irq_disable_none,
    .ack          = ack_nonmaskable_msi_irq,
    .end          = end_nonmaskable_msi_irq,
    .set_affinity = set_msi_affinity
};

static struct msi_desc* alloc_msi_entry(void)
{
    struct msi_desc *entry;

    entry = xmalloc(struct msi_desc);
    if ( !entry )
        return NULL;

    INIT_LIST_HEAD(&entry->list);
    entry->dev = NULL;
    entry->remap_index = -1;

    return entry;
}

void setup_msi_handler(struct irq_desc *desc, struct msi_desc *msidesc)
{
    desc->msi_desc = msidesc;
    desc->handler = msi_maskable_irq(msidesc) ? &pci_msi_maskable
                                              : &pci_msi_nonmaskable;
}

void setup_msi_irq(struct irq_desc *desc)
{
    struct msi_msg msg;

    msi_compose_msg(desc, &msg);
    write_msi_msg(desc->msi_desc, &msg);
}

int msi_free_irq(struct msi_desc *entry)
{
    destroy_irq(entry->irq);
    if ( entry->msi_attrib.type == PCI_CAP_ID_MSIX )
    {
        unsigned long start;
        start = (unsigned long)entry->mask_base & ~(PAGE_SIZE - 1);
        msix_put_fixmap(entry->dev, virt_to_fix(start));
    }

    /* Free the unused IRTE if intr remap enabled */
    if ( iommu_intremap )
        iommu_update_ire_from_msi(entry, NULL);

    list_del(&entry->list);
    xfree(entry);
    return 0;
}

static struct msi_desc *find_msi_entry(struct pci_dev *dev,
                                       int irq, int cap_id)
{
    struct msi_desc *entry;

    list_for_each_entry( entry, &dev->msi_list, list )
    {
        if ( entry->msi_attrib.type == cap_id &&
             (irq == -1 || entry->irq == irq) )
            return entry;
    }

    return NULL;
}

/**
 * msi_capability_init - configure device's MSI capability structure
 * @dev: pointer to the pci_dev data structure of MSI device function
 *
 * Setup the MSI capability structure of device function with a single
 * MSI irq, regardless of device function is capable of handling
 * multiple messages. A return of zero indicates the successful setup
 * of an entry zero with the new MSI irq or non-zero for otherwise.
 **/
static int msi_capability_init(struct pci_dev *dev,
                               int irq,
                               struct msi_desc **desc)
{
    struct msi_desc *entry;
    int pos;
    u16 control, seg = dev->seg;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    ASSERT(spin_is_locked(&pcidevs_lock));
    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSI);
    control = pci_conf_read16(seg, bus, slot, func, msi_control_reg(pos));
    /* MSI Entry Initialization */
    msi_set_enable(dev, 0); /* Ensure msi is disabled as I set it up */

    entry = alloc_msi_entry();
    if ( !entry )
        return -ENOMEM;

    entry->msi_attrib.type = PCI_CAP_ID_MSI;
    entry->msi_attrib.is_64 = is_64bit_address(control);
    entry->msi_attrib.entry_nr = 0;
    entry->msi_attrib.maskbit = is_mask_bit_support(control);
    entry->msi_attrib.masked = 1;
    entry->msi_attrib.pos = pos;
    entry->irq = irq;
    if ( is_mask_bit_support(control) )
        entry->mask_base = (void __iomem *)(long)msi_mask_bits_reg(pos,
                                                                   is_64bit_address(control));
    entry->dev = dev;
    if ( entry->msi_attrib.maskbit )
    {
        unsigned int maskbits, temp;
        /* All MSIs are unmasked by default, Mask them all */
        maskbits = pci_conf_read32(seg, bus, slot, func,
                                   msi_mask_bits_reg(pos, is_64bit_address(control)));
        temp = (1 << multi_msi_capable(control));
        temp = ((temp - 1) & ~temp);
        maskbits |= temp;
        pci_conf_write32(seg, bus, slot, func,
                         msi_mask_bits_reg(pos, is_64bit_address(control)),
                         maskbits);
    }
    list_add_tail(&entry->list, &dev->msi_list);

    *desc = entry;
    /* Restore the original MSI enabled bits  */
    pci_conf_write16(seg, bus, slot, func, msi_control_reg(pos), control);

    return 0;
}

static u64 read_pci_mem_bar(u16 seg, u8 bus, u8 slot, u8 func, u8 bir, int vf)
{
    u8 limit;
    u32 addr, base = PCI_BASE_ADDRESS_0, disp = 0;

    if ( vf >= 0 )
    {
        struct pci_dev *pdev = pci_get_pdev(seg, bus, PCI_DEVFN(slot, func));
        unsigned int pos = pci_find_ext_capability(seg, bus,
                                                   PCI_DEVFN(slot, func),
                                                   PCI_EXT_CAP_ID_SRIOV);
        u16 ctrl = pci_conf_read16(seg, bus, slot, func, pos + PCI_SRIOV_CTRL);
        u16 num_vf = pci_conf_read16(seg, bus, slot, func,
                                     pos + PCI_SRIOV_NUM_VF);
        u16 offset = pci_conf_read16(seg, bus, slot, func,
                                     pos + PCI_SRIOV_VF_OFFSET);
        u16 stride = pci_conf_read16(seg, bus, slot, func,
                                     pos + PCI_SRIOV_VF_STRIDE);

        if ( !pdev || !pos ||
             !(ctrl & PCI_SRIOV_CTRL_VFE) ||
             !(ctrl & PCI_SRIOV_CTRL_MSE) ||
             !num_vf || !offset || (num_vf > 1 && !stride) ||
             bir >= PCI_SRIOV_NUM_BARS ||
             !pdev->vf_rlen[bir] )
            return 0;
        base = pos + PCI_SRIOV_BAR;
        vf -= PCI_BDF(bus, slot, func) + offset;
        if ( vf < 0 || (vf && vf % stride) )
            return 0;
        if ( stride )
        {
            if ( vf % stride )
                return 0;
            vf /= stride;
        }
        if ( vf >= num_vf )
            return 0;
        BUILD_BUG_ON(ARRAY_SIZE(pdev->vf_rlen) != PCI_SRIOV_NUM_BARS);
        disp = vf * pdev->vf_rlen[bir];
        limit = PCI_SRIOV_NUM_BARS;
    }
    else switch ( pci_conf_read8(seg, bus, slot, func,
                                 PCI_HEADER_TYPE) & 0x7f )
    {
    case PCI_HEADER_TYPE_NORMAL:
        limit = 6;
        break;
    case PCI_HEADER_TYPE_BRIDGE:
        limit = 2;
        break;
    case PCI_HEADER_TYPE_CARDBUS:
        limit = 1;
        break;
    default:
        return 0;
    }

    if ( bir >= limit )
        return 0;
    addr = pci_conf_read32(seg, bus, slot, func, base + bir * 4);
    if ( (addr & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO )
        return 0;
    if ( (addr & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64 )
    {
        addr &= PCI_BASE_ADDRESS_MEM_MASK;
        if ( ++bir >= limit )
            return 0;
        return addr + disp +
               ((u64)pci_conf_read32(seg, bus, slot, func,
                                     base + bir * 4) << 32);
    }
    return (addr & PCI_BASE_ADDRESS_MEM_MASK) + disp;
}

/**
 * msix_capability_init - configure device's MSI-X capability
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of struct msix_entry entries
 * @nvec: number of @entries
 *
 * Setup the MSI-X capability structure of device function with the requested
 * number MSI-X irqs. A return of zero indicates the successful setup of
 * requested MSI-X entries with allocated irqs or non-zero for otherwise.
 **/
static int msix_capability_init(struct pci_dev *dev,
                                struct msi_info *msi,
                                struct msi_desc **desc,
                                unsigned int nr_entries)
{
    struct msi_desc *entry = NULL;
    int pos, vf;
    u16 control;
    u64 table_paddr;
    u32 table_offset;
    u8 bir, pbus, pslot, pfunc;
    u16 seg = dev->seg;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    ASSERT(spin_is_locked(&pcidevs_lock));

    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSIX);
    control = pci_conf_read16(seg, bus, slot, func, msix_control_reg(pos));
    msix_set_enable(dev, 0);/* Ensure msix is disabled as I set it up */

    if ( desc )
    {
        entry = alloc_msi_entry();
        if ( !entry )
            return -ENOMEM;
        ASSERT(msi);
    }

    /* Locate MSI-X table region */
    table_offset = pci_conf_read32(seg, bus, slot, func,
                                   msix_table_offset_reg(pos));
    bir = (u8)(table_offset & PCI_MSIX_BIRMASK);
    table_offset &= ~PCI_MSIX_BIRMASK;

    if ( !dev->info.is_virtfn )
    {
        pbus = bus;
        pslot = slot;
        pfunc = func;
        vf = -1;
    }
    else
    {
        pbus = dev->info.physfn.bus;
        pslot = PCI_SLOT(dev->info.physfn.devfn);
        pfunc = PCI_FUNC(dev->info.physfn.devfn);
        vf = PCI_BDF2(dev->bus, dev->devfn);
    }

    table_paddr = read_pci_mem_bar(seg, pbus, pslot, pfunc, bir, vf);
    WARN_ON(msi && msi->table_base != table_paddr);
    if ( !table_paddr )
    {
        if ( !msi || !msi->table_base )
        {
            xfree(entry);
            return -ENXIO;
        }
        table_paddr = msi->table_base;
    }
    table_paddr += table_offset;

    if ( !dev->msix_used_entries )
    {
        u64 pba_paddr;
        u32 pba_offset;

        dev->msix_nr_entries = nr_entries;
        dev->msix_table.first = PFN_DOWN(table_paddr);
        dev->msix_table.last = PFN_DOWN(table_paddr +
                                        nr_entries * PCI_MSIX_ENTRY_SIZE - 1);
        WARN_ON(rangeset_overlaps_range(mmio_ro_ranges, dev->msix_table.first,
                                        dev->msix_table.last));

        pba_offset = pci_conf_read32(seg, bus, slot, func,
                                     msix_pba_offset_reg(pos));
        bir = (u8)(pba_offset & PCI_MSIX_BIRMASK);
        pba_paddr = read_pci_mem_bar(seg, pbus, pslot, pfunc, bir, vf);
        WARN_ON(!pba_paddr);
        pba_paddr += pba_offset & ~PCI_MSIX_BIRMASK;

        dev->msix_pba.first = PFN_DOWN(pba_paddr);
        dev->msix_pba.last = PFN_DOWN(pba_paddr +
                                      BITS_TO_LONGS(nr_entries) - 1);
        WARN_ON(rangeset_overlaps_range(mmio_ro_ranges, dev->msix_pba.first,
                                        dev->msix_pba.last));
    }

    if ( entry )
    {
        /* Map MSI-X table region */
        u64 entry_paddr = table_paddr + msi->entry_nr * PCI_MSIX_ENTRY_SIZE;
        int idx = msix_get_fixmap(dev, table_paddr, entry_paddr);
        void __iomem *base;

        if ( idx < 0 )
        {
            xfree(entry);
            return idx;
        }
        base = (void *)(fix_to_virt(idx) +
                        ((unsigned long)entry_paddr & (PAGE_SIZE - 1)));

        /* Mask interrupt here */
        writel(1, base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

        entry->msi_attrib.type = PCI_CAP_ID_MSIX;
        entry->msi_attrib.is_64 = 1;
        entry->msi_attrib.entry_nr = msi->entry_nr;
        entry->msi_attrib.maskbit = 1;
        entry->msi_attrib.masked = 1;
        entry->msi_attrib.pos = pos;
        entry->irq = msi->irq;
        entry->dev = dev;
        entry->mask_base = base;

        list_add_tail(&entry->list, &dev->msi_list);
        *desc = entry;
    }

    if ( !dev->msix_used_entries )
    {
        if ( rangeset_add_range(mmio_ro_ranges, dev->msix_table.first,
                                dev->msix_table.last) )
            WARN();
        if ( rangeset_add_range(mmio_ro_ranges, dev->msix_pba.first,
                                dev->msix_pba.last) )
            WARN();

        if ( dev->domain )
            p2m_change_entry_type_global(dev->domain,
                                         p2m_mmio_direct, p2m_mmio_direct);
        if ( desc && (!dev->domain || !paging_mode_translate(dev->domain)) )
        {
            struct domain *d = dev->domain;

            if ( !d )
                for_each_domain(d)
                    if ( !paging_mode_translate(d) &&
                         (iomem_access_permitted(d, dev->msix_table.first,
                                                 dev->msix_table.last) ||
                          iomem_access_permitted(d, dev->msix_pba.first,
                                                 dev->msix_pba.last)) )
                        break;
            if ( d )
            {
                if ( !IS_PRIV(d) && dev->msix_warned != d->domain_id )
                {
                    dev->msix_warned = d->domain_id;
                    printk(XENLOG_ERR
                           "Potentially insecure use of MSI-X on %04x:%02x:%02x.%u by Dom%d\n",
                           seg, bus, slot, func, d->domain_id);
                }
                /* XXX How to deal with existing mappings? */
            }
        }
    }
    WARN_ON(dev->msix_nr_entries != nr_entries);
    WARN_ON(dev->msix_table.first != (table_paddr >> PAGE_SHIFT));
    ++dev->msix_used_entries;

    /* Restore MSI-X enabled bits */
    pci_conf_write16(seg, bus, slot, func, msix_control_reg(pos), control);

    return 0;
}

/**
 * pci_enable_msi - configure device's MSI capability structure
 * @dev: pointer to the pci_dev data structure of MSI device function
 *
 * Setup the MSI capability structure of device function with
 * a single MSI irq upon its software driver call to request for
 * MSI mode enabled on its hardware device function. A return of zero
 * indicates the successful setup of an entry zero with the new MSI
 * irq or non-zero for otherwise.
 **/

static int __pci_enable_msi(struct msi_info *msi, struct msi_desc **desc)
{
    int status;
    struct pci_dev *pdev;
    struct msi_desc *old_desc;

    ASSERT(spin_is_locked(&pcidevs_lock));
    pdev = pci_get_pdev(msi->seg, msi->bus, msi->devfn);
    if ( !pdev )
        return -ENODEV;

    old_desc = find_msi_entry(pdev, msi->irq, PCI_CAP_ID_MSI);
    if ( old_desc )
    {
        dprintk(XENLOG_WARNING, "irq %d has already mapped to MSI on "
                "device %04x:%02x:%02x.%01x\n",
                msi->irq, msi->seg, msi->bus,
                PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        *desc = old_desc;
        return 0;
    }

    old_desc = find_msi_entry(pdev, -1, PCI_CAP_ID_MSIX);
    if ( old_desc )
    {
        dprintk(XENLOG_WARNING, "MSI-X is already in use on "
                "device %04x:%02x:%02x.%01x\n", msi->seg, msi->bus,
                PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        pci_disable_msi(old_desc);
    }

    status = msi_capability_init(pdev, msi->irq, desc);
    return status;
}

static void __pci_disable_msi(struct msi_desc *entry)
{
    struct pci_dev *dev;

    dev = entry->dev;
    msi_set_enable(dev, 0);

    BUG_ON(list_empty(&dev->msi_list));

}

/**
 * pci_enable_msix - configure device's MSI-X capability structure
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of MSI-X entries
 * @nvec: number of MSI-X irqs requested for allocation by device driver
 *
 * Setup the MSI-X capability structure of device function with the number
 * of requested irqs upon its software driver call to request for
 * MSI-X mode enabled on its hardware device function. A return of zero
 * indicates the successful configuration of MSI-X capability structure
 * with new allocated MSI-X irqs. A return of < 0 indicates a failure.
 * Or a return of > 0 indicates that driver request is exceeding the number
 * of irqs available. Driver should use the returned value to re-send
 * its request.
 **/
static int __pci_enable_msix(struct msi_info *msi, struct msi_desc **desc)
{
    int status, pos, nr_entries;
    struct pci_dev *pdev;
    u16 control;
    u8 slot = PCI_SLOT(msi->devfn);
    u8 func = PCI_FUNC(msi->devfn);
    struct msi_desc *old_desc;

    ASSERT(spin_is_locked(&pcidevs_lock));
    pdev = pci_get_pdev(msi->seg, msi->bus, msi->devfn);
    if ( !pdev )
        return -ENODEV;

    pos = pci_find_cap_offset(msi->seg, msi->bus, slot, func, PCI_CAP_ID_MSIX);
    control = pci_conf_read16(msi->seg, msi->bus, slot, func,
                              msix_control_reg(pos));
    nr_entries = multi_msix_capable(control);
    if (msi->entry_nr >= nr_entries)
        return -EINVAL;

    old_desc = find_msi_entry(pdev, msi->irq, PCI_CAP_ID_MSIX);
    if ( old_desc )
    {
        dprintk(XENLOG_WARNING, "irq %d has already mapped to MSIX on "
                "device %04x:%02x:%02x.%01x\n",
                msi->irq, msi->seg, msi->bus,
                PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        *desc = old_desc;
        return 0;
    }

    old_desc = find_msi_entry(pdev, -1, PCI_CAP_ID_MSI);
    if ( old_desc )
    {
        dprintk(XENLOG_WARNING, "MSI is already in use on "
                "device %04x:%02x:%02x.%01x\n", msi->seg, msi->bus,
                PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        pci_disable_msi(old_desc);

    }

    status = msix_capability_init(pdev, msi, desc, nr_entries);
    return status;
}

static void _pci_cleanup_msix(struct pci_dev *dev)
{
    if ( !--dev->msix_used_entries )
    {
        if ( rangeset_remove_range(mmio_ro_ranges, dev->msix_table.first,
                                   dev->msix_table.last) )
            WARN();
        if ( rangeset_remove_range(mmio_ro_ranges, dev->msix_pba.first,
                                   dev->msix_pba.last) )
            WARN();
    }
}

static void __pci_disable_msix(struct msi_desc *entry)
{
    struct pci_dev *dev;
    int pos;
    u16 control, seg;
    u8 bus, slot, func;

    dev = entry->dev;
    seg = dev->seg;
    bus = dev->bus;
    slot = PCI_SLOT(dev->devfn);
    func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSIX);
    control = pci_conf_read16(seg, bus, slot, func, msix_control_reg(pos));
    msix_set_enable(dev, 0);

    BUG_ON(list_empty(&dev->msi_list));

    writel(1, entry->mask_base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

    pci_conf_write16(seg, bus, slot, func, msix_control_reg(pos), control);

    _pci_cleanup_msix(dev);
}

int pci_prepare_msix(u16 seg, u8 bus, u8 devfn, bool_t off)
{
    int rc;
    struct pci_dev *pdev;
    u8 slot = PCI_SLOT(devfn), func = PCI_FUNC(devfn);
    unsigned int pos = pci_find_cap_offset(seg, bus, slot, func,
                                           PCI_CAP_ID_MSIX);

    if ( !use_msi )
        return 0;

    if ( !pos )
        return -ENODEV;

    spin_lock(&pcidevs_lock);
    pdev = pci_get_pdev(seg, bus, devfn);
    if ( !pdev )
        rc = -ENODEV;
    else if ( pdev->msix_used_entries != !!off )
        rc = -EBUSY;
    else if ( off )
    {
        _pci_cleanup_msix(pdev);
        rc = 0;
    }
    else
    {
        u16 control = pci_conf_read16(seg, bus, slot, func,
                                      msix_control_reg(pos));

        rc = msix_capability_init(pdev, NULL, NULL,
                                  multi_msix_capable(control));
    }
    spin_unlock(&pcidevs_lock);

    return rc;
}

/*
 * Notice: only construct the msi_desc
 * no change to irq_desc here, and the interrupt is masked
 */
int pci_enable_msi(struct msi_info *msi, struct msi_desc **desc)
{
    ASSERT(spin_is_locked(&pcidevs_lock));

    if ( !use_msi )
        return -EPERM;

    return  msi->table_base ? __pci_enable_msix(msi, desc) :
        __pci_enable_msi(msi, desc);
}

/*
 * Device only, no irq_desc
 */
void pci_disable_msi(struct msi_desc *msi_desc)
{
    if ( msi_desc->msi_attrib.type == PCI_CAP_ID_MSI )
        __pci_disable_msi(msi_desc);
    else if ( msi_desc->msi_attrib.type == PCI_CAP_ID_MSIX )
        __pci_disable_msix(msi_desc);
}

static void msi_free_irqs(struct pci_dev* dev)
{
    struct msi_desc *entry, *tmp;

    list_for_each_entry_safe( entry, tmp, &dev->msi_list, list )
    {
        pci_disable_msi(entry);
        msi_free_irq(entry);
    }
}

void pci_cleanup_msi(struct pci_dev *pdev)
{
    /* Disable MSI and/or MSI-X */
    msi_set_enable(pdev, 0);
    msix_set_enable(pdev, 0);
    msi_free_irqs(pdev);
}

int pci_restore_msi_state(struct pci_dev *pdev)
{
    unsigned long flags;
    int irq;
    int ret;
    struct msi_desc *entry, *tmp;
    struct irq_desc *desc;
    struct msi_msg msg;

    ASSERT(spin_is_locked(&pcidevs_lock));

    if ( !use_msi )
        return -EOPNOTSUPP;

    if ( !pdev )
        return -EINVAL;

    ret = xsm_resource_setup_pci((pdev->seg << 16) | (pdev->bus << 8) | pdev->devfn);
    if ( ret )
        return ret;

    list_for_each_entry_safe( entry, tmp, &pdev->msi_list, list )
    {
        irq = entry->irq;
        desc = &irq_desc[irq];

        spin_lock_irqsave(&desc->lock, flags);

        ASSERT(desc->msi_desc == entry);

        if (desc->msi_desc != entry)
        {
            dprintk(XENLOG_ERR,
                    "Restore MSI for dev %04x:%02x:%02x:%x not set before?\n",
                    pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                    PCI_FUNC(pdev->devfn));
            spin_unlock_irqrestore(&desc->lock, flags);
            return -EINVAL;
        }

        if ( entry->msi_attrib.type == PCI_CAP_ID_MSI )
            msi_set_enable(pdev, 0);
        else if ( entry->msi_attrib.type == PCI_CAP_ID_MSIX )
            msix_set_enable(pdev, 0);

        msg = entry->msg;
        write_msi_msg(entry, &msg);

        msi_set_mask_bit(desc, entry->msi_attrib.masked);

        if ( entry->msi_attrib.type == PCI_CAP_ID_MSI )
            msi_set_enable(pdev, 1);
        else if ( entry->msi_attrib.type == PCI_CAP_ID_MSIX )
            msix_set_enable(pdev, 1);

        spin_unlock_irqrestore(&desc->lock, flags);
    }

    return 0;
}

unsigned int pci_msix_get_table_len(struct pci_dev *pdev)
{
    int pos;
    u16 control, seg = pdev->seg;
    u8 bus, slot, func;
    unsigned int len;

    bus = pdev->bus;
    slot = PCI_SLOT(pdev->devfn);
    func = PCI_FUNC(pdev->devfn);

    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSIX);
    if ( !pos || !use_msi )
        return 0;

    control = pci_conf_read16(seg, bus, slot, func, msix_control_reg(pos));
    len = msix_table_size(control) * PCI_MSIX_ENTRY_SIZE;

    return len;
}

static void dump_msi(unsigned char key)
{
    unsigned int irq;

    printk("PCI-MSI interrupt information:\n");

    for ( irq = 0; irq < nr_irqs; irq++ )
    {
        struct irq_desc *desc = irq_to_desc(irq);
        const struct msi_desc *entry;
        u32 addr, data, dest32;
        int mask;
        struct msi_attrib attr;
        unsigned long flags;
        char type;

        if ( !irq_desc_initialized(desc) )
            continue;

        spin_lock_irqsave(&desc->lock, flags);

        entry = desc->msi_desc;
        if ( !entry )
        {
            spin_unlock_irqrestore(&desc->lock, flags);
            continue;
        }

        switch ( entry->msi_attrib.type )
        {
        case PCI_CAP_ID_MSI: type = ' '; break;
        case PCI_CAP_ID_MSIX: type = 'X'; break;
        default: type = '?'; break;
        }

        data = entry->msg.data;
        addr = entry->msg.address_lo;
        dest32 = entry->msg.dest32;
        attr = entry->msi_attrib;
        mask = msi_get_mask_bit(entry);

        spin_unlock_irqrestore(&desc->lock, flags);

        printk(" MSI%c %4u vec=%02x%7s%6s%3sassert%5s%7s"
               " dest=%08x mask=%d/%d/%d\n",
               type, irq,
               (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT,
               data & MSI_DATA_DELIVERY_LOWPRI ? "lowest" : "fixed",
               data & MSI_DATA_TRIGGER_LEVEL ? "level" : "edge",
               data & MSI_DATA_LEVEL_ASSERT ? "" : "de",
               addr & MSI_ADDR_DESTMODE_LOGIC ? "log" : "phys",
               addr & MSI_ADDR_REDIRECTION_LOWPRI ? "lowest" : "cpu",
               dest32, attr.maskbit, attr.masked, mask);
    }
}

static struct keyhandler dump_msi_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_msi,
    .desc = "dump MSI state"
};

static int __init msi_setup_keyhandler(void)
{
    if ( use_msi < 0 )
        use_msi = !(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_MSI);

    register_keyhandler('M', &dump_msi_keyhandler);
    return 0;
}
__initcall(msi_setup_keyhandler);
