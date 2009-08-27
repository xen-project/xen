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
#include <xen/keyhandler.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/desc.h>
#include <asm/msi.h>
#include <asm/fixmap.h>
#include <mach_apic.h>
#include <io_ports.h>
#include <public/physdev.h>
#include <xen/iommu.h>

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

static int msix_get_fixmap(struct pci_dev *dev, unsigned long table_paddr,
                           unsigned long entry_paddr)
{
    int nr_page, idx;

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
void msi_compose_msg(struct pci_dev *pdev, int irq,
                            struct msi_msg *msg)
{
    unsigned dest;
    cpumask_t domain;
    struct irq_cfg *cfg = irq_cfg(irq);
    int vector = cfg->vector;
    domain = cfg->domain;

    if ( cpus_empty( domain ) ) {
        dprintk(XENLOG_ERR,"%s, compose msi message error!!\n", __func__);
	    return;
    }

    if ( vector ) {

        dest = cpu_mask_to_apicid(domain);

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
        u16 data;
        u8 bus = dev->bus;
        u8 slot = PCI_SLOT(dev->devfn);
        u8 func = PCI_FUNC(dev->devfn);

        msg->address_lo = pci_conf_read32(bus, slot, func,
                                          msi_lower_address_reg(pos));
        if ( entry->msi_attrib.is_64 )
        {
            msg->address_hi = pci_conf_read32(bus, slot, func,
                                              msi_upper_address_reg(pos));
            data = pci_conf_read16(bus, slot, func, msi_data_reg(pos, 1));
        }
        else
        {
            msg->address_hi = 0;
            data = pci_conf_read16(bus, slot, func, msi_data_reg(pos, 0));
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

    if ( iommu_enabled )
        iommu_read_msi_from_ire(entry, msg);
}

static int set_irq_msi(struct msi_desc *entry)
{
    if ( entry->irq >= nr_irqs )
    {
        dprintk(XENLOG_ERR, "Trying to install msi data for irq %d\n",
                entry->irq);
        return -EINVAL;
    }

    irq_desc[entry->irq].msi_desc = entry;
    return 0;
}

static void write_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
    if ( iommu_enabled )
        iommu_update_ire_from_msi(entry, msg);

    switch ( entry->msi_attrib.type )
    {
    case PCI_CAP_ID_MSI:
    {
        struct pci_dev *dev = entry->dev;
        int pos = entry->msi_attrib.pos;
        u8 bus = dev->bus;
        u8 slot = PCI_SLOT(dev->devfn);
        u8 func = PCI_FUNC(dev->devfn);

        pci_conf_write32(bus, slot, func, msi_lower_address_reg(pos),
                         msg->address_lo);
        if ( entry->msi_attrib.is_64 )
        {
            pci_conf_write32(bus, slot, func, msi_upper_address_reg(pos),
                             msg->address_hi);
            pci_conf_write16(bus, slot, func, msi_data_reg(pos, 1),
                             msg->data);
        }
        else
            pci_conf_write16(bus, slot, func, msi_data_reg(pos, 0),
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
    entry->msg = *msg;
}

void set_msi_affinity(unsigned int irq, cpumask_t mask)
{
    struct msi_msg msg;
    unsigned int dest;
    struct irq_desc *desc = irq_to_desc(irq);
    struct msi_desc *msi_desc = desc->msi_desc;
    struct irq_cfg *cfg = desc->chip_data;

    dest = set_desc_affinity(desc, mask);
    if (dest == BAD_APICID || !msi_desc)
        return;

    ASSERT(spin_is_locked(&desc->lock));

    memset(&msg, 0, sizeof(msg));
    read_msi_msg(msi_desc, &msg);

    msg.data &= ~MSI_DATA_VECTOR_MASK;
    msg.data |= MSI_DATA_VECTOR(cfg->vector);
    cpus_and(mask, mask, cpu_online_map);
    if ( cpus_empty(mask) )
        mask = TARGET_CPUS;
    dest = cpu_mask_to_apicid(mask);

    if ( !desc )
        return;

    ASSERT(spin_is_locked(&desc->lock));
    read_msi_msg(msi_desc, &msg);

    msg.data &= ~MSI_DATA_VECTOR_MASK;
    msg.data |= MSI_DATA_VECTOR(cfg->vector);

    msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
    msg.address_lo |= MSI_ADDR_DEST_ID(dest);

    write_msi_msg(msi_desc, &msg);
}

static void msi_set_enable(struct pci_dev *dev, int enable)
{
    int pos;
    u16 control;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSI);
    if ( pos )
    {
        control = pci_conf_read16(bus, slot, func, pos + PCI_MSI_FLAGS);
        control &= ~PCI_MSI_FLAGS_ENABLE;
        if ( enable )
            control |= PCI_MSI_FLAGS_ENABLE;
        pci_conf_write16(bus, slot, func, pos + PCI_MSI_FLAGS, control);
    }
}

static void msix_set_enable(struct pci_dev *dev, int enable)
{
    int pos;
    u16 control;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSIX);
    if ( pos )
    {
        control = pci_conf_read16(bus, slot, func, pos + PCI_MSIX_FLAGS);
        control &= ~PCI_MSIX_FLAGS_ENABLE;
        if ( enable )
            control |= PCI_MSIX_FLAGS_ENABLE;
        pci_conf_write16(bus, slot, func, pos + PCI_MSIX_FLAGS, control);
    }
}

static void msix_flush_writes(unsigned int irq)
{
    struct msi_desc *entry = irq_desc[irq].msi_desc;

    BUG_ON(!entry || !entry->dev);
    switch (entry->msi_attrib.type) {
    case PCI_CAP_ID_MSI:
        /* nothing to do */
        break;
    case PCI_CAP_ID_MSIX:
    {
        int offset = PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET;
        readl(entry->mask_base + offset);
        break;
    }
    default:
        BUG();
        break;
    }
}

int msi_maskable_irq(const struct msi_desc *entry)
{
    BUG_ON(!entry);
    return entry->msi_attrib.type != PCI_CAP_ID_MSI
           || entry->msi_attrib.maskbit;
}

static void msi_set_mask_bit(unsigned int irq, int flag)
{
    struct msi_desc *entry = irq_desc[irq].msi_desc;

    ASSERT(spin_is_locked(&irq_desc[irq].lock));
    BUG_ON(!entry || !entry->dev);
    switch (entry->msi_attrib.type) {
    case PCI_CAP_ID_MSI:
        if (entry->msi_attrib.maskbit) {
            int pos;
            u32 mask_bits;
            u8 bus = entry->dev->bus;
            u8 slot = PCI_SLOT(entry->dev->devfn);
            u8 func = PCI_FUNC(entry->dev->devfn);

            pos = (long)entry->mask_base;
            mask_bits = pci_conf_read32(bus, slot, func, pos);
            mask_bits &= ~(1);
            mask_bits |= flag;
            pci_conf_write32(bus, slot, func, pos, mask_bits);
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

void mask_msi_irq(unsigned int irq)
{
    msi_set_mask_bit(irq, 1);
    msix_flush_writes(irq);
}

void unmask_msi_irq(unsigned int irq)
{
    msi_set_mask_bit(irq, 0);
    msix_flush_writes(irq);
}

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

int setup_msi_irq(struct pci_dev *dev, struct msi_desc *msidesc, int irq)
{
    struct msi_msg msg;

    msi_compose_msg(dev, irq, &msg);
    set_irq_msi(msidesc);
    write_msi_msg(irq_desc[irq].msi_desc, &msg);

    return 0;
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
    u16 control;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    ASSERT(spin_is_locked(&pcidevs_lock));
    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSI);
    control = pci_conf_read16(bus, slot, func, msi_control_reg(pos));
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
        maskbits = pci_conf_read32(bus, slot, func,
                                   msi_mask_bits_reg(pos, is_64bit_address(control)));
        temp = (1 << multi_msi_capable(control));
        temp = ((temp - 1) & ~temp);
        maskbits |= temp;
        pci_conf_write32(bus, slot, func,
                         msi_mask_bits_reg(pos, is_64bit_address(control)),
                         maskbits);
    }
    list_add_tail(&entry->list, &dev->msi_list);

    *desc = entry;
    /* Restore the original MSI enabled bits  */
    pci_conf_write16(bus, slot, func, msi_control_reg(pos), control);

    return 0;
}

/**
 * msix_capability_init - configure device's MSI-X capability
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of struct msix_entry entries
 * @nvec: number of @entries
 *
 * Setup the MSI-X capability structure of device function with a
 * single MSI-X irq. A return of zero indicates the successful setup of
 * requested MSI-X entries with allocated irqs or non-zero for otherwise.
 **/
static int msix_capability_init(struct pci_dev *dev,
                                struct msi_info *msi,
                                struct msi_desc **desc)
{
    struct msi_desc *entry;
    int pos;
    u16 control;
    unsigned long table_paddr, entry_paddr;
    u32 table_offset, entry_offset;
    u8 bir;
    void __iomem *base;
    int idx;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(desc);

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSIX);
    control = pci_conf_read16(bus, slot, func, msix_control_reg(pos));
    msix_set_enable(dev, 0);/* Ensure msix is disabled as I set it up */

    /* MSI-X Table Initialization */
    entry = alloc_msi_entry();
    if ( !entry )
        return -ENOMEM;

    /* Request & Map MSI-X table region */
    table_offset = pci_conf_read32(bus, slot, func, msix_table_offset_reg(pos));
    bir = (u8)(table_offset & PCI_MSIX_FLAGS_BIRMASK);
    table_offset &= ~PCI_MSIX_FLAGS_BIRMASK;
    entry_offset = msi->entry_nr * PCI_MSIX_ENTRY_SIZE;

    table_paddr = msi->table_base + table_offset;
    entry_paddr = table_paddr + entry_offset;
    idx = msix_get_fixmap(dev, table_paddr, entry_paddr);
    if ( idx < 0 )
    {
        xfree(entry);
        return idx;
    }
    base = (void *)(fix_to_virt(idx) + (entry_paddr & ((1UL << PAGE_SHIFT) - 1)));

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

    /* Mask interrupt here */
    writel(1, entry->mask_base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

    *desc = entry;
    /* Restore MSI-X enabled bits */
    pci_conf_write16(bus, slot, func, msix_control_reg(pos), control);

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

    ASSERT(spin_is_locked(&pcidevs_lock));
    pdev = pci_get_pdev(msi->bus, msi->devfn);
    if ( !pdev )
        return -ENODEV;

    if ( find_msi_entry(pdev, msi->irq, PCI_CAP_ID_MSI) )
    {
        dprintk(XENLOG_WARNING, "irq %d has already mapped to MSI on "
                "device %02x:%02x.%01x.\n", msi->irq, msi->bus,
                PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        return 0;
    }

    status = msi_capability_init(pdev, msi->irq, desc);
    return status;
}

static void __pci_disable_msi(struct msi_desc *entry)
{
    struct pci_dev *dev;
    int pos;
    u16 control;
    u8 bus, slot, func;

    dev = entry->dev;
    bus = dev->bus;
    slot = PCI_SLOT(dev->devfn);
    func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSI);
    control = pci_conf_read16(bus, slot, func, msi_control_reg(pos));
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

    ASSERT(spin_is_locked(&pcidevs_lock));
    pdev = pci_get_pdev(msi->bus, msi->devfn);
    if ( !pdev )
        return -ENODEV;

    pos = pci_find_cap_offset(msi->bus, slot, func, PCI_CAP_ID_MSIX);
    control = pci_conf_read16(msi->bus, slot, func, msi_control_reg(pos));
    nr_entries = multi_msix_capable(control);
    if (msi->entry_nr >= nr_entries)
        return -EINVAL;

    if ( find_msi_entry(pdev, msi->irq, PCI_CAP_ID_MSIX) )
    {
        dprintk(XENLOG_WARNING, "irq %d has already mapped to MSIX on "
                "device %02x:%02x.%01x.\n", msi->irq, msi->bus,
                PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        return 0;
    }

    status = msix_capability_init(pdev, msi, desc);
    return status;
}

static void __pci_disable_msix(struct msi_desc *entry)
{
    struct pci_dev *dev;
    int pos;
    u16 control;
    u8 bus, slot, func;

    dev = entry->dev;
    bus = dev->bus;
    slot = PCI_SLOT(dev->devfn);
    func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSIX);
    control = pci_conf_read16(bus, slot, func, msix_control_reg(pos));
    msix_set_enable(dev, 0);

    BUG_ON(list_empty(&dev->msi_list));

    writel(1, entry->mask_base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

    pci_conf_write16(bus, slot, func, msix_control_reg(pos), control);
}

/*
 * Notice: only construct the msi_desc
 * no change to irq_desc here, and the interrupt is masked
 */
int pci_enable_msi(struct msi_info *msi, struct msi_desc **desc)
{
    ASSERT(spin_is_locked(&pcidevs_lock));

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
    struct msi_desc *entry, *tmp;
    struct irq_desc *desc;

    ASSERT(spin_is_locked(&pcidevs_lock));

    if (!pdev)
        return -EINVAL;

    list_for_each_entry_safe( entry, tmp, &pdev->msi_list, list )
    {
        irq = entry->irq;
        desc = &irq_desc[irq];

        spin_lock_irqsave(&desc->lock, flags);

        ASSERT(desc->msi_desc == entry);

        if (desc->msi_desc != entry)
        {
            dprintk(XENLOG_ERR, "Restore MSI for dev %x:%x not set before?\n",
                                pdev->bus, pdev->devfn);
            spin_unlock_irqrestore(&desc->lock, flags);
            return -EINVAL;
        }

        if ( entry->msi_attrib.type == PCI_CAP_ID_MSI )
            msi_set_enable(pdev, 0);
        else if ( entry->msi_attrib.type == PCI_CAP_ID_MSIX )
            msix_set_enable(pdev, 0);

        write_msi_msg(entry, &entry->msg);

        msi_set_mask_bit(irq, entry->msi_attrib.masked);

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
    u16 control;
    u8 bus, slot, func;
    unsigned int len;

    bus = pdev->bus;
    slot = PCI_SLOT(pdev->devfn);
    func = PCI_FUNC(pdev->devfn);

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSIX);
    if ( !pos )
        return 0;

    control = pci_conf_read16(bus, slot, func, msix_control_reg(pos));
    len = msix_table_size(control) * PCI_MSIX_ENTRY_SIZE;

    return len;
}
