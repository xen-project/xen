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
DECLARE_BITMAP(msix_fixmap_pages, MAX_MSIX_PAGES);

static int msix_fixmap_alloc(void)
{
    int i, rc = -1;

    spin_lock(&msix_fixmap_lock);
    for ( i = 0; i < MAX_MSIX_PAGES; i++ )
        if ( !test_bit(i, &msix_fixmap_pages) )
            break;
    if ( i == MAX_MSIX_PAGES )
        goto out;
    rc = FIX_MSIX_IO_RESERV_BASE + i;
    set_bit(i, &msix_fixmap_pages);

 out:
    spin_unlock(&msix_fixmap_lock);
    return rc;
}

static void msix_fixmap_free(int idx)
{
    if ( idx >= FIX_MSIX_IO_RESERV_BASE )
        clear_bit(idx - FIX_MSIX_IO_RESERV_BASE, &msix_fixmap_pages);
}

/*
 * MSI message composition
 */
static void msi_compose_msg(struct pci_dev *pdev, int vector,
                            struct msi_msg *msg)
{
    unsigned dest;
    cpumask_t tmp;

    tmp = TARGET_CPUS;
    if ( vector )
    {
        dest = cpu_mask_to_apicid(tmp);

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
        base = entry->mask_base +
            entry->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE;

        msg->address_lo = readl(base + PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET);
        msg->address_hi = readl(base + PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET);
        msg->data = readl(base + PCI_MSIX_ENTRY_DATA_OFFSET);
        break;
    }
    default:
        BUG();
    }

    if ( vtd_enabled )
        msi_msg_read_remap_rte(entry, msg);
}

static int set_vector_msi(struct msi_desc *entry)
{
    if ( entry->vector >= NR_VECTORS )
    {
        dprintk(XENLOG_ERR, "Trying to install msi data for Vector %d\n",
                entry->vector);
        return -EINVAL;
    }

    irq_desc[entry->vector].msi_desc = entry;
    return 0;
}

static int unset_vector_msi(int vector)
{
    ASSERT(spin_is_locked(&irq_desc[vector].lock));

    if ( vector >= NR_VECTORS )
    {
        dprintk(XENLOG_ERR, "Trying to uninstall msi data for Vector %d\n",
                vector);
        return -EINVAL;
    }

    irq_desc[vector].msi_desc = NULL;

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
        base = entry->mask_base +
            entry->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE;

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

void set_msi_affinity(unsigned int vector, cpumask_t mask)
{
    struct msi_desc *desc = irq_desc[vector].msi_desc;
    struct msi_msg msg;
    unsigned int dest;

    memset(&msg, 0, sizeof(msg));
    cpus_and(mask, mask, cpu_online_map);
    if ( cpus_empty(mask) )
        mask = TARGET_CPUS;
    dest = cpu_mask_to_apicid(mask);

    if ( !desc )
        return;

    ASSERT(spin_is_locked(&irq_desc[vector].lock));
    read_msi_msg(desc, &msg);

    msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
    msg.address_lo |= MSI_ADDR_DEST_ID(dest);

    write_msi_msg(desc, &msg);
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

static void msix_flush_writes(unsigned int vector)
{
    struct msi_desc *entry = irq_desc[vector].msi_desc;

    BUG_ON(!entry || !entry->dev);
    switch (entry->msi_attrib.type) {
    case PCI_CAP_ID_MSI:
        /* nothing to do */
        break;
    case PCI_CAP_ID_MSIX:
    {
        int offset = entry->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE +
            PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET;
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

static void msi_set_mask_bit(unsigned int vector, int flag)
{
    struct msi_desc *entry = irq_desc[vector].msi_desc;

    ASSERT(spin_is_locked(&irq_desc[vector].lock));
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
        int offset = entry->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE +
            PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET;
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

void mask_msi_vector(unsigned int vector)
{
    msi_set_mask_bit(vector, 1);
    msix_flush_writes(vector);
}

void unmask_msi_vector(unsigned int vector)
{
    msi_set_mask_bit(vector, 0);
    msix_flush_writes(vector);
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

int setup_msi_irq(struct pci_dev *dev, struct msi_desc *desc)
{
    struct msi_msg msg;

    msi_compose_msg(dev, desc->vector, &msg);
    set_vector_msi(desc);
    write_msi_msg(irq_desc[desc->vector].msi_desc, &msg);

    return 0;
}

void teardown_msi_vector(int vector)
{
    unset_vector_msi(vector);
}

int msi_free_vector(struct msi_desc *entry)
{
    if ( entry->msi_attrib.type == PCI_CAP_ID_MSIX )
    {
        unsigned long start;

        writel(1, entry->mask_base + entry->msi_attrib.entry_nr
               * PCI_MSIX_ENTRY_SIZE
               + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

        start = (unsigned long)entry->mask_base & ~(PAGE_SIZE - 1);
        msix_fixmap_free(virt_to_fix(start));
        destroy_xen_mappings(start, start + PAGE_SIZE);
    }
    list_del(&entry->list);
    xfree(entry);
    return 0;
}

static struct msi_desc *find_msi_entry(struct pci_dev *dev,
                                       int vector, int cap_id)
{
    struct msi_desc *entry;

    list_for_each_entry( entry, &dev->msi_list, list )
    {
        if ( entry->msi_attrib.type == cap_id &&
             (vector == -1 || entry->vector == vector) )
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
                               int vector,
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
    entry->vector = vector;
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
    unsigned long phys_addr;
    u32 table_offset;
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
    phys_addr = msi->table_base + table_offset;
    idx = msix_fixmap_alloc();
    if ( idx < 0 )
    {
        xfree(entry);
        return -ENOMEM;
    }
    set_fixmap_nocache(idx, phys_addr);
    base = (void *)(fix_to_virt(idx) + (phys_addr & ((1UL << PAGE_SHIFT) - 1)));

    entry->msi_attrib.type = PCI_CAP_ID_MSIX;
    entry->msi_attrib.is_64 = 1;
    entry->msi_attrib.entry_nr = msi->entry_nr;
    entry->msi_attrib.maskbit = 1;
    entry->msi_attrib.masked = 1;
    entry->msi_attrib.pos = pos;
    entry->vector = msi->vector;
    entry->dev = dev;
    entry->mask_base = base;

    list_add_tail(&entry->list, &dev->msi_list);

    /* Mask interrupt here */
    writel(1, entry->mask_base + entry->msi_attrib.entry_nr
                * PCI_MSIX_ENTRY_SIZE
                + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

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

    if ( find_msi_entry(pdev, msi->vector, PCI_CAP_ID_MSI) )
    {
        dprintk(XENLOG_WARNING, "vector %d has already mapped to MSI on "
                "device %02x:%02x.%01x.\n", msi->vector, msi->bus,
                PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        return 0;
    }

    status = msi_capability_init(pdev, msi->vector, desc);
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

    if ( find_msi_entry(pdev, msi->vector, PCI_CAP_ID_MSIX) )
    {
        dprintk(XENLOG_WARNING, "vector %d has already mapped to MSIX on "
                "device %02x:%02x.%01x.\n", msi->vector, msi->bus,
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

    writel(1, entry->mask_base + entry->msi_attrib.entry_nr
      * PCI_MSIX_ENTRY_SIZE
      + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

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

static void msi_free_vectors(struct pci_dev* dev)
{
    struct msi_desc *entry, *tmp;
    irq_desc_t *desc;
    unsigned long flags, vector;

    list_for_each_entry_safe( entry, tmp, &dev->msi_list, list )
    {
        vector = entry->vector;
        desc = &irq_desc[vector];
        pci_disable_msi(entry);

        spin_lock_irqsave(&desc->lock, flags);

        teardown_msi_vector(vector);

        if ( desc->handler == &pci_msi_type )
        {
            /* MSI is not shared, so should be released already */
            BUG_ON(desc->status & IRQ_GUEST);
            desc->handler = &no_irq_type;
        }

        spin_unlock_irqrestore(&desc->lock, flags);
        msi_free_vector(entry);
    }
}

void pci_cleanup_msi(struct pci_dev *pdev)
{
    /* Disable MSI and/or MSI-X */
    msi_set_enable(pdev, 0);
    msix_set_enable(pdev, 0);
    msi_free_vectors(pdev);
}

int pci_restore_msi_state(struct pci_dev *pdev)
{
    unsigned long flags;
    int vector;
    struct msi_desc *entry, *tmp;
    irq_desc_t *desc;

    ASSERT(spin_is_locked(&pcidevs_lock));

    if (!pdev)
        return -EINVAL;

    list_for_each_entry_safe( entry, tmp, &pdev->msi_list, list )
    {
        vector = entry->vector;
        desc = &irq_desc[vector];

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

        msi_set_mask_bit(vector, entry->msi_attrib.masked);

        if ( entry->msi_attrib.type == PCI_CAP_ID_MSI )
            msi_set_enable(pdev, 1);
        else if ( entry->msi_attrib.type == PCI_CAP_ID_MSIX )
            msix_set_enable(pdev, 1);

        spin_unlock_irqrestore(&desc->lock, flags);
    }

    return 0;
}

