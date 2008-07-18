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

extern int msi_irq_enable;

/* bitmap indicate which fixed map is free */
DEFINE_SPINLOCK(msix_fixmap_lock);
DECLARE_BITMAP(msix_fixmap_pages, MAX_MSIX_PAGES);

static int msix_fixmap_alloc(void)
{
    int i;
    int rc = -1;

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
    if ( idx < FIX_MSIX_IO_RESERV_BASE )
        return;

    spin_lock(&msix_fixmap_lock);
    clear_bit(idx - FIX_MSIX_IO_RESERV_BASE, &msix_fixmap_pages);
    spin_unlock(&msix_fixmap_lock);
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

void set_msi_irq_affinity(unsigned int irq, cpumask_t mask)
{
    struct msi_desc *desc = irq_desc[irq].msi_desc;
    struct msi_msg msg;
    unsigned int dest;

    memset(&msg, 0, sizeof(msg));
    cpus_and(mask, mask, cpu_online_map);
    if ( cpus_empty(mask) )
        mask = TARGET_CPUS;
    dest = cpu_mask_to_apicid(mask);

    if ( !desc )
	return;

    ASSERT(spin_is_locked(&irq_desc[irq].lock));
    spin_lock(&desc->dev->lock);
    read_msi_msg(desc, &msg);

    msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
    msg.address_lo |= MSI_ADDR_DEST_ID(dest);

    write_msi_msg(desc, &msg);
    spin_unlock(&desc->dev->lock);
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
        } else {
            msi_set_enable(entry->dev, !flag);
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

    return entry;
}

static int setup_msi_irq(struct pci_dev *dev, struct msi_desc *desc)
{
    struct msi_msg msg;

    msi_compose_msg(dev, desc->vector, &msg);
    set_vector_msi(desc);
    write_msi_msg(irq_desc[desc->vector].msi_desc, &msg);

    return 0;
}

static void teardown_msi_vector(int vector)
{
    unset_vector_msi(vector);
}

static void msi_free_vector(int vector)
{
    struct msi_desc *entry;

    ASSERT(spin_is_locked(&irq_desc[vector].lock));
    entry = irq_desc[vector].msi_desc;
    teardown_msi_vector(vector);

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
static int msi_capability_init(struct pci_dev *dev, int vector)
{
    struct msi_desc *entry;
    int pos, ret;
    u16 control;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

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

    /* Configure MSI capability structure */
    ret = setup_msi_irq(dev, entry);
    if ( ret )
    {
        msi_free_vector(vector);
        return ret;
    }

    /* Restore the original MSI enabled bits  */
    pci_conf_write16(bus, slot, func, msi_control_reg(pos), control);

    return 0;
}

static u64 pci_resource_start(struct pci_dev *dev, u8 bar_index)
{
    u64 bar_base;
    u32 reg_val;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    reg_val = pci_conf_read32(bus, slot, func,
                              PCI_BASE_ADDRESS_0 + 4 * bar_index);
    bar_base = reg_val & PCI_BASE_ADDRESS_MEM_MASK;
    if ( ( reg_val & PCI_BASE_ADDRESS_MEM_TYPE_MASK ) ==
         PCI_BASE_ADDRESS_MEM_TYPE_64 )
    {
        reg_val = pci_conf_read32(bus, slot, func,
                                  PCI_BASE_ADDRESS_0 + 4 * (bar_index + 1));
        bar_base |= ((u64)reg_val) << 32;
    }

    return bar_base;
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
static int msix_capability_init(struct pci_dev *dev, int vector, int entry_nr)
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
    phys_addr = pci_resource_start(dev, bir) + table_offset;
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
    entry->msi_attrib.entry_nr = entry_nr;
    entry->msi_attrib.maskbit = 1;
    entry->msi_attrib.masked = 1;
    entry->msi_attrib.pos = pos;
    entry->vector = vector;
    entry->dev = dev;
    entry->mask_base = base;

    list_add_tail(&entry->list, &dev->msi_list);

    setup_msi_irq(dev, entry);

    /* Set MSI-X enabled bits */
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
static int __pci_enable_msi(u8 bus, u8 devfn, int vector)
{
    int status;
    struct pci_dev *pdev;

    pdev = pci_lock_pdev(bus, devfn);
    if ( !pdev )
	return -ENODEV;

    if ( find_msi_entry(pdev, vector, PCI_CAP_ID_MSI) )
    {
	spin_unlock(&pdev->lock);
        dprintk(XENLOG_WARNING, "vector %d has already mapped to MSI on device \
            %02x:%02x.%01x.\n", vector, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        return 0;
    }

    status = msi_capability_init(pdev, vector);
    spin_unlock(&pdev->lock);
    return status;
}

static void __pci_disable_msi(int vector)
{
    struct msi_desc *entry;
    struct pci_dev *dev;
    int pos;
    u16 control;
    u8 bus, slot, func;

    entry = irq_desc[vector].msi_desc;
    if ( !entry )
	return;
    /*
     * Lock here is safe.  msi_desc can not be removed without holding
     * both irq_desc[].lock (which we do) and pdev->lock.
     */
    spin_lock(&entry->dev->lock);
    dev = entry->dev;
    bus = dev->bus;
    slot = PCI_SLOT(dev->devfn);
    func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSI);
    control = pci_conf_read16(bus, slot, func, msi_control_reg(pos));
    msi_set_enable(dev, 0);

    BUG_ON(list_empty(&dev->msi_list));

    msi_free_vector(vector);

    pci_conf_write16(bus, slot, func, msi_control_reg(pos), control);
    spin_unlock(&dev->lock);
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
static int __pci_enable_msix(u8 bus, u8 devfn, int vector, int entry_nr)
{
    int status, pos, nr_entries;
    struct pci_dev *pdev;
    u16 control;
    u8 slot = PCI_SLOT(devfn);
    u8 func = PCI_FUNC(devfn);

    pdev = pci_lock_pdev(bus, devfn);
    if ( !pdev )
	return -ENODEV;

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSIX);
    control = pci_conf_read16(bus, slot, func, msi_control_reg(pos));
    nr_entries = multi_msix_capable(control);
    if (entry_nr > nr_entries)
    {
	spin_unlock(&pdev->lock);
        return -EINVAL;
    }

    if ( find_msi_entry(pdev, vector, PCI_CAP_ID_MSIX) )
    {
	spin_unlock(&pdev->lock);
        dprintk(XENLOG_WARNING, "vector %d has already mapped to MSIX on \
                device %02x:%02x.%01x.\n", vector, bus,
                PCI_SLOT(devfn), PCI_FUNC(devfn));
        return 0;
    }

    status = msix_capability_init(pdev, vector, entry_nr);
    spin_unlock(&pdev->lock);
    return status;
}

static void __pci_disable_msix(int vector)
{
    struct msi_desc *entry;
    struct pci_dev *dev;
    int pos;
    u16 control;
    u8 bus, slot, func;

    entry = irq_desc[vector].msi_desc;
    if ( !entry )
	return;
    /*
     * Lock here is safe.  msi_desc can not be removed without holding
     * both irq_desc[].lock (which we do) and pdev->lock.
     */
    spin_lock(&entry->dev->lock);
    dev = entry->dev;
    bus = dev->bus;
    slot = PCI_SLOT(dev->devfn);
    func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(bus, slot, func, PCI_CAP_ID_MSIX);
    control = pci_conf_read16(bus, slot, func, msix_control_reg(pos));
    msi_set_enable(dev, 0);

    BUG_ON(list_empty(&dev->msi_list));

    msi_free_vector(vector);

    pci_conf_write16(bus, slot, func, msix_control_reg(pos), control);
    spin_unlock(&dev->lock);
}

int pci_enable_msi(u8 bus, u8 devfn, int vector, int entry_nr, int msi)
{
    ASSERT(spin_is_locked(&irq_desc[vector].lock));
    if ( msi )
        return __pci_enable_msi(bus, devfn, vector);
    else
        return __pci_enable_msix(bus, devfn, vector, entry_nr);
}

void pci_disable_msi(int vector)
{
    irq_desc_t *desc = &irq_desc[vector];
    ASSERT(spin_is_locked(&desc->lock));
    if ( !desc->msi_desc )
	return;

    if ( desc->msi_desc->msi_attrib.type == PCI_CAP_ID_MSI )
        __pci_disable_msi(vector);
    else if ( desc->msi_desc->msi_attrib.type == PCI_CAP_ID_MSIX )
        __pci_disable_msix(vector);
}

extern struct hw_interrupt_type pci_msi_type;
static void msi_free_vectors(struct pci_dev* dev)
{
    struct msi_desc *entry, *tmp;
    irq_desc_t *desc;
    unsigned long flags;

retry:
    list_for_each_entry_safe( entry, tmp, &dev->msi_list, list )
    {
        desc = &irq_desc[entry->vector];

	local_irq_save(flags);
	if ( !spin_trylock(&desc->lock) )
	{
	    local_irq_restore(flags);
	    goto retry;
	}

        spin_lock_irqsave(&desc->lock, flags);
        if ( desc->handler == &pci_msi_type )
        {
            /* MSI is not shared, so should be released already */
            BUG_ON(desc->status & IRQ_GUEST);
            desc->handler = &no_irq_type;
        }

        msi_free_vector(entry->vector);
        spin_unlock_irqrestore(&desc->lock, flags);
    }
}

void pci_cleanup_msi(struct pci_dev *pdev)
{
    /* Disable MSI and/or MSI-X */
    msi_set_enable(pdev, 0);
    msix_set_enable(pdev, 0);
    msi_free_vectors(pdev);
}

