/*
 * File:    msi.c
 * Purpose: PCI Message Signaled Interrupt (MSI)
 *
 * Copyright (C) 2003-2004 Intel
 * Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
 */

#include <xen/lib.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/sched.h>
#include <xen/acpi.h>
#include <xen/cpu.h>
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
#include <xen/vpci.h>

static s8 __read_mostly use_msi = -1;
boolean_param("msi", use_msi);

static void __pci_disable_msix(struct msi_desc *);

/* bitmap indicate which fixed map is free */
static DEFINE_SPINLOCK(msix_fixmap_lock);
static DECLARE_BITMAP(msix_fixmap_pages, FIX_MSIX_MAX_PAGES);

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

static int msix_get_fixmap(struct arch_msix *msix, u64 table_paddr,
                           u64 entry_paddr)
{
    long nr_page;
    int idx;

    nr_page = (entry_paddr >> PAGE_SHIFT) - (table_paddr >> PAGE_SHIFT);

    if ( nr_page < 0 || nr_page >= MAX_MSIX_TABLE_PAGES )
        return -EINVAL;

    spin_lock(&msix->table_lock);
    if ( msix->table_refcnt[nr_page]++ == 0 )
    {
        idx = msix_fixmap_alloc();
        if ( idx < 0 )
        {
            msix->table_refcnt[nr_page]--;
            goto out;
        }
        set_fixmap_nocache(idx, entry_paddr);
        msix->table_idx[nr_page] = idx;
    }
    else
        idx = msix->table_idx[nr_page];

 out:
    spin_unlock(&msix->table_lock);
    return idx;
}

static void msix_put_fixmap(struct arch_msix *msix, int idx)
{
    int i;

    spin_lock(&msix->table_lock);
    for ( i = 0; i < MAX_MSIX_TABLE_PAGES; i++ )
    {
        if ( msix->table_idx[i] == idx )
            break;
    }
    if ( i == MAX_MSIX_TABLE_PAGES )
        goto out;

    if ( --msix->table_refcnt[i] == 0 )
    {
        clear_fixmap(idx);
        msix_fixmap_free(idx);
        msix->table_idx[i] = 0;
    }

 out:
    spin_unlock(&msix->table_lock);
}

static bool memory_decoded(const struct pci_dev *dev)
{
    pci_sbdf_t sbdf = dev->sbdf;

    if ( dev->info.is_virtfn )
    {
        sbdf.bus = dev->info.physfn.bus;
        sbdf.devfn = dev->info.physfn.devfn;
    }

    return pci_conf_read16(sbdf, PCI_COMMAND) & PCI_COMMAND_MEMORY;
}

static bool msix_memory_decoded(const struct pci_dev *dev, unsigned int pos)
{
    uint16_t control = pci_conf_read16(dev->sbdf, msix_control_reg(pos));

    if ( !(control & PCI_MSIX_FLAGS_ENABLE) )
        return false;

    return memory_decoded(dev);
}

/*
 * MSI message composition
 */
void msi_compose_msg(unsigned vector, const cpumask_t *cpu_mask, struct msi_msg *msg)
{
    memset(msg, 0, sizeof(*msg));

    if ( vector < FIRST_DYNAMIC_VECTOR )
        return;

    if ( cpu_mask )
    {
        cpumask_t *mask = this_cpu(scratch_cpumask);

        if ( !cpumask_intersects(cpu_mask, &cpu_online_map) )
            return;

        cpumask_and(mask, cpu_mask, &cpu_online_map);
        msg->dest32 = cpu_mask_to_apicid(mask);
    }

    msg->address_hi = MSI_ADDR_BASE_HI;
    msg->address_lo = MSI_ADDR_BASE_LO |
                      (INT_DEST_MODE ? MSI_ADDR_DESTMODE_LOGIC
                                     : MSI_ADDR_DESTMODE_PHYS) |
                      ((INT_DELIVERY_MODE != dest_LowestPrio)
                       ? MSI_ADDR_REDIRECTION_CPU
                       : MSI_ADDR_REDIRECTION_LOWPRI) |
                      MSI_ADDR_DEST_ID(msg->dest32);

    msg->data = MSI_DATA_TRIGGER_EDGE |
                MSI_DATA_LEVEL_ASSERT |
                ((INT_DELIVERY_MODE != dest_LowestPrio)
                 ? MSI_DATA_DELIVERY_FIXED
                 : MSI_DATA_DELIVERY_LOWPRI) |
                MSI_DATA_VECTOR(vector);
}

static bool read_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
    switch ( entry->msi_attrib.type )
    {
    case PCI_CAP_ID_MSI:
    {
        struct pci_dev *dev = entry->dev;
        int pos = entry->msi_attrib.pos;
        uint16_t data;

        msg->address_lo = pci_conf_read32(dev->sbdf,
                                          msi_lower_address_reg(pos));
        if ( entry->msi_attrib.is_64 )
        {
            msg->address_hi = pci_conf_read32(dev->sbdf,
                                              msi_upper_address_reg(pos));
            data = pci_conf_read16(dev->sbdf, msi_data_reg(pos, 1));
        }
        else
        {
            msg->address_hi = 0;
            data = pci_conf_read16(dev->sbdf, msi_data_reg(pos, 0));
        }
        msg->data = data;
        break;
    }
    case PCI_CAP_ID_MSIX:
    {
        void __iomem *base = entry->mask_base;

        if ( unlikely(!msix_memory_decoded(entry->dev,
                                           entry->msi_attrib.pos)) )
            return false;
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

    return true;
}

static int write_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
    entry->msg = *msg;

    if ( iommu_intremap )
    {
        int rc;

        ASSERT(msg != &entry->msg);
        rc = iommu_update_ire_from_msi(entry, msg);
        if ( rc )
            return rc;
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
        int nr = entry->msi_attrib.entry_nr;

        ASSERT((msg->data & (entry[-nr].msi.nvec - 1)) == nr);
        if ( nr )
            return 0;

        pci_conf_write32(seg, bus, slot, func, msi_lower_address_reg(pos),
                         msg->address_lo);
        if ( entry->msi_attrib.is_64 )
        {
            pci_conf_write32(seg, bus, slot, func, msi_upper_address_reg(pos),
                             msg->address_hi);
            pci_conf_write16(dev->sbdf, msi_data_reg(pos, 1), msg->data);
        }
        else
            pci_conf_write16(dev->sbdf, msi_data_reg(pos, 0), msg->data);
        break;
    }
    case PCI_CAP_ID_MSIX:
    {
        void __iomem *base = entry->mask_base;

        if ( unlikely(!msix_memory_decoded(entry->dev,
                                           entry->msi_attrib.pos)) )
            return -ENXIO;
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

    return 0;
}

void set_msi_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    struct msi_msg msg;
    unsigned int dest;
    struct msi_desc *msi_desc = desc->msi_desc;

    dest = set_desc_affinity(desc, mask);
    if ( dest == BAD_APICID || !msi_desc )
        return;

    ASSERT(spin_is_locked(&desc->lock));

    memset(&msg, 0, sizeof(msg));
    if ( !read_msi_msg(msi_desc, &msg) )
        return;

    msg.data &= ~MSI_DATA_VECTOR_MASK;
    msg.data |= MSI_DATA_VECTOR(desc->arch.vector);
    msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
    msg.address_lo |= MSI_ADDR_DEST_ID(dest);
    msg.dest32 = dest;

    write_msi_msg(msi_desc, &msg);
}

void __msi_set_enable(u16 seg, u8 bus, u8 slot, u8 func, int pos, int enable)
{
    uint16_t control = pci_conf_read16(PCI_SBDF(seg, bus, slot, func),
                                       pos + PCI_MSI_FLAGS);

    control &= ~PCI_MSI_FLAGS_ENABLE;
    if ( enable )
        control |= PCI_MSI_FLAGS_ENABLE;
    pci_conf_write16(PCI_SBDF(seg, bus, slot, func),
                     pos + PCI_MSI_FLAGS, control);
}

static void msi_set_enable(struct pci_dev *dev, int enable)
{
    int pos;
    u16 seg = dev->seg;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSI);
    if ( pos )
        __msi_set_enable(seg, bus, slot, func, pos, enable);
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
        control = pci_conf_read16(dev->sbdf, msix_control_reg(pos));
        control &= ~PCI_MSIX_FLAGS_ENABLE;
        if ( enable )
            control |= PCI_MSIX_FLAGS_ENABLE;
        pci_conf_write16(dev->sbdf, msix_control_reg(pos), control);
    }
}

int msi_maskable_irq(const struct msi_desc *entry)
{
    BUG_ON(!entry);
    return entry->msi_attrib.type != PCI_CAP_ID_MSI
           || entry->msi_attrib.maskbit;
}

static bool msi_set_mask_bit(struct irq_desc *desc, bool host, bool guest)
{
    struct msi_desc *entry = desc->msi_desc;
    struct pci_dev *pdev;
    u16 seg, control;
    u8 bus, slot, func;
    bool flag = host || guest, maskall;

    ASSERT(spin_is_locked(&desc->lock));
    BUG_ON(!entry || !entry->dev);
    pdev = entry->dev;
    seg = pdev->seg;
    bus = pdev->bus;
    slot = PCI_SLOT(pdev->devfn);
    func = PCI_FUNC(pdev->devfn);
    switch ( entry->msi_attrib.type )
    {
    case PCI_CAP_ID_MSI:
        if ( entry->msi_attrib.maskbit )
        {
            u32 mask_bits;

            mask_bits = pci_conf_read32(pdev->sbdf, entry->msi.mpos);
            mask_bits &= ~((u32)1 << entry->msi_attrib.entry_nr);
            mask_bits |= (u32)flag << entry->msi_attrib.entry_nr;
            pci_conf_write32(seg, bus, slot, func, entry->msi.mpos, mask_bits);
        }
        break;
    case PCI_CAP_ID_MSIX:
        maskall = pdev->msix->host_maskall;
        control = pci_conf_read16(pdev->sbdf,
                                  msix_control_reg(entry->msi_attrib.pos));
        if ( unlikely(!(control & PCI_MSIX_FLAGS_ENABLE)) )
        {
            pdev->msix->host_maskall = 1;
            pci_conf_write16(pdev->sbdf,
                             msix_control_reg(entry->msi_attrib.pos),
                             control | (PCI_MSIX_FLAGS_ENABLE |
                                        PCI_MSIX_FLAGS_MASKALL));
        }
        if ( likely(memory_decoded(pdev)) )
        {
            writel(flag, entry->mask_base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);
            readl(entry->mask_base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

            if ( likely(control & PCI_MSIX_FLAGS_ENABLE) )
                break;

            entry->msi_attrib.host_masked = host;
            entry->msi_attrib.guest_masked = guest;

            flag = true;
        }
        else if ( flag && !(control & PCI_MSIX_FLAGS_MASKALL) )
        {
            domid_t domid = pdev->domain->domain_id;

            maskall = true;
            if ( pdev->msix->warned != domid )
            {
                pdev->msix->warned = domid;
                printk(XENLOG_G_WARNING
                       "cannot mask IRQ %d: masking MSI-X on Dom%d's %04x:%02x:%02x.%u\n",
                       desc->irq, domid, seg, bus, slot, func);
            }
        }
        pdev->msix->host_maskall = maskall;
        if ( maskall || pdev->msix->guest_maskall )
            control |= PCI_MSIX_FLAGS_MASKALL;
        pci_conf_write16(pdev->sbdf,
                         msix_control_reg(entry->msi_attrib.pos), control);
        return flag;
    default:
        return 0;
    }
    entry->msi_attrib.host_masked = host;
    entry->msi_attrib.guest_masked = guest;

    return 1;
}

static int msi_get_mask_bit(const struct msi_desc *entry)
{
    if ( !entry->dev )
        return -1;

    switch ( entry->msi_attrib.type )
    {
    case PCI_CAP_ID_MSI:
        if ( !entry->msi_attrib.maskbit )
            break;
        return (pci_conf_read32(entry->dev->sbdf, entry->msi.mpos) >>
                entry->msi_attrib.entry_nr) & 1;
    case PCI_CAP_ID_MSIX:
        if ( unlikely(!msix_memory_decoded(entry->dev,
                                           entry->msi_attrib.pos)) )
            break;
        return readl(entry->mask_base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET) & 1;
    }
    return -1;
}

void mask_msi_irq(struct irq_desc *desc)
{
    if ( unlikely(!msi_set_mask_bit(desc, 1,
                                    desc->msi_desc->msi_attrib.guest_masked)) )
        BUG_ON(!(desc->status & IRQ_DISABLED));
}

void unmask_msi_irq(struct irq_desc *desc)
{
    if ( unlikely(!msi_set_mask_bit(desc, 0,
                                    desc->msi_desc->msi_attrib.guest_masked)) )
        WARN();
}

void guest_mask_msi_irq(struct irq_desc *desc, bool mask)
{
    msi_set_mask_bit(desc, desc->msi_desc->msi_attrib.host_masked, mask);
}

static unsigned int startup_msi_irq(struct irq_desc *desc)
{
    if ( unlikely(!msi_set_mask_bit(desc, 0, !!(desc->status & IRQ_GUEST))) )
        WARN();
    return 0;
}

static void shutdown_msi_irq(struct irq_desc *desc)
{
    if ( unlikely(!msi_set_mask_bit(desc, 1, 1)) )
        BUG_ON(!(desc->status & IRQ_DISABLED));
}

void ack_nonmaskable_msi_irq(struct irq_desc *desc)
{
    irq_complete_move(desc);
    move_native_irq(desc);
}

static void ack_maskable_msi_irq(struct irq_desc *desc)
{
    ack_nonmaskable_msi_irq(desc);
    ack_APIC_irq(); /* ACKTYPE_NONE */
}

void end_nonmaskable_msi_irq(struct irq_desc *desc, u8 vector)
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
    .shutdown     = shutdown_msi_irq,
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

static struct msi_desc *alloc_msi_entry(unsigned int nr)
{
    struct msi_desc *entry;

    entry = xmalloc_array(struct msi_desc, nr);
    if ( !entry )
        return NULL;

    INIT_LIST_HEAD(&entry->list);
    while ( nr-- )
    {
        entry[nr].dev = NULL;
        entry[nr].irq = -1;
        entry[nr].remap_index = -1;
        entry[nr].pi_desc = NULL;
        entry[nr].irte_initialized = false;
    }

    return entry;
}

int setup_msi_irq(struct irq_desc *desc, struct msi_desc *msidesc)
{
    const struct pci_dev *pdev = msidesc->dev;
    unsigned int cpos = msix_control_reg(msidesc->msi_attrib.pos);
    u16 control = ~0;
    int rc;

    if ( msidesc->msi_attrib.type == PCI_CAP_ID_MSIX )
    {
        control = pci_conf_read16(pdev->sbdf, cpos);
        if ( !(control & PCI_MSIX_FLAGS_ENABLE) )
            pci_conf_write16(pdev->sbdf, cpos,
                             control | (PCI_MSIX_FLAGS_ENABLE |
                                        PCI_MSIX_FLAGS_MASKALL));
    }

    rc = __setup_msi_irq(desc, msidesc,
                         msi_maskable_irq(msidesc) ? &pci_msi_maskable
                                                   : &pci_msi_nonmaskable);

    if ( !(control & PCI_MSIX_FLAGS_ENABLE) )
        pci_conf_write16(pdev->sbdf, cpos, control);

    return rc;
}

int __setup_msi_irq(struct irq_desc *desc, struct msi_desc *msidesc,
                    hw_irq_controller *handler)
{
    struct msi_msg msg;
    int ret;

    desc->msi_desc = msidesc;
    desc->handler = handler;
    msi_compose_msg(desc->arch.vector, desc->arch.cpu_mask, &msg);
    ret = write_msi_msg(msidesc, &msg);
    if ( unlikely(ret) )
    {
        desc->handler = &no_irq_type;
        desc->msi_desc = NULL;
    }

    return ret;
}

int msi_free_irq(struct msi_desc *entry)
{
    unsigned int nr = entry->msi_attrib.type != PCI_CAP_ID_MSIX
                      ? entry->msi.nvec : 1;

    while ( nr-- )
    {
        if ( entry[nr].irq >= 0 )
            destroy_irq(entry[nr].irq);

        /* Free the unused IRTE if intr remap enabled */
        if ( iommu_intremap )
            iommu_update_ire_from_msi(entry + nr, NULL);
    }

    if ( entry->msi_attrib.type == PCI_CAP_ID_MSIX )
        msix_put_fixmap(entry->dev->msix,
                        virt_to_fix((unsigned long)entry->mask_base));

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
                               struct msi_desc **desc,
                               unsigned int nvec)
{
    struct msi_desc *entry;
    int pos;
    unsigned int i, maxvec, mpos;
    u16 control, seg = dev->seg;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);

    ASSERT(pcidevs_locked());
    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSI);
    if ( !pos )
        return -ENODEV;
    control = pci_conf_read16(dev->sbdf, msi_control_reg(pos));
    maxvec = multi_msi_capable(control);
    if ( nvec > maxvec )
        return maxvec;
    control &= ~PCI_MSI_FLAGS_QSIZE;
    multi_msi_enable(control, nvec);

    /* MSI Entry Initialization */
    msi_set_enable(dev, 0); /* Ensure msi is disabled as I set it up */

    entry = alloc_msi_entry(nvec);
    if ( !entry )
        return -ENOMEM;

    mpos = msi_mask_bits_reg(pos, is_64bit_address(control));
    for ( i = 0; i < nvec; ++i )
    {
        entry[i].msi_attrib.type = PCI_CAP_ID_MSI;
        entry[i].msi_attrib.is_64 = is_64bit_address(control);
        entry[i].msi_attrib.entry_nr = i;
        entry[i].msi_attrib.host_masked =
        entry[i].msi_attrib.maskbit = is_mask_bit_support(control);
        entry[i].msi_attrib.guest_masked = 0;
        entry[i].msi_attrib.pos = pos;
        if ( entry[i].msi_attrib.maskbit )
            entry[i].msi.mpos = mpos;
        entry[i].msi.nvec = 0;
        entry[i].dev = dev;
    }
    entry->msi.nvec = nvec;
    entry->irq = irq;
    if ( entry->msi_attrib.maskbit )
    {
        u32 maskbits;

        /* All MSIs are unmasked by default, Mask them all */
        maskbits = pci_conf_read32(dev->sbdf, mpos);
        maskbits |= ~(u32)0 >> (32 - maxvec);
        pci_conf_write32(seg, bus, slot, func, mpos, maskbits);
    }
    list_add_tail(&entry->list, &dev->msi_list);

    *desc = entry;
    /* Restore the original MSI enabled bits  */
    if ( !hardware_domain )
    {
        /*
         * ..., except for internal requests (before Dom0 starts), in which
         * case we rather need to behave "normally", i.e. not follow the split
         * brain model where Dom0 actually enables MSI (and disables INTx).
         */
        pci_intx(dev, false);
        control |= PCI_MSI_FLAGS_ENABLE;
    }
    pci_conf_write16(dev->sbdf, msi_control_reg(pos), control);

    return 0;
}

static u64 read_pci_mem_bar(u16 seg, u8 bus, u8 slot, u8 func, u8 bir, int vf)
{
    u8 limit;
    u32 addr, base = PCI_BASE_ADDRESS_0;
    u64 disp = 0;

    if ( vf >= 0 )
    {
        struct pci_dev *pdev = pci_get_pdev(seg, bus, PCI_DEVFN(slot, func));
        unsigned int pos = pci_find_ext_capability(seg, bus,
                                                   PCI_DEVFN(slot, func),
                                                   PCI_EXT_CAP_ID_SRIOV);
        uint16_t ctrl = pci_conf_read16(PCI_SBDF(seg, bus, slot, func),
                                        pos + PCI_SRIOV_CTRL);
        uint16_t num_vf = pci_conf_read16(PCI_SBDF(seg, bus, slot, func),
                                          pos + PCI_SRIOV_NUM_VF);
        uint16_t offset = pci_conf_read16(PCI_SBDF(seg, bus, slot, func),
                                          pos + PCI_SRIOV_VF_OFFSET);
        uint16_t stride = pci_conf_read16(PCI_SBDF(seg, bus, slot, func),
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
        if ( vf < 0 )
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
    else switch ( pci_conf_read8(PCI_SBDF(seg, bus, slot, func),
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
    addr = pci_conf_read32(PCI_SBDF(seg, bus, slot, func), base + bir * 4);
    if ( (addr & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO )
        return 0;
    if ( (addr & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64 )
    {
        addr &= PCI_BASE_ADDRESS_MEM_MASK;
        if ( ++bir >= limit )
            return 0;
        return addr + disp +
               ((uint64_t)pci_conf_read32(PCI_SBDF(seg, bus, slot, func),
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
                                unsigned int pos,
                                struct msi_info *msi,
                                struct msi_desc **desc,
                                unsigned int nr_entries)
{
    struct arch_msix *msix = dev->msix;
    struct msi_desc *entry = NULL;
    int vf;
    u16 control;
    u64 table_paddr;
    u32 table_offset;
    u8 bir, pbus, pslot, pfunc;
    u16 seg = dev->seg;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);
    bool maskall = msix->host_maskall;

    ASSERT(pcidevs_locked());

    control = pci_conf_read16(dev->sbdf, msix_control_reg(pos));
    /*
     * Ensure MSI-X interrupts are masked during setup. Some devices require
     * MSI-X to be enabled before we can touch the MSI-X registers. We need
     * to mask all the vectors to prevent interrupts coming in before they're
     * fully set up.
     */
    msix->host_maskall = 1;
    pci_conf_write16(dev->sbdf, msix_control_reg(pos),
                     control | (PCI_MSIX_FLAGS_ENABLE |
                                PCI_MSIX_FLAGS_MASKALL));

    if ( unlikely(!memory_decoded(dev)) )
    {
        pci_conf_write16(dev->sbdf, msix_control_reg(pos),
                         control & ~PCI_MSIX_FLAGS_ENABLE);
        return -ENXIO;
    }

    if ( desc )
    {
        entry = alloc_msi_entry(1);
        if ( !entry )
        {
            pci_conf_write16(dev->sbdf, msix_control_reg(pos),
                             control & ~PCI_MSIX_FLAGS_ENABLE);
            return -ENOMEM;
        }
        ASSERT(msi);
    }

    /* Locate MSI-X table region */
    table_offset = pci_conf_read32(dev->sbdf, msix_table_offset_reg(pos));
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
            pci_conf_write16(dev->sbdf, msix_control_reg(pos),
                             control & ~PCI_MSIX_FLAGS_ENABLE);
            xfree(entry);
            return -ENXIO;
        }
        table_paddr = msi->table_base;
    }
    table_paddr += table_offset;

    if ( !msix->used_entries )
    {
        u64 pba_paddr;
        u32 pba_offset;

        msix->nr_entries = nr_entries;
        msix->table.first = PFN_DOWN(table_paddr);
        msix->table.last = PFN_DOWN(table_paddr +
                                    nr_entries * PCI_MSIX_ENTRY_SIZE - 1);
        WARN_ON(rangeset_overlaps_range(mmio_ro_ranges, msix->table.first,
                                        msix->table.last));

        pba_offset = pci_conf_read32(dev->sbdf, msix_pba_offset_reg(pos));
        bir = (u8)(pba_offset & PCI_MSIX_BIRMASK);
        pba_paddr = read_pci_mem_bar(seg, pbus, pslot, pfunc, bir, vf);
        WARN_ON(!pba_paddr);
        pba_paddr += pba_offset & ~PCI_MSIX_BIRMASK;

        msix->pba.first = PFN_DOWN(pba_paddr);
        msix->pba.last = PFN_DOWN(pba_paddr +
                                  BITS_TO_LONGS(nr_entries) - 1);
        WARN_ON(rangeset_overlaps_range(mmio_ro_ranges, msix->pba.first,
                                        msix->pba.last));
    }

    if ( entry )
    {
        /* Map MSI-X table region */
        u64 entry_paddr = table_paddr + msi->entry_nr * PCI_MSIX_ENTRY_SIZE;
        int idx = msix_get_fixmap(msix, table_paddr, entry_paddr);
        void __iomem *base;

        if ( idx < 0 )
        {
            pci_conf_write16(dev->sbdf, msix_control_reg(pos),
                             control & ~PCI_MSIX_FLAGS_ENABLE);
            xfree(entry);
            return idx;
        }
        base = fix_to_virt(idx) + (entry_paddr & (PAGE_SIZE - 1));

        /* Mask interrupt here */
        writel(1, base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);

        entry->msi_attrib.type = PCI_CAP_ID_MSIX;
        entry->msi_attrib.is_64 = 1;
        entry->msi_attrib.entry_nr = msi->entry_nr;
        entry->msi_attrib.maskbit = 1;
        entry->msi_attrib.host_masked = 1;
        entry->msi_attrib.guest_masked = 1;
        entry->msi_attrib.pos = pos;
        entry->irq = msi->irq;
        entry->dev = dev;
        entry->mask_base = base;

        list_add_tail(&entry->list, &dev->msi_list);
        *desc = entry;
    }

    if ( !msix->used_entries )
    {
        maskall = false;
        if ( !msix->guest_maskall )
            control &= ~PCI_MSIX_FLAGS_MASKALL;
        else
            control |= PCI_MSIX_FLAGS_MASKALL;

        if ( rangeset_add_range(mmio_ro_ranges, msix->table.first,
                                msix->table.last) )
            WARN();
        if ( rangeset_add_range(mmio_ro_ranges, msix->pba.first,
                                msix->pba.last) )
            WARN();

        if ( desc )
        {
            struct domain *currd = current->domain;
            struct domain *d = dev->domain ?: currd;

            if ( !is_hardware_domain(currd) || d != currd )
                printk("%s use of MSI-X on %04x:%02x:%02x.%u by Dom%d\n",
                       is_hardware_domain(currd)
                       ? XENLOG_WARNING "Potentially insecure"
                       : XENLOG_ERR "Insecure",
                       seg, bus, slot, func, d->domain_id);
            if ( !is_hardware_domain(d) &&
                 /* Assume a domain without memory has no mappings yet. */
                 (!is_hardware_domain(currd) || d->tot_pages) )
                domain_crash(d);
            /* XXX How to deal with existing mappings? */
        }
    }
    WARN_ON(msix->nr_entries != nr_entries);
    WARN_ON(msix->table.first != (table_paddr >> PAGE_SHIFT));
    ++msix->used_entries;

    /* Restore MSI-X enabled bits */
    if ( !hardware_domain )
    {
        /*
         * ..., except for internal requests (before Dom0 starts), in which
         * case we rather need to behave "normally", i.e. not follow the split
         * brain model where Dom0 actually enables MSI (and disables INTx).
         */
        pci_intx(dev, false);
        control |= PCI_MSIX_FLAGS_ENABLE;
        control &= ~PCI_MSIX_FLAGS_MASKALL;
        maskall = 0;
    }
    msix->host_maskall = maskall;
    pci_conf_write16(dev->sbdf, msix_control_reg(pos), control);

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
    struct pci_dev *pdev;
    struct msi_desc *old_desc;

    ASSERT(pcidevs_locked());
    pdev = pci_get_pdev(msi->seg, msi->bus, msi->devfn);
    if ( !pdev )
        return -ENODEV;

    old_desc = find_msi_entry(pdev, msi->irq, PCI_CAP_ID_MSI);
    if ( old_desc )
    {
        printk(XENLOG_ERR "irq %d already mapped to MSI on %04x:%02x:%02x.%u\n",
               msi->irq, msi->seg, msi->bus,
               PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        return -EEXIST;
    }

    old_desc = find_msi_entry(pdev, -1, PCI_CAP_ID_MSIX);
    if ( old_desc )
    {
        printk(XENLOG_WARNING "MSI-X already in use on %04x:%02x:%02x.%u\n",
               msi->seg, msi->bus,
               PCI_SLOT(msi->devfn), PCI_FUNC(msi->devfn));
        __pci_disable_msix(old_desc);
    }

    return msi_capability_init(pdev, msi->irq, desc, msi->entry_nr);
}

static void __pci_disable_msi(struct msi_desc *entry)
{
    struct pci_dev *dev;

    dev = entry->dev;
    msi_set_enable(dev, 0);
    if ( entry->irq > 0 && !(irq_to_desc(entry->irq)->status & IRQ_GUEST) )
        pci_intx(dev, true);

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
    int pos, nr_entries;
    struct pci_dev *pdev;
    u16 control;
    u8 slot = PCI_SLOT(msi->devfn);
    u8 func = PCI_FUNC(msi->devfn);
    struct msi_desc *old_desc;

    ASSERT(pcidevs_locked());
    pdev = pci_get_pdev(msi->seg, msi->bus, msi->devfn);
    pos = pci_find_cap_offset(msi->seg, msi->bus, slot, func, PCI_CAP_ID_MSIX);
    if ( !pdev || !pos )
        return -ENODEV;

    control = pci_conf_read16(pdev->sbdf, msix_control_reg(pos));
    nr_entries = multi_msix_capable(control);
    if ( msi->entry_nr >= nr_entries )
        return -EINVAL;

    old_desc = find_msi_entry(pdev, msi->irq, PCI_CAP_ID_MSIX);
    if ( old_desc )
    {
        printk(XENLOG_ERR "irq %d already mapped to MSI-X on %04x:%02x:%02x.%u\n",
               msi->irq, msi->seg, msi->bus, slot, func);
        return -EEXIST;
    }

    old_desc = find_msi_entry(pdev, -1, PCI_CAP_ID_MSI);
    if ( old_desc )
    {
        printk(XENLOG_WARNING "MSI already in use on %04x:%02x:%02x.%u\n",
               msi->seg, msi->bus, slot, func);
        __pci_disable_msi(old_desc);
    }

    return msix_capability_init(pdev, pos, msi, desc, nr_entries);
}

static void _pci_cleanup_msix(struct arch_msix *msix)
{
    if ( !--msix->used_entries )
    {
        if ( rangeset_remove_range(mmio_ro_ranges, msix->table.first,
                                   msix->table.last) )
            WARN();
        if ( rangeset_remove_range(mmio_ro_ranges, msix->pba.first,
                                   msix->pba.last) )
            WARN();
    }
}

static void __pci_disable_msix(struct msi_desc *entry)
{
    struct pci_dev *dev = entry->dev;
    u16 seg = dev->seg;
    u8 bus = dev->bus;
    u8 slot = PCI_SLOT(dev->devfn);
    u8 func = PCI_FUNC(dev->devfn);
    unsigned int pos = pci_find_cap_offset(seg, bus, slot, func,
                                           PCI_CAP_ID_MSIX);
    u16 control = pci_conf_read16(dev->sbdf,
                                  msix_control_reg(entry->msi_attrib.pos));
    bool maskall = dev->msix->host_maskall;

    if ( unlikely(!(control & PCI_MSIX_FLAGS_ENABLE)) )
    {
        dev->msix->host_maskall = 1;
        pci_conf_write16(dev->sbdf, msix_control_reg(pos),
                         control | (PCI_MSIX_FLAGS_ENABLE |
                                    PCI_MSIX_FLAGS_MASKALL));
    }

    BUG_ON(list_empty(&dev->msi_list));

    if ( likely(memory_decoded(dev)) )
        writel(1, entry->mask_base + PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET);
    else if ( !(control & PCI_MSIX_FLAGS_MASKALL) )
    {
        printk(XENLOG_WARNING
               "cannot disable IRQ %d: masking MSI-X on %04x:%02x:%02x.%u\n",
               entry->irq, seg, bus, slot, func);
        maskall = true;
    }
    dev->msix->host_maskall = maskall;
    if ( maskall || dev->msix->guest_maskall )
        control |= PCI_MSIX_FLAGS_MASKALL;
    pci_conf_write16(dev->sbdf, msix_control_reg(pos), control);

    _pci_cleanup_msix(dev->msix);
}

int pci_prepare_msix(u16 seg, u8 bus, u8 devfn, bool off)
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

    pcidevs_lock();
    pdev = pci_get_pdev(seg, bus, devfn);
    if ( !pdev )
        rc = -ENODEV;
    else if ( pdev->msix->used_entries != !!off )
        rc = -EBUSY;
    else if ( off )
    {
        _pci_cleanup_msix(pdev->msix);
        rc = 0;
    }
    else
    {
        uint16_t control = pci_conf_read16(PCI_SBDF3(seg, bus, devfn),
                                           msix_control_reg(pos));

        rc = msix_capability_init(pdev, pos, NULL, NULL,
                                  multi_msix_capable(control));
    }
    pcidevs_unlock();

    return rc;
}

/*
 * Notice: only construct the msi_desc
 * no change to irq_desc here, and the interrupt is masked
 */
int pci_enable_msi(struct msi_info *msi, struct msi_desc **desc)
{
    ASSERT(pcidevs_locked());

    if ( !use_msi )
        return -EPERM;

    return msi->table_base ? __pci_enable_msix(msi, desc) :
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

int pci_msi_conf_write_intercept(struct pci_dev *pdev, unsigned int reg,
                                 unsigned int size, uint32_t *data)
{
    u16 seg = pdev->seg;
    u8 bus = pdev->bus;
    u8 slot = PCI_SLOT(pdev->devfn);
    u8 func = PCI_FUNC(pdev->devfn);
    struct msi_desc *entry;
    unsigned int pos;

    if ( pdev->msix )
    {
        entry = find_msi_entry(pdev, -1, PCI_CAP_ID_MSIX);
        pos = entry ? entry->msi_attrib.pos
                    : pci_find_cap_offset(seg, bus, slot, func,
                                          PCI_CAP_ID_MSIX);
        ASSERT(pos);

        if ( reg >= pos && reg < msix_pba_offset_reg(pos) + 4 )
        {
            if ( reg != msix_control_reg(pos) || size != 2 )
                return -EACCES;

            pdev->msix->guest_maskall = !!(*data & PCI_MSIX_FLAGS_MASKALL);
            if ( pdev->msix->host_maskall )
                *data |= PCI_MSIX_FLAGS_MASKALL;

            return 1;
        }
    }

    entry = find_msi_entry(pdev, -1, PCI_CAP_ID_MSI);
    if ( entry && entry->msi_attrib.maskbit )
    {
        uint16_t cntl;
        uint32_t unused;
        unsigned int nvec = entry->msi.nvec;

        pos = entry->msi_attrib.pos;
        if ( reg < pos || reg >= entry->msi.mpos + 8 )
            return 0;

        if ( reg == msi_control_reg(pos) )
            return size == 2 ? 1 : -EACCES;
        if ( reg < entry->msi.mpos || reg >= entry->msi.mpos + 4 || size != 4 )
            return -EACCES;

        cntl = pci_conf_read16(pdev->sbdf, msi_control_reg(pos));
        unused = ~(uint32_t)0 >> (32 - multi_msi_capable(cntl));
        for ( pos = 0; pos < nvec; ++pos, ++entry )
        {
            entry->msi_attrib.guest_masked =
                *data >> entry->msi_attrib.entry_nr;
            if ( entry->msi_attrib.host_masked )
                *data |= 1 << pos;
            unused &= ~(1 << pos);
        }

        *data |= unused;

        return 1;
    }

    return 0;
}

int pci_restore_msi_state(struct pci_dev *pdev)
{
    unsigned long flags;
    int irq;
    int ret;
    struct msi_desc *entry, *tmp;
    struct irq_desc *desc;
    struct msi_msg msg;
    u8 slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    unsigned int type = 0, pos = 0;
    u16 control = 0;

    ASSERT(pcidevs_locked());

    if ( !use_msi )
        return -EOPNOTSUPP;

    ret = xsm_resource_setup_pci(XSM_PRIV,
                                (pdev->seg << 16) | (pdev->bus << 8) |
                                pdev->devfn);
    if ( ret )
        return ret;

    list_for_each_entry_safe( entry, tmp, &pdev->msi_list, list )
    {
        unsigned int i = 0, nr = 1;

        irq = entry->irq;
        desc = &irq_desc[irq];

        spin_lock_irqsave(&desc->lock, flags);

        ASSERT(desc->msi_desc == entry);

        if (desc->msi_desc != entry)
        {
    bogus:
            dprintk(XENLOG_ERR,
                    "Restore MSI for %04x:%02x:%02x:%u entry %u not set?\n",
                    pdev->seg, pdev->bus, slot, func, i);
            spin_unlock_irqrestore(&desc->lock, flags);
            if ( type == PCI_CAP_ID_MSIX )
                pci_conf_write16(pdev->sbdf, msix_control_reg(pos),
                                 control & ~PCI_MSIX_FLAGS_ENABLE);
            return -EINVAL;
        }

        ASSERT(!type || type == entry->msi_attrib.type);
        pos = entry->msi_attrib.pos;
        if ( entry->msi_attrib.type == PCI_CAP_ID_MSI )
        {
            msi_set_enable(pdev, 0);
            nr = entry->msi.nvec;
        }
        else if ( !type && entry->msi_attrib.type == PCI_CAP_ID_MSIX )
        {
            control = pci_conf_read16(pdev->sbdf, msix_control_reg(pos));
            pci_conf_write16(pdev->sbdf, msix_control_reg(pos),
                             control | (PCI_MSIX_FLAGS_ENABLE |
                                        PCI_MSIX_FLAGS_MASKALL));
            if ( unlikely(!memory_decoded(pdev)) )
            {
                spin_unlock_irqrestore(&desc->lock, flags);
                pci_conf_write16(pdev->sbdf, msix_control_reg(pos),
                                 control & ~PCI_MSIX_FLAGS_ENABLE);
                return -ENXIO;
            }
        }
        type = entry->msi_attrib.type;

        msg = entry->msg;
        write_msi_msg(entry, &msg);

        for ( i = 0; ; )
        {
            if ( unlikely(!msi_set_mask_bit(desc,
                                            entry[i].msi_attrib.host_masked,
                                            entry[i].msi_attrib.guest_masked)) )
                BUG();

            if ( !--nr )
                break;

            spin_unlock_irqrestore(&desc->lock, flags);
            desc = &irq_desc[entry[++i].irq];
            spin_lock_irqsave(&desc->lock, flags);
            if ( desc->msi_desc != entry + i )
                goto bogus;
        }

        spin_unlock_irqrestore(&desc->lock, flags);

        if ( type == PCI_CAP_ID_MSI )
        {
            unsigned int cpos = msi_control_reg(pos);

            control = pci_conf_read16(pdev->sbdf, cpos) & ~PCI_MSI_FLAGS_QSIZE;
            multi_msi_enable(control, entry->msi.nvec);
            pci_conf_write16(pdev->sbdf, cpos, control);

            msi_set_enable(pdev, 1);
        }
    }

    if ( type == PCI_CAP_ID_MSIX )
        pci_conf_write16(pdev->sbdf, msix_control_reg(pos),
                         control | PCI_MSIX_FLAGS_ENABLE);

    return 0;
}

void __init early_msi_init(void)
{
    if ( use_msi < 0 )
        use_msi = !(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_MSI);
    if ( !use_msi )
        return;
}

static void dump_msi(unsigned char key)
{
    unsigned int irq;

    printk("MSI information:\n");

    for ( irq = 0; irq < nr_irqs; irq++ )
    {
        struct irq_desc *desc = irq_to_desc(irq);
        const struct msi_desc *entry;
        u32 addr, data, dest32;
        signed char mask;
        struct msi_attrib attr;
        unsigned long flags;
        const char *type = "???";

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
        case PCI_CAP_ID_MSI: type = "MSI"; break;
        case PCI_CAP_ID_MSIX: type = "MSI-X"; break;
        case 0:
            switch ( entry->msi_attrib.pos )
            {
            case MSI_TYPE_HPET: type = "HPET"; break;
            case MSI_TYPE_IOMMU: type = "IOMMU"; break;
            }
            break;
        }

        data = entry->msg.data;
        addr = entry->msg.address_lo;
        dest32 = entry->msg.dest32;
        attr = entry->msi_attrib;
        if ( entry->msi_attrib.type )
            mask = msi_get_mask_bit(entry);
        else
            mask = -1;

        spin_unlock_irqrestore(&desc->lock, flags);

        if ( mask >= 0 )
            mask += '0';
        else
            mask = '?';
        printk(" %-6s%4u vec=%02x%7s%6s%3sassert%5s%7s"
               " dest=%08x mask=%d/%c%c/%c\n",
               type, irq,
               (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT,
               data & MSI_DATA_DELIVERY_LOWPRI ? "lowest" : "fixed",
               data & MSI_DATA_TRIGGER_LEVEL ? "level" : "edge",
               data & MSI_DATA_LEVEL_ASSERT ? "" : "de",
               addr & MSI_ADDR_DESTMODE_LOGIC ? "log" : "phys",
               addr & MSI_ADDR_REDIRECTION_LOWPRI ? "lowest" : "cpu",
               dest32, attr.maskbit,
               attr.host_masked ? 'H' : ' ',
               attr.guest_masked ? 'G' : ' ',
               mask);
    }

    vpci_dump_msi();
}

static int __init msi_setup_keyhandler(void)
{
    register_keyhandler('M', dump_msi, "dump MSI state", 1);
    return 0;
}
__initcall(msi_setup_keyhandler);
