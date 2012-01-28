/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
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

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/acpi.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/irq.h>
#include <asm/amd-iommu.h>
#include <asm/msi.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <asm-x86/fixmap.h>
#include <mach_apic.h>

static int __initdata nr_amd_iommus;

static struct tasklet amd_iommu_irq_tasklet;

unsigned short ivrs_bdf_entries;
static struct radix_tree_root ivrs_maps;
struct list_head amd_iommu_head;
struct table_struct device_table;
bool_t iommuv2_enabled;

static int iommu_has_ht_flag(struct amd_iommu *iommu, u8 mask)
{
    return iommu->ht_flags & mask;
}

static int __init map_iommu_mmio_region(struct amd_iommu *iommu)
{
    unsigned long mfn;

    if ( nr_amd_iommus > MAX_AMD_IOMMUS )
    {
        AMD_IOMMU_DEBUG("nr_amd_iommus %d > MAX_IOMMUS\n", nr_amd_iommus);
        return -ENOMEM;
    }

    iommu->mmio_base = (void *)fix_to_virt(
        FIX_IOMMU_MMIO_BASE_0 + nr_amd_iommus * MMIO_PAGES_PER_IOMMU);
    mfn = (unsigned long)(iommu->mmio_base_phys >> PAGE_SHIFT);
    map_pages_to_xen((unsigned long)iommu->mmio_base, mfn,
                     MMIO_PAGES_PER_IOMMU, PAGE_HYPERVISOR_NOCACHE);

    memset(iommu->mmio_base, 0, IOMMU_MMIO_REGION_LENGTH);

    return 0;
}

static void __init unmap_iommu_mmio_region(struct amd_iommu *iommu)
{
    if ( iommu->mmio_base )
    {
        iounmap(iommu->mmio_base);
        iommu->mmio_base = NULL;
    }
}

static void set_iommu_ht_flags(struct amd_iommu *iommu)
{
    u32 entry;
    entry = readl(iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    /* Setup HT flags */
    if ( iommu_has_cap(iommu, PCI_CAP_HT_TUNNEL_SHIFT) )
        iommu_has_ht_flag(iommu, ACPI_IVHD_TT_ENABLE) ?
            iommu_set_bit(&entry, IOMMU_CONTROL_HT_TUNNEL_TRANSLATION_SHIFT) :
            iommu_clear_bit(&entry, IOMMU_CONTROL_HT_TUNNEL_TRANSLATION_SHIFT);

    iommu_has_ht_flag(iommu, ACPI_IVHD_RES_PASS_PW) ?
        iommu_set_bit(&entry, IOMMU_CONTROL_RESP_PASS_POSTED_WRITE_SHIFT):
        iommu_clear_bit(&entry, IOMMU_CONTROL_RESP_PASS_POSTED_WRITE_SHIFT);

    iommu_has_ht_flag(iommu, ACPI_IVHD_ISOC) ?
        iommu_set_bit(&entry, IOMMU_CONTROL_ISOCHRONOUS_SHIFT):
        iommu_clear_bit(&entry, IOMMU_CONTROL_ISOCHRONOUS_SHIFT);

    iommu_has_ht_flag(iommu, ACPI_IVHD_PASS_PW) ?
        iommu_set_bit(&entry, IOMMU_CONTROL_PASS_POSTED_WRITE_SHIFT):
        iommu_clear_bit(&entry, IOMMU_CONTROL_PASS_POSTED_WRITE_SHIFT);

    /* Force coherent */
    iommu_set_bit(&entry, IOMMU_CONTROL_COHERENT_SHIFT);

    writel(entry, iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
}

static void register_iommu_dev_table_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64, addr_lo, addr_hi;
    u32 entry;

    ASSERT( iommu->dev_table.buffer );

    addr_64 = (u64)virt_to_maddr(iommu->dev_table.buffer);
    addr_lo = addr_64 & DMA_32BIT_MASK;
    addr_hi = addr_64 >> 32;

    entry = 0;
    iommu_set_addr_lo_to_reg(&entry, addr_lo >> PAGE_SHIFT);
    set_field_in_reg_u32((iommu->dev_table.alloc_size / PAGE_SIZE) - 1,
                         entry, IOMMU_DEV_TABLE_SIZE_MASK,
                         IOMMU_DEV_TABLE_SIZE_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_DEV_TABLE_BASE_LOW_OFFSET);

    entry = 0;
    iommu_set_addr_hi_to_reg(&entry, addr_hi);
    writel(entry, iommu->mmio_base + IOMMU_DEV_TABLE_BASE_HIGH_OFFSET);
}

static void register_iommu_cmd_buffer_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64;
    u32 addr_lo, addr_hi;
    u32 power_of2_entries;
    u32 entry;

    ASSERT( iommu->cmd_buffer.buffer );

    addr_64 = virt_to_maddr(iommu->cmd_buffer.buffer);
    addr_lo = addr_64;
    addr_hi = addr_64 >> 32;

    entry = 0;
    iommu_set_addr_lo_to_reg(&entry, addr_lo >> PAGE_SHIFT);
    writel(entry, iommu->mmio_base + IOMMU_CMD_BUFFER_BASE_LOW_OFFSET);

    power_of2_entries = get_order_from_bytes(iommu->cmd_buffer.alloc_size) +
        IOMMU_CMD_BUFFER_POWER_OF2_ENTRIES_PER_PAGE;

    entry = 0;
    iommu_set_addr_hi_to_reg(&entry, addr_hi);
    set_field_in_reg_u32(power_of2_entries, entry,
                         IOMMU_CMD_BUFFER_LENGTH_MASK,
                         IOMMU_CMD_BUFFER_LENGTH_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_CMD_BUFFER_BASE_HIGH_OFFSET);
}

static void register_iommu_event_log_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64;
    u32 addr_lo, addr_hi;
    u32 power_of2_entries;
    u32 entry;

    ASSERT( iommu->event_log.buffer );

    addr_64 = virt_to_maddr(iommu->event_log.buffer);
    addr_lo = addr_64;
    addr_hi = addr_64 >> 32;

    entry = 0;
    iommu_set_addr_lo_to_reg(&entry, addr_lo >> PAGE_SHIFT);
    writel(entry, iommu->mmio_base + IOMMU_EVENT_LOG_BASE_LOW_OFFSET);

    power_of2_entries = get_order_from_bytes(iommu->event_log.alloc_size) +
                        IOMMU_EVENT_LOG_POWER_OF2_ENTRIES_PER_PAGE;

    entry = 0;
    iommu_set_addr_hi_to_reg(&entry, addr_hi);
    set_field_in_reg_u32(power_of2_entries, entry,
                        IOMMU_EVENT_LOG_LENGTH_MASK,
                        IOMMU_EVENT_LOG_LENGTH_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_EVENT_LOG_BASE_HIGH_OFFSET);
}

static void register_iommu_ppr_log_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64;
    u32 addr_lo, addr_hi;
    u32 power_of2_entries;
    u32 entry;

    ASSERT ( iommu->ppr_log.buffer );

    addr_64 = virt_to_maddr(iommu->ppr_log.buffer);
    addr_lo = addr_64;
    addr_hi = addr_64 >> 32;

    entry = 0;
    iommu_set_addr_lo_to_reg(&entry, addr_lo >> PAGE_SHIFT);
    writel(entry, iommu->mmio_base + IOMMU_PPR_LOG_BASE_LOW_OFFSET);

    power_of2_entries = get_order_from_bytes(iommu->ppr_log.alloc_size) +
                        IOMMU_PPR_LOG_POWER_OF2_ENTRIES_PER_PAGE;

    entry = 0;
    iommu_set_addr_hi_to_reg(&entry, addr_hi);
    set_field_in_reg_u32(power_of2_entries, entry,
                        IOMMU_PPR_LOG_LENGTH_MASK,
                        IOMMU_PPR_LOG_LENGTH_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_PPR_LOG_BASE_HIGH_OFFSET);
}


static void set_iommu_translation_control(struct amd_iommu *iommu,
                                                 int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    enable ?
        iommu_set_bit(&entry, IOMMU_CONTROL_TRANSLATION_ENABLE_SHIFT) :
        iommu_clear_bit(&entry, IOMMU_CONTROL_TRANSLATION_ENABLE_SHIFT);

    writel(entry, iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
}

static void set_iommu_guest_translation_control(struct amd_iommu *iommu,
                                                int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    enable ?
        iommu_set_bit(&entry, IOMMU_CONTROL_GT_ENABLE_SHIFT) :
        iommu_clear_bit(&entry, IOMMU_CONTROL_GT_ENABLE_SHIFT);

    writel(entry, iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);

    if ( enable )
        AMD_IOMMU_DEBUG("Guest Translation Enabled.\n");
}

static void set_iommu_command_buffer_control(struct amd_iommu *iommu,
                                                    int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    /*reset head and tail pointer manually before enablement */
    if ( enable )
    {
        writel(0x0, iommu->mmio_base + IOMMU_CMD_BUFFER_HEAD_OFFSET);
        writel(0x0, iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET);

        iommu_set_bit(&entry, IOMMU_CONTROL_COMMAND_BUFFER_ENABLE_SHIFT);
    }
    else
        iommu_clear_bit(&entry, IOMMU_CONTROL_COMMAND_BUFFER_ENABLE_SHIFT);

    writel(entry, iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
}

static void register_iommu_exclusion_range(struct amd_iommu *iommu)
{
    u32 addr_lo, addr_hi;
    u32 entry;

    addr_lo = iommu->exclusion_limit;
    addr_hi = iommu->exclusion_limit >> 32;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_EXCLUSION_LIMIT_HIGH_MASK,
                         IOMMU_EXCLUSION_LIMIT_HIGH_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_EXCLUSION_LIMIT_HIGH_OFFSET);

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_EXCLUSION_LIMIT_LOW_MASK,
                         IOMMU_EXCLUSION_LIMIT_LOW_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_EXCLUSION_LIMIT_LOW_OFFSET);

    addr_lo = iommu->exclusion_base & DMA_32BIT_MASK;
    addr_hi = iommu->exclusion_base >> 32;

    entry = 0;
    iommu_set_addr_hi_to_reg(&entry, addr_hi);
    writel(entry, iommu->mmio_base+IOMMU_EXCLUSION_BASE_HIGH_OFFSET);

    entry = 0;
    iommu_set_addr_lo_to_reg(&entry, addr_lo >> PAGE_SHIFT);

    set_field_in_reg_u32(iommu->exclusion_allow_all, entry,
                         IOMMU_EXCLUSION_ALLOW_ALL_MASK,
                         IOMMU_EXCLUSION_ALLOW_ALL_SHIFT, &entry);

    set_field_in_reg_u32(iommu->exclusion_enable, entry,
                         IOMMU_EXCLUSION_RANGE_ENABLE_MASK,
                         IOMMU_EXCLUSION_RANGE_ENABLE_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_EXCLUSION_BASE_LOW_OFFSET);
}

static void set_iommu_event_log_control(struct amd_iommu *iommu,
            int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    /*reset head and tail pointer manually before enablement */
    if ( enable )
    {
        writel(0x0, iommu->mmio_base + IOMMU_EVENT_LOG_HEAD_OFFSET);
        writel(0x0, iommu->mmio_base + IOMMU_EVENT_LOG_TAIL_OFFSET);

        iommu_set_bit(&entry, IOMMU_CONTROL_EVENT_LOG_INT_SHIFT);
        iommu_set_bit(&entry, IOMMU_CONTROL_EVENT_LOG_ENABLE_SHIFT);
    }
    else
    {
        iommu_clear_bit(&entry, IOMMU_CONTROL_EVENT_LOG_INT_SHIFT);
        iommu_clear_bit(&entry, IOMMU_CONTROL_EVENT_LOG_ENABLE_SHIFT);
    }

    iommu_clear_bit(&entry, IOMMU_CONTROL_COMP_WAIT_INT_SHIFT);

    writel(entry, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
}

static void set_iommu_ppr_log_control(struct amd_iommu *iommu,
                                      int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    /*reset head and tail pointer manually before enablement */
    if ( enable )
    {
        writel(0x0, iommu->mmio_base + IOMMU_PPR_LOG_HEAD_OFFSET);
        writel(0x0, iommu->mmio_base + IOMMU_PPR_LOG_TAIL_OFFSET);

        iommu_set_bit(&entry, IOMMU_CONTROL_PPR_ENABLE_SHIFT);
        iommu_set_bit(&entry, IOMMU_CONTROL_PPR_INT_SHIFT);
        iommu_set_bit(&entry, IOMMU_CONTROL_PPR_LOG_ENABLE_SHIFT);
    }
    else
    {
        iommu_clear_bit(&entry, IOMMU_CONTROL_PPR_ENABLE_SHIFT);
        iommu_clear_bit(&entry, IOMMU_CONTROL_PPR_INT_SHIFT);
        iommu_clear_bit(&entry, IOMMU_CONTROL_PPR_LOG_ENABLE_SHIFT);
    }

    writel(entry, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
    if ( enable )
        AMD_IOMMU_DEBUG("PPR Log Enabled.\n");
}

/* read event log or ppr log from iommu ring buffer */
static int iommu_read_log(struct amd_iommu *iommu,
                          struct ring_buffer *log,
                          unsigned int entry_size,
                          void (*parse_func)(struct amd_iommu *, u32 *))
{
    u32 tail, head, *entry, tail_offest, head_offset;

    BUG_ON(!iommu || ((log != &iommu->event_log) && (log != &iommu->ppr_log)));

    /* make sure there's an entry in the log */
    tail_offest = ( log == &iommu->event_log ) ?
        IOMMU_EVENT_LOG_TAIL_OFFSET :
        IOMMU_PPR_LOG_TAIL_OFFSET;

    head_offset = ( log == &iommu->event_log ) ?
        IOMMU_EVENT_LOG_HEAD_OFFSET :
        IOMMU_PPR_LOG_HEAD_OFFSET;

    tail = readl(iommu->mmio_base + tail_offest);
    tail = iommu_get_rb_pointer(tail);

    while ( tail != log->head )
    {
        /* read event log entry */
        entry = (u32 *)(log->buffer + log->head * entry_size);

        parse_func(iommu, entry);
        if ( ++log->head == log->entries )
            log->head = 0;

        /* update head pointer */
        head = 0;
        iommu_set_rb_pointer(&head, log->head);

        writel(head, iommu->mmio_base + head_offset);
    }

    return 0;
}

/* reset event log or ppr log when overflow */
static void iommu_reset_log(struct amd_iommu *iommu,
                            struct ring_buffer *log,
                            void (*ctrl_func)(struct amd_iommu *iommu, int))
{
    u32 entry;
    int log_run, run_bit, of_bit;
    int loop_count = 1000;

    BUG_ON(!iommu || ((log != &iommu->event_log) && (log != &iommu->ppr_log)));

    run_bit = ( log == &iommu->event_log ) ?
        IOMMU_STATUS_EVENT_LOG_RUN_SHIFT :
        IOMMU_STATUS_PPR_LOG_RUN_SHIFT;

    of_bit = ( log == &iommu->event_log ) ?
        IOMMU_STATUS_EVENT_OVERFLOW_SHIFT :
        IOMMU_STATUS_PPR_LOG_OVERFLOW_SHIFT;

    /* wait until EventLogRun bit = 0 */
    do {
        entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
        log_run = iommu_get_bit(entry, run_bit);
        loop_count--;
    } while ( log_run && loop_count );

    if ( log_run )
    {
        AMD_IOMMU_DEBUG("Warning: Log Run bit %d is not cleared"
                        "before reset!\n", run_bit);
        return;
    }

    ctrl_func(iommu, IOMMU_CONTROL_DISABLED);

    /*clear overflow bit */
    iommu_clear_bit(&entry, of_bit);
    writel(entry, iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    /*reset event log base address */
    log->head = 0;

    ctrl_func(iommu, IOMMU_CONTROL_ENABLED);
}

static void iommu_msi_set_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    struct msi_msg msg;
    unsigned int dest;
    struct amd_iommu *iommu = desc->action->dev_id;
    u16 seg = iommu->seg;
    u8 bus = (iommu->bdf >> 8) & 0xff;
    u8 dev = PCI_SLOT(iommu->bdf & 0xff);
    u8 func = PCI_FUNC(iommu->bdf & 0xff);

    dest = set_desc_affinity(desc, mask);

    if ( dest == BAD_APICID )
    {
        dprintk(XENLOG_ERR, "Set iommu interrupt affinity error!\n");
        return;
    }

    memset(&msg, 0, sizeof(msg)); 
    msg.data = MSI_DATA_VECTOR(desc->arch.vector) & 0xff;
    msg.data |= 1 << 14;
    msg.data |= (INT_DELIVERY_MODE != dest_LowestPrio) ?
        MSI_DATA_DELIVERY_FIXED:
        MSI_DATA_DELIVERY_LOWPRI;

    msg.address_hi =0;
    msg.address_lo = (MSI_ADDRESS_HEADER << (MSI_ADDRESS_HEADER_SHIFT + 8)); 
    msg.address_lo |= INT_DEST_MODE ? MSI_ADDR_DESTMODE_LOGIC:
                    MSI_ADDR_DESTMODE_PHYS;
    msg.address_lo |= (INT_DELIVERY_MODE != dest_LowestPrio) ?
                    MSI_ADDR_REDIRECTION_CPU:
                    MSI_ADDR_REDIRECTION_LOWPRI;
    msg.address_lo |= MSI_ADDR_DEST_ID(dest & 0xff);

    pci_conf_write32(seg, bus, dev, func,
        iommu->msi_cap + PCI_MSI_DATA_64, msg.data);
    pci_conf_write32(seg, bus, dev, func,
        iommu->msi_cap + PCI_MSI_ADDRESS_LO, msg.address_lo);
    pci_conf_write32(seg, bus, dev, func,
        iommu->msi_cap + PCI_MSI_ADDRESS_HI, msg.address_hi);
    
}

static void amd_iommu_msi_enable(struct amd_iommu *iommu, int flag)
{
    u16 control;
    int bus = (iommu->bdf >> 8) & 0xff;
    int dev = PCI_SLOT(iommu->bdf & 0xff);
    int func = PCI_FUNC(iommu->bdf & 0xff);

    control = pci_conf_read16(iommu->seg, bus, dev, func,
        iommu->msi_cap + PCI_MSI_FLAGS);
    control &= ~(1);
    if ( flag )
        control |= flag;
    pci_conf_write16(iommu->seg, bus, dev, func,
        iommu->msi_cap + PCI_MSI_FLAGS, control);
}

static void iommu_msi_unmask(struct irq_desc *desc)
{
    unsigned long flags;
    struct amd_iommu *iommu = desc->action->dev_id;

    /* FIXME: do not support mask bits at the moment */
    if ( iommu->maskbit )
        return;

    spin_lock_irqsave(&iommu->lock, flags);
    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_ENABLED);
    spin_unlock_irqrestore(&iommu->lock, flags);
}

static void iommu_msi_mask(struct irq_desc *desc)
{
    unsigned long flags;
    struct amd_iommu *iommu = desc->action->dev_id;

    irq_complete_move(desc);

    /* FIXME: do not support mask bits at the moment */
    if ( iommu->maskbit )
        return;

    spin_lock_irqsave(&iommu->lock, flags);
    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_DISABLED);
    spin_unlock_irqrestore(&iommu->lock, flags);
}

static unsigned int iommu_msi_startup(struct irq_desc *desc)
{
    iommu_msi_unmask(desc);
    return 0;
}

static void iommu_msi_end(struct irq_desc *desc, u8 vector)
{
    iommu_msi_unmask(desc);
    ack_APIC_irq();
}


static hw_irq_controller iommu_msi_type = {
    .typename = "AMD-IOMMU-MSI",
    .startup = iommu_msi_startup,
    .shutdown = iommu_msi_mask,
    .enable = iommu_msi_unmask,
    .disable = iommu_msi_mask,
    .ack = iommu_msi_mask,
    .end = iommu_msi_end,
    .set_affinity = iommu_msi_set_affinity,
};

static void parse_event_log_entry(struct amd_iommu *iommu, u32 entry[])
{
    u16 domain_id, device_id, bdf, cword;
    u32 code;
    u64 *addr;
    char * event_str[] = {"ILLEGAL_DEV_TABLE_ENTRY",
                          "IO_PAGE_FAULT",
                          "DEV_TABLE_HW_ERROR",
                          "PAGE_TABLE_HW_ERROR",
                          "ILLEGAL_COMMAND_ERROR",
                          "COMMAND_HW_ERROR",
                          "IOTLB_INV_TIMEOUT",
                          "INVALID_DEV_REQUEST"};

    code = get_field_from_reg_u32(entry[1], IOMMU_EVENT_CODE_MASK,
                                            IOMMU_EVENT_CODE_SHIFT);

    if ( (code > IOMMU_EVENT_INVALID_DEV_REQUEST) ||
        (code < IOMMU_EVENT_ILLEGAL_DEV_TABLE_ENTRY) )
    {
        AMD_IOMMU_DEBUG("Invalid event log entry!\n");
        return;
    }

    if ( code == IOMMU_EVENT_IO_PAGE_FAULT )
    {
        device_id = iommu_get_devid_from_event(entry[0]);
        domain_id = get_field_from_reg_u32(entry[1],
                                           IOMMU_EVENT_DOMAIN_ID_MASK,
                                           IOMMU_EVENT_DOMAIN_ID_SHIFT);
        addr= (u64*) (entry + 2);
        printk(XENLOG_ERR "AMD-Vi: "
               "%s: domain = %d, device id = 0x%04x, "
               "fault address = 0x%"PRIx64"\n",
               event_str[code-1], domain_id, device_id, *addr);

        /* Tell the device to stop DMAing; we can't rely on the guest to
         * control it for us. */
        for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
            if ( get_dma_requestor_id(iommu->seg, bdf) == device_id )
            {
                cword = pci_conf_read16(iommu->seg, PCI_BUS(bdf),
                                        PCI_SLOT(bdf), PCI_FUNC(bdf),
                                        PCI_COMMAND);
                pci_conf_write16(iommu->seg, PCI_BUS(bdf), PCI_SLOT(bdf),
                                 PCI_FUNC(bdf), PCI_COMMAND, 
                                 cword & ~PCI_COMMAND_MASTER);
            }
    }
    else
    {
        AMD_IOMMU_DEBUG("event 0x%08x 0x%08x 0x%08x 0x%08x\n", entry[0],
                        entry[1], entry[2], entry[3]);
    }
}

static void iommu_check_event_log(struct amd_iommu *iommu)
{
    u32 entry;
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);

    iommu_read_log(iommu, &iommu->event_log,
                   sizeof(event_entry_t), parse_event_log_entry);

    /*check event overflow */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    if ( iommu_get_bit(entry, IOMMU_STATUS_EVENT_OVERFLOW_SHIFT) )
        iommu_reset_log(iommu, &iommu->event_log, set_iommu_event_log_control);

    /* reset interrupt status bit */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    iommu_set_bit(&entry, IOMMU_STATUS_EVENT_LOG_INT_SHIFT);

    writel(entry, iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    spin_unlock_irqrestore(&iommu->lock, flags);
}

void parse_ppr_log_entry(struct amd_iommu *iommu, u32 entry[])
{

    u16 device_id;
    u8 bus, devfn;
    struct pci_dev *pdev;
    struct domain *d;

    /* here device_id is physical value */
    device_id = iommu_get_devid_from_cmd(entry[0]);
    bus = PCI_BUS(device_id);
    devfn = PCI_DEVFN2(device_id);

    local_irq_enable();

    spin_lock(&pcidevs_lock);
    pdev = pci_get_pdev(iommu->seg, bus, devfn);
    spin_unlock(&pcidevs_lock);

    local_irq_disable();

    if ( pdev == NULL )
        return;

    d = pdev->domain;

    guest_iommu_add_ppr_log(d, entry);
}

static void iommu_check_ppr_log(struct amd_iommu *iommu)
{
    u32 entry;
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);

    iommu_read_log(iommu, &iommu->ppr_log,
                   sizeof(ppr_entry_t), parse_ppr_log_entry);

    /*check event overflow */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    if ( iommu_get_bit(entry, IOMMU_STATUS_PPR_LOG_OVERFLOW_SHIFT) )
        iommu_reset_log(iommu, &iommu->ppr_log, set_iommu_ppr_log_control);

    /* reset interrupt status bit */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    iommu_set_bit(&entry, IOMMU_STATUS_PPR_LOG_INT_SHIFT);

    writel(entry, iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    spin_unlock_irqrestore(&iommu->lock, flags);
}

static void do_amd_iommu_irq(unsigned long data)
{
    struct amd_iommu *iommu;

    if ( !iommu_found() )
    {
        AMD_IOMMU_DEBUG("no device found, something must be very wrong!\n");
        return;
    }

    /*
     * No matter from where the interrupt came from, check all the
     * IOMMUs present in the system. This allows for having just one
     * tasklet (instead of one per each IOMMUs).
     */
    for_each_amd_iommu ( iommu ) {
        iommu_check_event_log(iommu);

        if ( iommu->ppr_log.buffer != NULL )
            iommu_check_ppr_log(iommu);
    }
}

static void iommu_interrupt_handler(int irq, void *dev_id,
                                    struct cpu_user_regs *regs)
{
    u32 entry;
    unsigned long flags;
    struct amd_iommu *iommu = dev_id;

    spin_lock_irqsave(&iommu->lock, flags);

    /* Silence interrupts from both event and PPR logging */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    iommu_clear_bit(&entry, IOMMU_STATUS_EVENT_LOG_INT_SHIFT);
    iommu_clear_bit(&entry, IOMMU_STATUS_PPR_LOG_INT_SHIFT);
    writel(entry, iommu->mmio_base+IOMMU_STATUS_MMIO_OFFSET);

    spin_unlock_irqrestore(&iommu->lock, flags);

    /* It is the tasklet that will clear the logs and re-enable interrupts */
    tasklet_schedule(&amd_iommu_irq_tasklet);
}

static int __init set_iommu_interrupt_handler(struct amd_iommu *iommu)
{
    int irq, ret;

    irq = create_irq(NUMA_NO_NODE);
    if ( irq <= 0 )
    {
        dprintk(XENLOG_ERR, "IOMMU: no irqs\n");
        return 0;
    }
    
    irq_desc[irq].handler = &iommu_msi_type;
    ret = request_irq(irq, iommu_interrupt_handler, 0, "amd_iommu", iommu);
    if ( ret )
    {
        irq_desc[irq].handler = &no_irq_type;
        destroy_irq(irq);
        AMD_IOMMU_DEBUG("can't request irq\n");
        return 0;
    }

    iommu->irq = irq;
    return irq;
}

static void enable_iommu(struct amd_iommu *iommu)
{
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);

    if ( iommu->enabled )
    {
        spin_unlock_irqrestore(&iommu->lock, flags); 
        return;
    }

    register_iommu_dev_table_in_mmio_space(iommu);
    register_iommu_cmd_buffer_in_mmio_space(iommu);
    register_iommu_event_log_in_mmio_space(iommu);
    register_iommu_exclusion_range(iommu);

    if ( iommu_has_feature(iommu, IOMMU_EXT_FEATURE_PPRSUP_SHIFT) )
        register_iommu_ppr_log_in_mmio_space(iommu);

    iommu_msi_set_affinity(irq_to_desc(iommu->irq), &cpu_online_map);
    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_ENABLED);

    set_iommu_ht_flags(iommu);
    set_iommu_command_buffer_control(iommu, IOMMU_CONTROL_ENABLED);
    set_iommu_event_log_control(iommu, IOMMU_CONTROL_ENABLED);

    if ( iommu_has_feature(iommu, IOMMU_EXT_FEATURE_PPRSUP_SHIFT) )
        set_iommu_ppr_log_control(iommu, IOMMU_CONTROL_ENABLED);

    if ( iommu_has_feature(iommu, IOMMU_EXT_FEATURE_GTSUP_SHIFT) )
        set_iommu_guest_translation_control(iommu, IOMMU_CONTROL_ENABLED);

    set_iommu_translation_control(iommu, IOMMU_CONTROL_ENABLED);

    if ( iommu_has_feature(iommu, IOMMU_EXT_FEATURE_IASUP_SHIFT) )
        amd_iommu_flush_all_caches(iommu);

    iommu->enabled = 1;
    spin_unlock_irqrestore(&iommu->lock, flags);

}

static void __init deallocate_buffer(void *buf, uint32_t sz)
{
    int order = 0;
    if ( buf )
    {
        order = get_order_from_bytes(sz);
        __free_amd_iommu_tables(buf, order);
    }
}

static void __init deallocate_device_table(struct table_struct *table)
{
    deallocate_buffer(table->buffer, table->alloc_size);
    table->buffer = NULL;
}

static void __init deallocate_ring_buffer(struct ring_buffer *ring_buf)
{
    deallocate_buffer(ring_buf->buffer, ring_buf->alloc_size);
    ring_buf->buffer = NULL;
    ring_buf->head = 0;
    ring_buf->tail = 0;
}

static void * __init allocate_buffer(uint32_t alloc_size, const char *name)
{
    void * buffer;
    int order = get_order_from_bytes(alloc_size);

    buffer = __alloc_amd_iommu_tables(order);

    if ( buffer == NULL )
    {
        AMD_IOMMU_DEBUG("Error allocating %s\n", name);
        return NULL;
    }

    memset(buffer, 0, PAGE_SIZE * (1UL << order));
    return buffer;
}

static void * __init allocate_ring_buffer(struct ring_buffer *ring_buf,
                                          uint32_t entry_size,
                                          uint64_t entries, const char *name)
{
    ring_buf->head = 0;
    ring_buf->tail = 0;

    ring_buf->alloc_size = PAGE_SIZE << get_order_from_bytes(entries *
                                                             entry_size);
    ring_buf->entries = ring_buf->alloc_size / entry_size;
    ring_buf->buffer = allocate_buffer(ring_buf->alloc_size, name);
    return ring_buf->buffer;
}

static void * __init allocate_cmd_buffer(struct amd_iommu *iommu)
{
    /* allocate 'command buffer' in power of 2 increments of 4K */
    return allocate_ring_buffer(&iommu->cmd_buffer, sizeof(cmd_entry_t),
                                IOMMU_CMD_BUFFER_DEFAULT_ENTRIES,
                                "Command Buffer");
}

static void * __init allocate_event_log(struct amd_iommu *iommu)
{
    /* allocate 'event log' in power of 2 increments of 4K */
    return allocate_ring_buffer(&iommu->event_log, sizeof(event_entry_t),
                                IOMMU_EVENT_LOG_DEFAULT_ENTRIES, "Event Log");
}

static void * __init allocate_ppr_log(struct amd_iommu *iommu)
{
    /* allocate 'ppr log' in power of 2 increments of 4K */
    return allocate_ring_buffer(&iommu->ppr_log, sizeof(ppr_entry_t),
                                IOMMU_PPR_LOG_DEFAULT_ENTRIES, "PPR Log");
}

static int __init amd_iommu_init_one(struct amd_iommu *iommu)
{
    if ( map_iommu_mmio_region(iommu) != 0 )
        goto error_out;

    get_iommu_features(iommu);

    if ( iommu->features )
        iommuv2_enabled = 1;

    if ( allocate_cmd_buffer(iommu) == NULL )
        goto error_out;

    if ( allocate_event_log(iommu) == NULL )
        goto error_out;

    if ( iommu_has_feature(iommu, IOMMU_EXT_FEATURE_PPRSUP_SHIFT) )
        if ( allocate_ppr_log(iommu) == NULL )
            goto error_out;

    if ( set_iommu_interrupt_handler(iommu) == 0 )
        goto error_out;

    /* To make sure that device_table.buffer has been successfully allocated */
    if ( device_table.buffer == NULL )
        goto error_out;

    iommu->dev_table.alloc_size = device_table.alloc_size;
    iommu->dev_table.entries = device_table.entries;
    iommu->dev_table.buffer = device_table.buffer;

    enable_iommu(iommu);
    printk("AMD-Vi: IOMMU %d Enabled.\n", nr_amd_iommus );
    nr_amd_iommus++;

    softirq_tasklet_init(&amd_iommu_irq_tasklet, do_amd_iommu_irq, 0);

    return 0;

error_out:
    return -ENODEV;
}

static void __init amd_iommu_init_cleanup(void)
{
    struct amd_iommu *iommu, *next;

    /* free amd iommu list */
    list_for_each_entry_safe ( iommu, next, &amd_iommu_head, list )
    {
        list_del(&iommu->list);
        if ( iommu->enabled )
        {
            deallocate_ring_buffer(&iommu->cmd_buffer);
            deallocate_ring_buffer(&iommu->event_log);
            deallocate_ring_buffer(&iommu->ppr_log);
            unmap_iommu_mmio_region(iommu);
        }
        xfree(iommu);
    }

    /* free interrupt remapping table */
    iterate_ivrs_entries(amd_iommu_free_intremap_table);

    /* free device table */
    deallocate_device_table(&device_table);

    /* free ivrs_mappings[] */
    radix_tree_destroy(&ivrs_maps, xfree);

    iommu_enabled = 0;
    iommu_passthrough = 0;
    iommu_intremap = 0;
    iommuv2_enabled = 0;
}

/*
 * We allocate an extra array element to store the segment number
 * (and in the future perhaps other global information).
 */
#define IVRS_MAPPINGS_SEG(m) m[ivrs_bdf_entries].dte_requestor_id

struct ivrs_mappings *get_ivrs_mappings(u16 seg)
{
    return radix_tree_lookup(&ivrs_maps, seg);
}

int iterate_ivrs_mappings(int (*handler)(u16 seg, struct ivrs_mappings *))
{
    u16 seg = 0;
    int rc = 0;

    do {
        struct ivrs_mappings *map;

        if ( !radix_tree_gang_lookup(&ivrs_maps, (void **)&map, seg, 1) )
            break;
        seg = IVRS_MAPPINGS_SEG(map);
        rc = handler(seg, map);
    } while ( !rc && ++seg );

    return rc;
}

int iterate_ivrs_entries(int (*handler)(u16 seg, struct ivrs_mappings *))
{
    u16 seg = 0;
    int rc = 0;

    do {
        struct ivrs_mappings *map;
        int bdf;

        if ( !radix_tree_gang_lookup(&ivrs_maps, (void **)&map, seg, 1) )
            break;
        seg = IVRS_MAPPINGS_SEG(map);
        for ( bdf = 0; !rc && bdf < ivrs_bdf_entries; ++bdf )
            rc = handler(seg, map + bdf);
    } while ( !rc && ++seg );

    return rc;
}

static int __init alloc_ivrs_mappings(u16 seg)
{
    struct ivrs_mappings *ivrs_mappings;
    int bdf;

    BUG_ON( !ivrs_bdf_entries );

    if ( get_ivrs_mappings(seg) )
        return 0;

    ivrs_mappings = xzalloc_array(struct ivrs_mappings, ivrs_bdf_entries + 1);
    if ( ivrs_mappings == NULL )
    {
        AMD_IOMMU_DEBUG("Error allocating IVRS Mappings table\n");
        return -ENOMEM;
    }
    IVRS_MAPPINGS_SEG(ivrs_mappings) = seg;

    /* assign default values for device entries */
    for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
    {
        ivrs_mappings[bdf].dte_requestor_id = bdf;
        ivrs_mappings[bdf].dte_allow_exclusion = IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].unity_map_enable = IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].iommu = NULL;

        ivrs_mappings[bdf].intremap_table = NULL;
        ivrs_mappings[bdf].device_flags = 0;

        if ( amd_iommu_perdev_intremap )
            spin_lock_init(&ivrs_mappings[bdf].intremap_lock);
    }

    radix_tree_insert(&ivrs_maps, seg, ivrs_mappings);

    return 0;
}

static int __init amd_iommu_setup_device_table(
    u16 seg, struct ivrs_mappings *ivrs_mappings)
{
    int bdf;
    void *intr_tb, *dte;

    BUG_ON( (ivrs_bdf_entries == 0) );

    /* allocate 'device table' on a 4K boundary */
    device_table.alloc_size = PAGE_SIZE <<
                              get_order_from_bytes(
                              PAGE_ALIGN(ivrs_bdf_entries *
                              IOMMU_DEV_TABLE_ENTRY_SIZE));
    device_table.entries = device_table.alloc_size /
                           IOMMU_DEV_TABLE_ENTRY_SIZE;

    device_table.buffer = allocate_buffer(device_table.alloc_size,
                                          "Device Table");
    if  ( device_table.buffer == NULL )
        return -ENOMEM;

    /* Add device table entries */
    for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
    {
        intr_tb = ivrs_mappings[bdf].intremap_table;

        if ( intr_tb )
        {
            /* add device table entry */
            dte = device_table.buffer + (bdf * IOMMU_DEV_TABLE_ENTRY_SIZE);
            iommu_dte_add_device_entry(dte, &ivrs_mappings[bdf]);

            amd_iommu_set_intremap_table(
                dte, (u64)virt_to_maddr(intr_tb), iommu_intremap);
        }
    }

    return 0;
}

int __init amd_iommu_init(void)
{
    struct amd_iommu *iommu;

    BUG_ON( !iommu_found() );

    ivrs_bdf_entries = amd_iommu_get_ivrs_dev_entries();

    if ( !ivrs_bdf_entries )
        goto error_out;

    radix_tree_init(&ivrs_maps);
    for_each_amd_iommu ( iommu )
        if ( alloc_ivrs_mappings(iommu->seg) != 0 )
            goto error_out;

    if ( amd_iommu_update_ivrs_mapping_acpi() != 0 )
        goto error_out;

    /* initialize io-apic interrupt remapping entries */
    if ( amd_iommu_setup_ioapic_remapping() != 0 )
        goto error_out;

    /* allocate and initialize a global device table shared by all iommus */
    if ( iterate_ivrs_mappings(amd_iommu_setup_device_table) != 0 )
        goto error_out;

    /* per iommu initialization  */
    for_each_amd_iommu ( iommu )
        if ( amd_iommu_init_one(iommu) != 0 )
            goto error_out;

    return 0;

error_out:
    amd_iommu_init_cleanup();
    return -ENODEV;
}

static void disable_iommu(struct amd_iommu *iommu)
{
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);

    if ( !iommu->enabled )
    {
        spin_unlock_irqrestore(&iommu->lock, flags); 
        return;
    }

    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_DISABLED);
    set_iommu_command_buffer_control(iommu, IOMMU_CONTROL_DISABLED);
    set_iommu_event_log_control(iommu, IOMMU_CONTROL_DISABLED);

    if ( iommu_has_feature(iommu, IOMMU_EXT_FEATURE_PPRSUP_SHIFT) )
        set_iommu_ppr_log_control(iommu, IOMMU_CONTROL_DISABLED);

    if ( iommu_has_feature(iommu, IOMMU_EXT_FEATURE_GTSUP_SHIFT) )
        set_iommu_guest_translation_control(iommu, IOMMU_CONTROL_DISABLED);

    set_iommu_translation_control(iommu, IOMMU_CONTROL_DISABLED);

    iommu->enabled = 0;

    spin_unlock_irqrestore(&iommu->lock, flags);

}

static void invalidate_all_domain_pages(void)
{
    struct domain *d;
    for_each_domain( d )
        amd_iommu_flush_all_pages(d);
}

static int _invalidate_all_devices(
    u16 seg, struct ivrs_mappings *ivrs_mappings)
{
    int bdf, req_id;
    unsigned long flags;
    struct amd_iommu *iommu;

    for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
    {
        iommu = find_iommu_for_device(seg, bdf);
        req_id = ivrs_mappings[bdf].dte_requestor_id;
        if ( iommu )
        {
            spin_lock_irqsave(&iommu->lock, flags);
            amd_iommu_flush_device(iommu, req_id);
            amd_iommu_flush_intremap(iommu, req_id);
            spin_unlock_irqrestore(&iommu->lock, flags);
        }
    }

    return 0;
}

static void invalidate_all_devices(void)
{
    iterate_ivrs_mappings(_invalidate_all_devices);
}

void amd_iommu_suspend(void)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu ( iommu )
        disable_iommu(iommu);
}

void amd_iommu_resume(void)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu ( iommu )
    {
       /*
        * To make sure that iommus have not been touched 
        * before re-enablement
        */
        disable_iommu(iommu);
        enable_iommu(iommu);
    }

    /* flush all cache entries after iommu re-enabled */
    if ( !iommu_has_feature(iommu, IOMMU_EXT_FEATURE_IASUP_SHIFT) )
    {
        invalidate_all_devices();
        invalidate_all_domain_pages();
    }
}
