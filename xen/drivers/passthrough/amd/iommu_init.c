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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

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
#include <xen/delay.h>

static int __initdata nr_amd_iommus;

static void do_amd_iommu_irq(unsigned long data);
static DECLARE_SOFTIRQ_TASKLET(amd_iommu_irq_tasklet, do_amd_iommu_irq, 0);

unsigned int __read_mostly ivrs_bdf_entries;
u8 __read_mostly ivhd_type;
static struct radix_tree_root ivrs_maps;
LIST_HEAD_READ_MOSTLY(amd_iommu_head);
struct table_struct device_table;
bool_t iommuv2_enabled;

static bool iommu_has_ht_flag(struct amd_iommu *iommu, u8 mask)
{
    return iommu->ht_flags & mask;
}

static int __init map_iommu_mmio_region(struct amd_iommu *iommu)
{
    iommu->mmio_base = ioremap(iommu->mmio_base_phys,
                               IOMMU_MMIO_REGION_LENGTH);
    if ( !iommu->mmio_base )
        return -ENOMEM;

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
    /* Setup HT flags */
    if ( iommu_has_cap(iommu, PCI_CAP_HT_TUNNEL_SHIFT) )
        iommu->ctrl.ht_tun_en = iommu_has_ht_flag(iommu, ACPI_IVHD_TT_ENABLE);

    iommu->ctrl.pass_pw     = iommu_has_ht_flag(iommu, ACPI_IVHD_PASS_PW);
    iommu->ctrl.res_pass_pw = iommu_has_ht_flag(iommu, ACPI_IVHD_RES_PASS_PW);
    iommu->ctrl.isoc        = iommu_has_ht_flag(iommu, ACPI_IVHD_ISOC);

    /* Force coherent */
    iommu->ctrl.coherent = true;

    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
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
                                          bool enable)
{
    iommu->ctrl.iommu_en = enable;

    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
}

static void set_iommu_guest_translation_control(struct amd_iommu *iommu,
                                                bool enable)
{
    iommu->ctrl.gt_en = enable;

    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    if ( enable )
        AMD_IOMMU_DEBUG("Guest Translation Enabled.\n");
}

static void set_iommu_command_buffer_control(struct amd_iommu *iommu,
                                             bool enable)
{
    /* Reset head and tail pointer manually before enablement */
    if ( enable )
    {
        writeq(0, iommu->mmio_base + IOMMU_CMD_BUFFER_HEAD_OFFSET);
        writeq(0, iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET);
    }

    iommu->ctrl.cmd_buf_en = enable;

    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
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
                                        bool enable)
{
    /* Reset head and tail pointer manually before enablement */
    if ( enable )
    {
        writeq(0, iommu->mmio_base + IOMMU_EVENT_LOG_HEAD_OFFSET);
        writeq(0, iommu->mmio_base + IOMMU_EVENT_LOG_TAIL_OFFSET);
    }

    iommu->ctrl.event_int_en = enable;
    iommu->ctrl.event_log_en = enable;
    iommu->ctrl.com_wait_int_en = false;

    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
}

static void set_iommu_ppr_log_control(struct amd_iommu *iommu,
                                      bool enable)
{
    /* Reset head and tail pointer manually before enablement */
    if ( enable )
    {
        writeq(0, iommu->mmio_base + IOMMU_PPR_LOG_HEAD_OFFSET);
        writeq(0, iommu->mmio_base + IOMMU_PPR_LOG_TAIL_OFFSET);
    }

    iommu->ctrl.ppr_en = enable;
    iommu->ctrl.ppr_int_en = enable;
    iommu->ctrl.ppr_log_en = enable;

    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

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
    
    spin_lock(&log->lock);

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

    spin_unlock(&log->lock);
   
    return 0;
}

/* reset event log or ppr log when overflow */
static void iommu_reset_log(struct amd_iommu *iommu,
                            struct ring_buffer *log,
                            void (*ctrl_func)(struct amd_iommu *iommu, bool))
{
    u32 entry;
    int log_run, run_bit;
    int loop_count = 1000;

    BUG_ON(!iommu || ((log != &iommu->event_log) && (log != &iommu->ppr_log)));

    run_bit = ( log == &iommu->event_log ) ?
        IOMMU_STATUS_EVENT_LOG_RUN_SHIFT :
        IOMMU_STATUS_PPR_LOG_RUN_SHIFT;

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

    /* RW1C overflow bit */
    writel(log == &iommu->event_log ? IOMMU_STATUS_EVENT_OVERFLOW_MASK
                                    : IOMMU_STATUS_PPR_LOG_OVERFLOW_MASK,
           iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    /*reset event log base address */
    log->head = 0;

    ctrl_func(iommu, IOMMU_CONTROL_ENABLED);
}

static void amd_iommu_msi_enable(struct amd_iommu *iommu, int flag)
{
    __msi_set_enable(iommu->seg, PCI_BUS(iommu->bdf), PCI_SLOT(iommu->bdf),
                     PCI_FUNC(iommu->bdf), iommu->msi.msi_attrib.pos, flag);
}

static void iommu_msi_unmask(struct irq_desc *desc)
{
    unsigned long flags;
    struct amd_iommu *iommu = desc->action->dev_id;

    spin_lock_irqsave(&iommu->lock, flags);
    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_ENABLED);
    spin_unlock_irqrestore(&iommu->lock, flags);
    iommu->msi.msi_attrib.host_masked = 0;
}

static void iommu_msi_mask(struct irq_desc *desc)
{
    unsigned long flags;
    struct amd_iommu *iommu = desc->action->dev_id;

    irq_complete_move(desc);

    spin_lock_irqsave(&iommu->lock, flags);
    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_DISABLED);
    spin_unlock_irqrestore(&iommu->lock, flags);
    iommu->msi.msi_attrib.host_masked = 1;
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
    .set_affinity = set_msi_affinity,
};

static unsigned int iommu_maskable_msi_startup(struct irq_desc *desc)
{
    iommu_msi_unmask(desc);
    unmask_msi_irq(desc);
    return 0;
}

static void iommu_maskable_msi_shutdown(struct irq_desc *desc)
{
    mask_msi_irq(desc);
    iommu_msi_mask(desc);
}

/*
 * While the names may appear mismatched, we indeed want to use the non-
 * maskable flavors here, as we want the ACK to be issued in ->end().
 */
#define iommu_maskable_msi_ack ack_nonmaskable_msi_irq
#define iommu_maskable_msi_end end_nonmaskable_msi_irq

static hw_irq_controller iommu_maskable_msi_type = {
    .typename = "IOMMU-M-MSI",
    .startup = iommu_maskable_msi_startup,
    .shutdown = iommu_maskable_msi_shutdown,
    .enable = unmask_msi_irq,
    .disable = mask_msi_irq,
    .ack = iommu_maskable_msi_ack,
    .end = iommu_maskable_msi_end,
    .set_affinity = set_msi_affinity,
};

static void set_x2apic_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    struct amd_iommu *iommu = desc->action->dev_id;
    unsigned int dest = set_desc_affinity(desc, mask);
    union amd_iommu_x2apic_control ctrl = {};
    unsigned long flags;

    if ( dest == BAD_APICID )
        return;

    msi_compose_msg(desc->arch.vector, NULL, &iommu->msi.msg);
    iommu->msi.msg.dest32 = dest;

    ctrl.dest_mode = MASK_EXTR(iommu->msi.msg.address_lo,
                               MSI_ADDR_DESTMODE_MASK);
    ctrl.int_type = MASK_EXTR(iommu->msi.msg.data,
                              MSI_DATA_DELIVERY_MODE_MASK);
    ctrl.vector = desc->arch.vector;
    ctrl.dest_lo = dest;
    ctrl.dest_hi = dest >> 24;

    spin_lock_irqsave(&iommu->lock, flags);
    writeq(ctrl.raw, iommu->mmio_base + IOMMU_XT_INT_CTRL_MMIO_OFFSET);
    writeq(ctrl.raw, iommu->mmio_base + IOMMU_XT_PPR_INT_CTRL_MMIO_OFFSET);
    spin_unlock_irqrestore(&iommu->lock, flags);
}

static hw_irq_controller iommu_x2apic_type = {
    .typename     = "IOMMU-x2APIC",
    .startup      = irq_startup_none,
    .shutdown     = irq_shutdown_none,
    .enable       = irq_enable_none,
    .disable      = irq_disable_none,
    .ack          = ack_nonmaskable_msi_irq,
    .end          = end_nonmaskable_msi_irq,
    .set_affinity = set_x2apic_affinity,
};

static void parse_event_log_entry(struct amd_iommu *iommu, u32 entry[])
{
    u16 domain_id, device_id, flags;
    unsigned int bdf;
    u32 code;
    u64 *addr;
    int count = 0;
    static const char *const event_str[] = {
#define EVENT_STR(name) [IOMMU_EVENT_##name - 1] = #name
        EVENT_STR(ILLEGAL_DEV_TABLE_ENTRY),
        EVENT_STR(IO_PAGE_FAULT),
        EVENT_STR(DEV_TABLE_HW_ERROR),
        EVENT_STR(PAGE_TABLE_HW_ERROR),
        EVENT_STR(ILLEGAL_COMMAND_ERROR),
        EVENT_STR(COMMAND_HW_ERROR),
        EVENT_STR(IOTLB_INV_TIMEOUT),
        EVENT_STR(INVALID_DEV_REQUEST)
#undef EVENT_STR
    };

    code = get_field_from_reg_u32(entry[1], IOMMU_EVENT_CODE_MASK,
                                            IOMMU_EVENT_CODE_SHIFT);

    /*
     * Workaround for erratum 732:
     * It can happen that the tail pointer is updated before the actual entry
     * got written. As suggested by RevGuide, we initialize the event log
     * buffer to all zeros and clear event log entries after processing them.
     */
    while ( code == 0 )
    {
        if ( unlikely(++count == IOMMU_LOG_ENTRY_TIMEOUT) )
        {
            AMD_IOMMU_DEBUG("AMD-Vi: No event written to log\n");
            return;
        }
        udelay(1);
        barrier(); /* Prevent hoisting of the entry[] read. */
        code = get_field_from_reg_u32(entry[1], IOMMU_EVENT_CODE_MASK,
                                      IOMMU_EVENT_CODE_SHIFT);
    }

    if ( code == IOMMU_EVENT_IO_PAGE_FAULT )
    {
        device_id = iommu_get_devid_from_event(entry[0]);
        domain_id = get_field_from_reg_u32(entry[1],
                                           IOMMU_EVENT_DOMAIN_ID_MASK,
                                           IOMMU_EVENT_DOMAIN_ID_SHIFT);
        flags = get_field_from_reg_u32(entry[1],
                                       IOMMU_EVENT_FLAGS_MASK,
                                       IOMMU_EVENT_FLAGS_SHIFT);
        addr= (u64*) (entry + 2);
        printk(XENLOG_ERR "AMD-Vi: "
               "%s: domain = %d, device id = %#x, "
               "fault address = %#"PRIx64", flags = %#x\n",
               event_str[code-1], domain_id, device_id, *addr, flags);

        for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
            if ( get_dma_requestor_id(iommu->seg, bdf) == device_id )
                pci_check_disable_device(iommu->seg, PCI_BUS(bdf),
                                         PCI_DEVFN2(bdf));
    }
    else
    {
        AMD_IOMMU_DEBUG("%s %08x %08x %08x %08x\n",
                        code <= ARRAY_SIZE(event_str) ? event_str[code - 1]
                                                      : "event",
                        entry[0], entry[1], entry[2], entry[3]);
    }

    memset(entry, 0, IOMMU_EVENT_LOG_ENTRY_SIZE);
}

static void iommu_check_event_log(struct amd_iommu *iommu)
{
    u32 entry;
    unsigned long flags;

    /* RW1C interrupt status bit */
    writel(IOMMU_STATUS_EVENT_LOG_INT_MASK,
           iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    iommu_read_log(iommu, &iommu->event_log,
                   sizeof(event_entry_t), parse_event_log_entry);

    spin_lock_irqsave(&iommu->lock, flags);
    
    /* Check event overflow. */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    if ( iommu_get_bit(entry, IOMMU_STATUS_EVENT_OVERFLOW_SHIFT) )
        iommu_reset_log(iommu, &iommu->event_log, set_iommu_event_log_control);
    else
    {
        if ( !iommu->ctrl.event_int_en )
        {
            iommu->ctrl.event_int_en = true;
            writeq(iommu->ctrl.raw,
                   iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
            /*
             * Re-schedule the tasklet to handle eventual log entries added
             * between reading the log above and re-enabling the interrupt.
             */
            tasklet_schedule(&amd_iommu_irq_tasklet);
        }
    }

    /*
     * Workaround for erratum787:
     * Re-check to make sure the bit has been cleared.
     */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    if ( entry & IOMMU_STATUS_EVENT_LOG_INT_MASK )
        tasklet_schedule(&amd_iommu_irq_tasklet);

    spin_unlock_irqrestore(&iommu->lock, flags);
}

void parse_ppr_log_entry(struct amd_iommu *iommu, u32 entry[])
{

    u16 device_id;
    u8 bus, devfn, code;
    struct pci_dev *pdev;
    int count = 0;

    code = get_field_from_reg_u32(entry[1], IOMMU_PPR_LOG_CODE_MASK,
                                  IOMMU_PPR_LOG_CODE_SHIFT);

    /*
     * Workaround for erratum 733:
     * It can happen that the tail pointer is updated before the actual entry
     * got written. As suggested by RevGuide, we initialize the event log
     * buffer to all zeros and clear ppr log entries after processing them.
     */
    while ( code == 0 )
    {
        if ( unlikely(++count == IOMMU_LOG_ENTRY_TIMEOUT) )
        {
            AMD_IOMMU_DEBUG("AMD-Vi: No ppr written to log\n");
            return;
        }
        udelay(1);
        barrier(); /* Prevent hoisting of the entry[] read. */
        code = get_field_from_reg_u32(entry[1], IOMMU_PPR_LOG_CODE_MASK,
                                      IOMMU_PPR_LOG_CODE_SHIFT);
    }

    /* here device_id is physical value */
    device_id = iommu_get_devid_from_cmd(entry[0]);
    bus = PCI_BUS(device_id);
    devfn = PCI_DEVFN2(device_id);

    pcidevs_lock();
    pdev = pci_get_real_pdev(iommu->seg, bus, devfn);
    pcidevs_unlock();

    if ( pdev )
        guest_iommu_add_ppr_log(pdev->domain, entry);

    memset(entry, 0, IOMMU_PPR_LOG_ENTRY_SIZE);
}

static void iommu_check_ppr_log(struct amd_iommu *iommu)
{
    u32 entry;
    unsigned long flags;

    /* RW1C interrupt status bit */
    writel(IOMMU_STATUS_PPR_LOG_INT_MASK,
           iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    iommu_read_log(iommu, &iommu->ppr_log,
                   sizeof(ppr_entry_t), parse_ppr_log_entry);
    
    spin_lock_irqsave(&iommu->lock, flags);

    /* Check event overflow. */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    if ( iommu_get_bit(entry, IOMMU_STATUS_PPR_LOG_OVERFLOW_SHIFT) )
        iommu_reset_log(iommu, &iommu->ppr_log, set_iommu_ppr_log_control);
    else
    {
        if ( !iommu->ctrl.ppr_int_en )
        {
            iommu->ctrl.ppr_int_en = true;
            writeq(iommu->ctrl.raw,
                   iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
            /*
             * Re-schedule the tasklet to handle eventual log entries added
             * between reading the log above and re-enabling the interrupt.
             */
            tasklet_schedule(&amd_iommu_irq_tasklet);
        }
    }

    /*
     * Workaround for erratum787:
     * Re-check to make sure the bit has been cleared.
     */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    if ( entry & IOMMU_STATUS_PPR_LOG_INT_MASK )
        tasklet_schedule(&amd_iommu_irq_tasklet);

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
    unsigned long flags;
    struct amd_iommu *iommu = dev_id;

    spin_lock_irqsave(&iommu->lock, flags);

    /*
     * Silence interrupts from both event and PPR by clearing the
     * enable logging bits in the control register
     */
    iommu->ctrl.event_int_en = false;
    iommu->ctrl.ppr_int_en = false;
    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    spin_unlock_irqrestore(&iommu->lock, flags);

    /* It is the tasklet that will clear the logs and re-enable interrupts */
    tasklet_schedule(&amd_iommu_irq_tasklet);
}

static bool_t __init set_iommu_interrupt_handler(struct amd_iommu *iommu)
{
    int irq, ret;

    irq = create_irq(NUMA_NO_NODE);
    if ( irq <= 0 )
    {
        dprintk(XENLOG_ERR, "IOMMU: no irqs\n");
        return 0;
    }

    pcidevs_lock();
    iommu->msi.dev = pci_get_pdev(iommu->seg, PCI_BUS(iommu->bdf),
                                  PCI_DEVFN2(iommu->bdf));
    pcidevs_unlock();
    if ( !iommu->msi.dev )
    {
        AMD_IOMMU_DEBUG("IOMMU: no pdev for %04x:%02x:%02x.%u\n",
                        iommu->seg, PCI_BUS(iommu->bdf),
                        PCI_SLOT(iommu->bdf), PCI_FUNC(iommu->bdf));
        return 0;
    }

    if ( iommu->ctrl.int_cap_xt_en )
    {
        struct irq_desc *desc = irq_to_desc(irq);

        iommu->msi.msi_attrib.pos = MSI_TYPE_IOMMU;
        iommu->msi.msi_attrib.maskbit = 0;
        iommu->msi.msi_attrib.is_64 = 1;

        desc->msi_desc = &iommu->msi;
        desc->handler = &iommu_x2apic_type;

        ret = 0;
    }
    else
    {
        hw_irq_controller *handler;
        u16 control;

        control = pci_conf_read16(PCI_SBDF2(iommu->seg, iommu->bdf),
                                  iommu->msi.msi_attrib.pos + PCI_MSI_FLAGS);

        iommu->msi.msi.nvec = 1;
        if ( is_mask_bit_support(control) )
        {
            iommu->msi.msi_attrib.maskbit = 1;
            iommu->msi.msi.mpos = msi_mask_bits_reg(iommu->msi.msi_attrib.pos,
                                                    is_64bit_address(control));
            handler = &iommu_maskable_msi_type;
        }
        else
            handler = &iommu_msi_type;

        ret = __setup_msi_irq(irq_to_desc(irq), &iommu->msi, handler);
    }

    if ( !ret )
        ret = request_irq(irq, 0, iommu_interrupt_handler, "amd_iommu", iommu);
    if ( ret )
    {
        destroy_irq(irq);
        AMD_IOMMU_DEBUG("can't request irq\n");
        return 0;
    }

    iommu->msi.irq = irq;

    return 1;
}

int iov_adjust_irq_affinities(void)
{
    const struct amd_iommu *iommu;

    if ( !iommu_enabled )
        return 0;

    for_each_amd_iommu ( iommu )
    {
        struct irq_desc *desc = irq_to_desc(iommu->msi.irq);
        unsigned long flags;

        spin_lock_irqsave(&desc->lock, flags);
        if ( iommu->ctrl.int_cap_xt_en )
            set_x2apic_affinity(desc, NULL);
        else
            set_msi_affinity(desc, NULL);
        spin_unlock_irqrestore(&desc->lock, flags);
    }

    return 0;
}
__initcall(iov_adjust_irq_affinities);

/*
 * Family15h Model 10h-1fh erratum 746 (IOMMU Logging May Stall Translations)
 * Workaround:
 *     BIOS should disable L2B micellaneous clock gating by setting
 *     L2_L2B_CK_GATE_CONTROL[CKGateL2BMiscDisable](D0F2xF4_x90[2]) = 1b
 */
static void amd_iommu_erratum_746_workaround(struct amd_iommu *iommu)
{
    u32 value;
    u8 bus = PCI_BUS(iommu->bdf);
    u8 dev = PCI_SLOT(iommu->bdf);
    u8 func = PCI_FUNC(iommu->bdf);

    if ( (boot_cpu_data.x86 != 0x15) ||
         (boot_cpu_data.x86_model < 0x10) ||
         (boot_cpu_data.x86_model > 0x1f) )
        return;

    pci_conf_write32(PCI_SBDF2(iommu->seg, iommu->bdf), 0xf0, 0x90);
    value = pci_conf_read32(PCI_SBDF2(iommu->seg, iommu->bdf), 0xf4);

    if ( value & (1 << 2) )
        return;

    /* Select NB indirect register 0x90 and enable writing */
    pci_conf_write32(PCI_SBDF2(iommu->seg, iommu->bdf), 0xf0, 0x90 | (1 << 8));

    pci_conf_write32(PCI_SBDF2(iommu->seg, iommu->bdf), 0xf4, value | (1 << 2));
    printk(XENLOG_INFO
           "AMD-Vi: Applying erratum 746 workaround for IOMMU at %04x:%02x:%02x.%u\n",
           iommu->seg, bus, dev, func);

    /* Clear the enable writing bit */
    pci_conf_write32(PCI_SBDF2(iommu->seg, iommu->bdf), 0xf0, 0x90);
}

static void enable_iommu(struct amd_iommu *iommu)
{
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);

    if ( unlikely(iommu->enabled) )
        goto out;

    amd_iommu_erratum_746_workaround(iommu);

    register_iommu_dev_table_in_mmio_space(iommu);
    register_iommu_cmd_buffer_in_mmio_space(iommu);
    register_iommu_event_log_in_mmio_space(iommu);
    register_iommu_exclusion_range(iommu);

    if ( iommu->features.flds.ppr_sup )
        register_iommu_ppr_log_in_mmio_space(iommu);

    if ( iommu->msi.irq > 0 )
    {
        struct irq_desc *desc = irq_to_desc(iommu->msi.irq);

        spin_lock(&desc->lock);

        if ( iommu->ctrl.int_cap_xt_en )
        {
            set_x2apic_affinity(desc, NULL);
            spin_unlock(&desc->lock);
        }
        else
        {
            set_msi_affinity(desc, NULL);
            spin_unlock(&desc->lock);

            amd_iommu_msi_enable(iommu, IOMMU_CONTROL_ENABLED);
        }
    }

    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_ENABLED);

    set_iommu_ht_flags(iommu);
    set_iommu_command_buffer_control(iommu, IOMMU_CONTROL_ENABLED);

    if ( iommu->msi.irq > 0 )
    {
        set_iommu_event_log_control(iommu, IOMMU_CONTROL_ENABLED);

        if ( iommu->features.flds.ppr_sup )
            set_iommu_ppr_log_control(iommu, IOMMU_CONTROL_ENABLED);
    }

    if ( iommu->features.flds.gt_sup )
        set_iommu_guest_translation_control(iommu, IOMMU_CONTROL_ENABLED);

    set_iommu_translation_control(iommu, IOMMU_CONTROL_ENABLED);

    if ( iommu->features.flds.ia_sup )
        amd_iommu_flush_all_caches(iommu);

    iommu->enabled = 1;

 out:
    spin_unlock_irqrestore(&iommu->lock, flags);
}

static void disable_iommu(struct amd_iommu *iommu)
{
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);

    if ( unlikely(!iommu->enabled) )
        goto out;

    if ( !iommu->ctrl.int_cap_xt_en )
        amd_iommu_msi_enable(iommu, IOMMU_CONTROL_DISABLED);

    set_iommu_command_buffer_control(iommu, IOMMU_CONTROL_DISABLED);
    set_iommu_event_log_control(iommu, IOMMU_CONTROL_DISABLED);

    if ( iommu->features.flds.ppr_sup )
        set_iommu_ppr_log_control(iommu, IOMMU_CONTROL_DISABLED);

    if ( iommu->features.flds.gt_sup )
        set_iommu_guest_translation_control(iommu, IOMMU_CONTROL_DISABLED);

    set_iommu_translation_control(iommu, IOMMU_CONTROL_DISABLED);

    iommu->enabled = 0;

 out:
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

    spin_lock_init(&ring_buf->lock);
    
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

static int __init amd_iommu_init_one(struct amd_iommu *iommu, bool intr)
{
    if ( allocate_cmd_buffer(iommu) == NULL )
        goto error_out;

    if ( allocate_event_log(iommu) == NULL )
        goto error_out;

    if ( iommu->features.flds.ppr_sup && !allocate_ppr_log(iommu) )
        goto error_out;

    if ( intr && !set_iommu_interrupt_handler(iommu) )
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

        iommu->ctrl.ga_en = 0;
        iommu->ctrl.xt_en = 0;
        iommu->ctrl.int_cap_xt_en = 0;

        if ( iommu->enabled )
            disable_iommu(iommu);
        else if ( iommu->mmio_base )
            writeq(iommu->ctrl.raw,
                   iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

        deallocate_ring_buffer(&iommu->cmd_buffer);
        deallocate_ring_buffer(&iommu->event_log);
        deallocate_ring_buffer(&iommu->ppr_log);
        unmap_iommu_mmio_region(iommu);
        xfree(iommu);
    }

    /* free interrupt remapping table */
    iterate_ivrs_entries(amd_iommu_free_intremap_table);

    /* free device table */
    deallocate_device_table(&device_table);

    /* free ivrs_mappings[] */
    radix_tree_destroy(&ivrs_maps, xfree);

    iommu_enabled = 0;
    iommu_hwdom_passthrough = false;
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

int iterate_ivrs_entries(int (*handler)(const struct amd_iommu *,
                                        struct ivrs_mappings *))
{
    u16 seg = 0;
    int rc = 0;

    do {
        struct ivrs_mappings *map;
        unsigned int bdf;

        if ( !radix_tree_gang_lookup(&ivrs_maps, (void **)&map, seg, 1) )
            break;
        seg = IVRS_MAPPINGS_SEG(map);
        for ( bdf = 0; !rc && bdf < ivrs_bdf_entries; ++bdf )
        {
            const struct amd_iommu *iommu = map[bdf].iommu;

            if ( iommu && map[bdf].dte_requestor_id == bdf )
                rc = handler(iommu, &map[bdf]);
        }
    } while ( !rc && ++seg );

    return rc;
}

static int __init alloc_ivrs_mappings(u16 seg)
{
    struct ivrs_mappings *ivrs_mappings;
    unsigned int bdf;

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
    unsigned int bdf;
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

/* Check whether SP5100 SATA Combined mode is on */
static bool_t __init amd_sp5100_erratum28(void)
{
    u32 bus, id;
    u16 vendor_id, dev_id;
    u8 byte;

    for (bus = 0; bus < 256; bus++)
    {
        id = pci_conf_read32(PCI_SBDF(0, bus, 0x14, 0), PCI_VENDOR_ID);

        vendor_id = id & 0xffff;
        dev_id = (id >> 16) & 0xffff;

        /* SP5100 SMBus module sets Combined mode on */
        if (vendor_id != 0x1002 || dev_id != 0x4385)
            continue;

        byte = pci_conf_read8(PCI_SBDF(0, bus, 0x14, 0), 0xad);
        if ( (byte >> 3) & 1 )
        {
            printk(XENLOG_WARNING "AMD-Vi: SP5100 erratum 28 detected, disabling IOMMU.\n"
                   "If possible, disable SATA Combined mode in BIOS or contact your vendor for BIOS update.\n");
            return 1;
        }
    }

    return 0;
}

static int __init amd_iommu_prepare_one(struct amd_iommu *iommu)
{
    int rc = alloc_ivrs_mappings(iommu->seg);

    if ( !rc )
        rc = map_iommu_mmio_region(iommu);
    if ( rc )
        return rc;

    get_iommu_features(iommu);

    if ( iommu->features.raw )
        iommuv2_enabled = true;

    return 0;
}

int __init amd_iommu_prepare(bool xt)
{
    struct amd_iommu *iommu;
    int rc = -ENODEV;

    BUG_ON( !iommu_found() );

    if ( iommu_intremap && amd_iommu_perdev_intremap &&
         amd_sp5100_erratum28() )
        goto error_out;

    /* We implies no IOMMU if ACPI indicates no MSI. */
    if ( unlikely(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_MSI) )
        goto error_out;

    /* Have we been here before? */
    if ( ivhd_type )
        return 0;

    rc = amd_iommu_get_supported_ivhd_type();
    if ( rc < 0 )
        goto error_out;
    BUG_ON(!rc);
    ivhd_type = rc;

    rc = amd_iommu_get_ivrs_dev_entries();
    if ( !rc )
        rc = -ENODEV;
    if ( rc < 0 )
        goto error_out;
    ivrs_bdf_entries = rc;

    radix_tree_init(&ivrs_maps);
    for_each_amd_iommu ( iommu )
    {
        rc = amd_iommu_prepare_one(iommu);
        if ( rc )
            goto error_out;

        rc = -ENODEV;
        if ( xt && (!iommu->features.flds.ga_sup || !iommu->features.flds.xt_sup) )
            goto error_out;
    }

    for_each_amd_iommu ( iommu )
    {
        /* NB: There's no need to actually write these out right here. */
        iommu->ctrl.ga_en |= xt;
        iommu->ctrl.xt_en = xt;
        iommu->ctrl.int_cap_xt_en = xt;
    }

    rc = amd_iommu_update_ivrs_mapping_acpi();

 error_out:
    if ( rc )
    {
        amd_iommu_init_cleanup();
        ivhd_type = 0;
    }

    return rc;
}

int __init amd_iommu_init(bool xt)
{
    struct amd_iommu *iommu;
    int rc = amd_iommu_prepare(xt);

    if ( rc )
        goto error_out;

    /* initialize io-apic interrupt remapping entries */
    if ( iommu_intremap )
        rc = amd_iommu_setup_ioapic_remapping();
    if ( rc )
        goto error_out;

    /* allocate and initialize a global device table shared by all iommus */
    rc = iterate_ivrs_mappings(amd_iommu_setup_device_table);
    if ( rc )
        goto error_out;

    /*
     * Disable sharing HAP page tables with AMD IOMMU,
     * since it only supports p2m_ram_rw, and this would
     * prevent doing IO to/from mapped grant frames.
     */
    iommu_hap_pt_share = 0;
    printk(XENLOG_DEBUG "AMD-Vi: Disabled HAP memory map sharing with IOMMU\n");

    /* per iommu initialization  */
    for_each_amd_iommu ( iommu )
    {
        /*
         * Setting up of the IOMMU interrupts cannot occur yet at the (very
         * early) time we get here when enabling x2APIC mode. Suppress it
         * here, and do it explicitly in amd_iommu_init_interrupt().
         */
        rc = amd_iommu_init_one(iommu, !xt);
        if ( rc )
            goto error_out;
    }

    return 0;

error_out:
    amd_iommu_init_cleanup();
    return rc;
}

int __init amd_iommu_init_interrupt(void)
{
    struct amd_iommu *iommu;
    int rc = 0;

    for_each_amd_iommu ( iommu )
    {
        struct irq_desc *desc;

        if ( !set_iommu_interrupt_handler(iommu) )
        {
            rc = -EIO;
            break;
        }

        desc = irq_to_desc(iommu->msi.irq);

        spin_lock(&desc->lock);
        ASSERT(iommu->ctrl.int_cap_xt_en);
        set_x2apic_affinity(desc, &cpu_online_map);
        spin_unlock(&desc->lock);

        set_iommu_event_log_control(iommu, IOMMU_CONTROL_ENABLED);

        if ( iommu->features.flds.ppr_sup )
            set_iommu_ppr_log_control(iommu, IOMMU_CONTROL_ENABLED);
    }

    if ( rc )
        amd_iommu_init_cleanup();

    return rc;
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
    unsigned int bdf; 
    u16 req_id;
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

int amd_iommu_suspend(void)
{
    amd_iommu_crash_shutdown();

    return 0;
}

void amd_iommu_crash_shutdown(void)
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
    if ( !iommu->features.flds.ia_sup )
    {
        invalidate_all_devices();
        invalidate_all_domain_pages();
    }
}
