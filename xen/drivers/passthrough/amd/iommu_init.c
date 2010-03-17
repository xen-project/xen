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
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/amd-iommu.h>
#include <asm/msi.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <asm-x86/fixmap.h>
#include <mach_apic.h>

static struct amd_iommu **irq_to_iommu;
static int nr_amd_iommus;
static long amd_iommu_cmd_buffer_entries = IOMMU_CMD_BUFFER_DEFAULT_ENTRIES;
static long amd_iommu_event_log_entries = IOMMU_EVENT_LOG_DEFAULT_ENTRIES;

unsigned short ivrs_bdf_entries;
struct ivrs_mappings *ivrs_mappings;
struct list_head amd_iommu_head;
struct table_struct device_table;

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

static void register_iommu_dev_table_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64, addr_lo, addr_hi;
    u32 entry;

    addr_64 = (u64)virt_to_maddr(iommu->dev_table.buffer);
    addr_lo = addr_64 & DMA_32BIT_MASK;
    addr_hi = addr_64 >> 32;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_DEV_TABLE_BASE_LOW_MASK,
                         IOMMU_DEV_TABLE_BASE_LOW_SHIFT, &entry);
    set_field_in_reg_u32((iommu->dev_table.alloc_size / PAGE_SIZE) - 1,
                         entry, IOMMU_DEV_TABLE_SIZE_MASK,
                         IOMMU_DEV_TABLE_SIZE_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_DEV_TABLE_BASE_LOW_OFFSET);

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_DEV_TABLE_BASE_HIGH_MASK,
                         IOMMU_DEV_TABLE_BASE_HIGH_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_DEV_TABLE_BASE_HIGH_OFFSET);
}

static void register_iommu_cmd_buffer_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64, addr_lo, addr_hi;
    u32 power_of2_entries;
    u32 entry;

    addr_64 = (u64)virt_to_maddr(iommu->cmd_buffer.buffer);
    addr_lo = addr_64 & DMA_32BIT_MASK;
    addr_hi = addr_64 >> 32;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_CMD_BUFFER_BASE_LOW_MASK,
                         IOMMU_CMD_BUFFER_BASE_LOW_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_CMD_BUFFER_BASE_LOW_OFFSET);

    power_of2_entries = get_order_from_bytes(iommu->cmd_buffer.alloc_size) +
        IOMMU_CMD_BUFFER_POWER_OF2_ENTRIES_PER_PAGE;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_CMD_BUFFER_BASE_HIGH_MASK,
                         IOMMU_CMD_BUFFER_BASE_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(power_of2_entries, entry,
                         IOMMU_CMD_BUFFER_LENGTH_MASK,
                         IOMMU_CMD_BUFFER_LENGTH_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_CMD_BUFFER_BASE_HIGH_OFFSET);
}

static void __init register_iommu_event_log_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64, addr_lo, addr_hi;
    u32 power_of2_entries;
    u32 entry;

    addr_64 = (u64)virt_to_maddr(iommu->event_log.buffer);
    addr_lo = addr_64 & DMA_32BIT_MASK;
    addr_hi = addr_64 >> 32;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_EVENT_LOG_BASE_LOW_MASK,
                         IOMMU_EVENT_LOG_BASE_LOW_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_EVENT_LOG_BASE_LOW_OFFSET);

    power_of2_entries = get_order_from_bytes(iommu->event_log.alloc_size) +
                        IOMMU_EVENT_LOG_POWER_OF2_ENTRIES_PER_PAGE;

    set_field_in_reg_u32((u32)addr_hi, 0,
                        IOMMU_EVENT_LOG_BASE_HIGH_MASK,
                        IOMMU_EVENT_LOG_BASE_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(power_of2_entries, entry,
                        IOMMU_EVENT_LOG_LENGTH_MASK,
                        IOMMU_EVENT_LOG_LENGTH_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_EVENT_LOG_BASE_HIGH_OFFSET);
}

static void set_iommu_translation_control(struct amd_iommu *iommu,
                                                 int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    if ( enable )
    {
        set_field_in_reg_u32(iommu->ht_tunnel_support ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_HT_TUNNEL_TRANSLATION_MASK,
                         IOMMU_CONTROL_HT_TUNNEL_TRANSLATION_SHIFT, &entry);
        set_field_in_reg_u32(iommu->isochronous ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_ISOCHRONOUS_MASK,
                         IOMMU_CONTROL_ISOCHRONOUS_SHIFT, &entry);
        set_field_in_reg_u32(iommu->coherent ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_COHERENT_MASK,
                         IOMMU_CONTROL_COHERENT_SHIFT, &entry);
        set_field_in_reg_u32(iommu->res_pass_pw ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_RESP_PASS_POSTED_WRITE_MASK,
                         IOMMU_CONTROL_RESP_PASS_POSTED_WRITE_SHIFT, &entry);
        /* do not set PassPW bit */
        set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_PASS_POSTED_WRITE_MASK,
                         IOMMU_CONTROL_PASS_POSTED_WRITE_SHIFT, &entry);
    }
    set_field_in_reg_u32(enable ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_TRANSLATION_ENABLE_MASK,
                         IOMMU_CONTROL_TRANSLATION_ENABLE_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
}

static void set_iommu_command_buffer_control(struct amd_iommu *iommu,
                                                    int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
    set_field_in_reg_u32(enable ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_COMMAND_BUFFER_ENABLE_MASK,
                         IOMMU_CONTROL_COMMAND_BUFFER_ENABLE_SHIFT, &entry);

    /*reset head and tail pointer manually before enablement */
    if ( enable == IOMMU_CONTROL_ENABLED )
    {
        writel(0x0, iommu->mmio_base + IOMMU_CMD_BUFFER_HEAD_OFFSET);
        writel(0x0, iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET);
    }

    writel(entry, iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
}

static void register_iommu_exclusion_range(struct amd_iommu *iommu)
{
    u64 addr_lo, addr_hi;
    u32 entry;

    addr_lo = iommu->exclusion_limit & DMA_32BIT_MASK;
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

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_EXCLUSION_BASE_HIGH_MASK,
                         IOMMU_EXCLUSION_BASE_HIGH_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_EXCLUSION_BASE_HIGH_OFFSET);

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_EXCLUSION_BASE_LOW_MASK,
                         IOMMU_EXCLUSION_BASE_LOW_SHIFT, &entry);

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
    set_field_in_reg_u32(enable ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_EVENT_LOG_ENABLE_MASK,
                         IOMMU_CONTROL_EVENT_LOG_ENABLE_SHIFT, &entry);
    set_field_in_reg_u32(enable ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_EVENT_LOG_INT_MASK,
                         IOMMU_CONTROL_EVENT_LOG_INT_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_CONTROL_COMP_WAIT_INT_MASK,
                         IOMMU_CONTROL_COMP_WAIT_INT_SHIFT, &entry);

    /*reset head and tail pointer manually before enablement */
    if ( enable == IOMMU_CONTROL_ENABLED )
    {
        writel(0x0, iommu->mmio_base + IOMMU_EVENT_LOG_HEAD_OFFSET);
        writel(0x0, iommu->mmio_base + IOMMU_EVENT_LOG_TAIL_OFFSET);
    }
    writel(entry, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);
}

static void amd_iommu_reset_event_log(struct amd_iommu *iommu)
{
    u32 entry;
    int log_run;
    int loop_count = 1000;

    /* wait until EventLogRun bit = 0 */
    do {
        entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
        log_run = get_field_from_reg_u32(entry,
                                        IOMMU_STATUS_EVENT_LOG_RUN_MASK,
                                        IOMMU_STATUS_EVENT_LOG_RUN_SHIFT);
        loop_count--;
    } while ( log_run && loop_count );

    if ( log_run )
    {
        AMD_IOMMU_DEBUG("Warning: EventLogRun bit is not cleared"
                       "before reset!\n");
        return;
    }

    set_iommu_event_log_control(iommu, IOMMU_CONTROL_DISABLED);

    /*clear overflow bit */
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_STATUS_EVENT_OVERFLOW_MASK,
                         IOMMU_STATUS_EVENT_OVERFLOW_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_STATUS_MMIO_OFFSET);

    /*reset event log base address */
    iommu->event_log_head = 0;

    set_iommu_event_log_control(iommu, IOMMU_CONTROL_ENABLED);
}

static void parse_event_log_entry(u32 entry[]);

static int amd_iommu_read_event_log(struct amd_iommu *iommu)
{
    u32 tail, head, *event_log;

    BUG_ON( !iommu );

    /* make sure there's an entry in the log */
    tail = readl(iommu->mmio_base + IOMMU_EVENT_LOG_TAIL_OFFSET);
    tail = get_field_from_reg_u32(tail,
                                  IOMMU_EVENT_LOG_TAIL_MASK,
                                  IOMMU_EVENT_LOG_TAIL_SHIFT);

    while ( tail != iommu->event_log_head )
    {
        /* read event log entry */
        event_log = (u32 *)(iommu->event_log.buffer +
                           (iommu->event_log_head *
                           IOMMU_EVENT_LOG_ENTRY_SIZE));

        parse_event_log_entry(event_log);

        if ( ++iommu->event_log_head == iommu->event_log.entries )
            iommu->event_log_head = 0;

        /* update head pointer */
        set_field_in_reg_u32(iommu->event_log_head, 0,
                             IOMMU_EVENT_LOG_HEAD_MASK,
                             IOMMU_EVENT_LOG_HEAD_SHIFT, &head);
        writel(head, iommu->mmio_base + IOMMU_EVENT_LOG_HEAD_OFFSET);
    }

    return 0;
}

static void iommu_msi_set_affinity(unsigned int irq, cpumask_t mask)
{
    struct msi_msg msg;
    unsigned int dest;
    struct amd_iommu *iommu = irq_to_iommu[irq];
    struct irq_desc *desc = irq_to_desc(irq);
    struct irq_cfg *cfg = desc->chip_data;
    u8 bus = (iommu->bdf >> 8) & 0xff;
    u8 dev = PCI_SLOT(iommu->bdf & 0xff);
    u8 func = PCI_FUNC(iommu->bdf & 0xff);

    dest = set_desc_affinity(desc, mask);
    if (dest == BAD_APICID){
        dprintk(XENLOG_ERR, "Set iommu interrupt affinity error!\n");
        return;
    }

    memset(&msg, 0, sizeof(msg)); 
    msg.data = MSI_DATA_VECTOR(cfg->vector) & 0xff;
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

    pci_conf_write32(bus, dev, func,
        iommu->msi_cap + PCI_MSI_DATA_64, msg.data);
    pci_conf_write32(bus, dev, func,
        iommu->msi_cap + PCI_MSI_ADDRESS_LO, msg.address_lo);
    pci_conf_write32(bus, dev, func,
        iommu->msi_cap + PCI_MSI_ADDRESS_HI, msg.address_hi);
    
}

static void amd_iommu_msi_enable(struct amd_iommu *iommu, int flag)
{
    u16 control;
    int bus = (iommu->bdf >> 8) & 0xff;
    int dev = PCI_SLOT(iommu->bdf & 0xff);
    int func = PCI_FUNC(iommu->bdf & 0xff);

    control = pci_conf_read16(bus, dev, func,
        iommu->msi_cap + PCI_MSI_FLAGS);
    control &= ~(1);
    if ( flag )
        control |= flag;
    pci_conf_write16(bus, dev, func,
        iommu->msi_cap + PCI_MSI_FLAGS, control);
}

static void iommu_msi_unmask(unsigned int irq)
{
    unsigned long flags;
    struct amd_iommu *iommu = irq_to_iommu[irq];

    /* FIXME: do not support mask bits at the moment */
    if ( iommu->maskbit )
        return;

    spin_lock_irqsave(&iommu->lock, flags);
    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_ENABLED);
    spin_unlock_irqrestore(&iommu->lock, flags);
}

static void iommu_msi_mask(unsigned int irq)
{
    unsigned long flags;
    struct amd_iommu *iommu = irq_to_iommu[irq];
    struct irq_desc *desc = irq_to_desc(irq);

    irq_complete_move(&desc);

    /* FIXME: do not support mask bits at the moment */
    if ( iommu->maskbit )
        return;

    spin_lock_irqsave(&iommu->lock, flags);
    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_DISABLED);
    spin_unlock_irqrestore(&iommu->lock, flags);
}

static unsigned int iommu_msi_startup(unsigned int irq)
{
    iommu_msi_unmask(irq);
    return 0;
}

static void iommu_msi_end(unsigned int irq)
{
    iommu_msi_unmask(irq);
    ack_APIC_irq();
}


static hw_irq_controller iommu_msi_type = {
    .typename = "AMD_IOV_MSI",
    .startup = iommu_msi_startup,
    .shutdown = iommu_msi_mask,
    .enable = iommu_msi_unmask,
    .disable = iommu_msi_mask,
    .ack = iommu_msi_mask,
    .end = iommu_msi_end,
    .set_affinity = iommu_msi_set_affinity,
};

static void parse_event_log_entry(u32 entry[])
{
    u16 domain_id, device_id;
    u32 code;
    u64 *addr;
    char * event_str[] = {"ILLEGAL_DEV_TABLE_ENTRY",
                          "IO_PAGE_FALT",
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

    if ( code == IOMMU_EVENT_IO_PAGE_FALT )
    {
        device_id = get_field_from_reg_u32(entry[0],
                                           IOMMU_EVENT_DEVICE_ID_MASK,
                                           IOMMU_EVENT_DEVICE_ID_SHIFT);
        domain_id = get_field_from_reg_u32(entry[1],
                                           IOMMU_EVENT_DOMAIN_ID_MASK,
                                           IOMMU_EVENT_DOMAIN_ID_SHIFT);
        addr= (u64*) (entry + 2);
        printk(XENLOG_ERR "AMD_IOV: "
            "%s: domain:%d, device id:0x%x, fault address:0x%"PRIx64"\n",
            event_str[code-1], domain_id, device_id, *addr);
    }
}

static void amd_iommu_page_fault(int irq, void *dev_id,
                             struct cpu_user_regs *regs)
{
    u32 entry;
    unsigned long flags;
    int of;
    struct amd_iommu *iommu = dev_id;

    spin_lock_irqsave(&iommu->lock, flags);
    amd_iommu_read_event_log(iommu);

    /*check event overflow */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    of = get_field_from_reg_u32(entry,
                               IOMMU_STATUS_EVENT_OVERFLOW_MASK,
                               IOMMU_STATUS_EVENT_OVERFLOW_SHIFT);

    /* reset event log if event overflow */
    if ( of )
        amd_iommu_reset_event_log(iommu);

    /* reset interrupt status bit */
    entry = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_STATUS_EVENT_LOG_INT_MASK,
                         IOMMU_STATUS_EVENT_LOG_INT_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_STATUS_MMIO_OFFSET);
    spin_unlock_irqrestore(&iommu->lock, flags);
}

static int set_iommu_interrupt_handler(struct amd_iommu *iommu)
{
    int irq, ret;

    irq = create_irq();
    if ( irq <= 0 )
    {
        dprintk(XENLOG_ERR, "IOMMU: no irqs\n");
        return 0;
    }
    
    irq_desc[irq].handler = &iommu_msi_type;
    irq_to_iommu[irq] = iommu;
    ret = request_irq(irq, amd_iommu_page_fault, 0,
                             "amd_iommu", iommu);
    if ( ret )
    {
        irq_desc[irq].handler = &no_irq_type;
        irq_to_iommu[irq] = NULL;
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

    iommu_msi_set_affinity(iommu->irq, cpu_online_map);
    amd_iommu_msi_enable(iommu, IOMMU_CONTROL_ENABLED);

    set_iommu_command_buffer_control(iommu, IOMMU_CONTROL_ENABLED);
    set_iommu_event_log_control(iommu, IOMMU_CONTROL_ENABLED);
    set_iommu_translation_control(iommu, IOMMU_CONTROL_ENABLED);

    iommu->enabled = 1;
    spin_unlock_irqrestore(&iommu->lock, flags);

}

static void __init deallocate_iommu_table_struct(
    struct table_struct *table)
{
    int order = 0;
    if ( table->buffer )
    {
        order = get_order_from_bytes(table->alloc_size);
        __free_amd_iommu_tables(table->buffer, order);
        table->buffer = NULL;
    }
}

static int __init allocate_iommu_table_struct(struct table_struct *table,
                                              const char *name)
{
    int order = 0;
    if ( table->buffer == NULL )
    {
        order = get_order_from_bytes(table->alloc_size);
        table->buffer = __alloc_amd_iommu_tables(order);

        if ( table->buffer == NULL )
        {
            AMD_IOMMU_DEBUG("Error allocating %s\n", name);
            return -ENOMEM;
        }
        memset(table->buffer, 0, PAGE_SIZE * (1UL << order));
    }
    return 0;
}

static int __init allocate_cmd_buffer(struct amd_iommu *iommu)
{
    /* allocate 'command buffer' in power of 2 increments of 4K */
    iommu->cmd_buffer_tail = 0;
    iommu->cmd_buffer.alloc_size = PAGE_SIZE <<
                                   get_order_from_bytes(
                                   PAGE_ALIGN(amd_iommu_cmd_buffer_entries *
                                   IOMMU_CMD_BUFFER_ENTRY_SIZE));
    iommu->cmd_buffer.entries = iommu->cmd_buffer.alloc_size /
                                IOMMU_CMD_BUFFER_ENTRY_SIZE;

    return (allocate_iommu_table_struct(&iommu->cmd_buffer, "Command Buffer"));
}

static int __init allocate_event_log(struct amd_iommu *iommu)
{
   /* allocate 'event log' in power of 2 increments of 4K */
    iommu->event_log_head = 0;
    iommu->event_log.alloc_size = PAGE_SIZE <<
                                  get_order_from_bytes(
                                  PAGE_ALIGN(amd_iommu_event_log_entries *
                                  IOMMU_EVENT_LOG_ENTRY_SIZE));
    iommu->event_log.entries = iommu->event_log.alloc_size /
                               IOMMU_EVENT_LOG_ENTRY_SIZE;

    return (allocate_iommu_table_struct(&iommu->event_log, "Event Log"));
}

static int __init amd_iommu_init_one(struct amd_iommu *iommu)
{
    if ( allocate_cmd_buffer(iommu) != 0 )
        goto error_out;

    if ( allocate_event_log(iommu) != 0 )
        goto error_out;

    if ( map_iommu_mmio_region(iommu) != 0 )
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

    return 0;

error_out:
    return -ENODEV;
}

static void __init amd_iommu_init_cleanup(void)
{
    struct amd_iommu *iommu, *next;
    int bdf;

    /* free amd iommu list */
    list_for_each_entry_safe ( iommu, next, &amd_iommu_head, list )
    {
        list_del(&iommu->list);
        if ( iommu->enabled )
        {
            deallocate_iommu_table_struct(&iommu->cmd_buffer);
            deallocate_iommu_table_struct(&iommu->event_log);
            unmap_iommu_mmio_region(iommu);
        }
        xfree(iommu);
    }

    /* free interrupt remapping table */
    for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
    {
        if ( ivrs_mappings[bdf].intremap_table )
            amd_iommu_free_intremap_table(bdf);
    }

    /* free device table */
    deallocate_iommu_table_struct(&device_table);

    /* free ivrs_mappings[] */
    if ( ivrs_mappings )
    {
        xfree(ivrs_mappings);
        ivrs_mappings = NULL;
    }

    /* free irq_to_iommu[] */
    if ( irq_to_iommu )
    {
        xfree(irq_to_iommu);
        irq_to_iommu = NULL;
    }

    iommu_enabled = 0;
    iommu_passthrough = 0;
    iommu_intremap = 0;
}

static int __init init_ivrs_mapping(void)
{
    int bdf;

    BUG_ON( !ivrs_bdf_entries );

    ivrs_mappings = xmalloc_array( struct ivrs_mappings, ivrs_bdf_entries);
    if ( ivrs_mappings == NULL )
    {
        AMD_IOMMU_DEBUG("Error allocating IVRS Mappings table\n");
        return -ENOMEM;
    }
    memset(ivrs_mappings, 0, ivrs_bdf_entries * sizeof(struct ivrs_mappings));

    /* assign default values for device entries */
    for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
    {
        ivrs_mappings[bdf].dte_requestor_id = bdf;
        ivrs_mappings[bdf].dte_sys_mgt_enable =
            IOMMU_DEV_TABLE_SYS_MGT_MSG_FORWARDED;
        ivrs_mappings[bdf].dte_allow_exclusion = IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].unity_map_enable = IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].iommu = NULL;

        ivrs_mappings[bdf].intremap_table = NULL;
        ivrs_mappings[bdf].dte_lint1_pass = IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].dte_lint0_pass = IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].dte_nmi_pass = IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].dte_ext_int_pass = IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].dte_init_pass = IOMMU_CONTROL_DISABLED;

        if ( amd_iommu_perdev_intremap )
            spin_lock_init(&ivrs_mappings[bdf].intremap_lock);
    }
    return 0;
}

static int __init amd_iommu_setup_device_table(void)
{
    int bdf;
    void *intr_tb, *dte;
    int sys_mgt, dev_ex, lint1_pass, lint0_pass,
       nmi_pass, ext_int_pass, init_pass;

    BUG_ON( (ivrs_bdf_entries == 0) );

    /* allocate 'device table' on a 4K boundary */
    device_table.alloc_size = PAGE_SIZE <<
                              get_order_from_bytes(
                              PAGE_ALIGN(ivrs_bdf_entries *
                              IOMMU_DEV_TABLE_ENTRY_SIZE));
    device_table.entries = device_table.alloc_size /
                           IOMMU_DEV_TABLE_ENTRY_SIZE;

    if ( allocate_iommu_table_struct(&device_table, "Device Table") != 0 )
         return -ENOMEM;

    /* Add device table entries */
    for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
    {
        intr_tb = ivrs_mappings[bdf].intremap_table;

        if ( intr_tb )
        {
            sys_mgt = ivrs_mappings[bdf].dte_sys_mgt_enable;
            dev_ex = ivrs_mappings[bdf].dte_allow_exclusion;

            /* get interrupt remapping settings */
            lint1_pass = ivrs_mappings[bdf].dte_lint1_pass;
            lint0_pass = ivrs_mappings[bdf].dte_lint0_pass;
            nmi_pass = ivrs_mappings[bdf].dte_nmi_pass;
            ext_int_pass = ivrs_mappings[bdf].dte_ext_int_pass;
            init_pass = ivrs_mappings[bdf].dte_init_pass;

            /* add device table entry */
            dte = device_table.buffer + (bdf * IOMMU_DEV_TABLE_ENTRY_SIZE);
            amd_iommu_add_dev_table_entry(
                dte, sys_mgt, dev_ex, lint1_pass, lint0_pass,
                nmi_pass, ext_int_pass, init_pass);

            amd_iommu_set_intremap_table(
                dte, (u64)virt_to_maddr(intr_tb), iommu_intremap);

            AMD_IOMMU_DEBUG("Add device table entry at DTE:0x%x, "
                "intremap_table:%"PRIx64"\n", bdf,
                (u64)virt_to_maddr(intr_tb));
        }
    }

    return 0;
}

int __init amd_iommu_init(void)
{
    struct amd_iommu *iommu;

    BUG_ON( !iommu_found() );

    irq_to_iommu = xmalloc_array(struct amd_iommu *, nr_irqs);
    if ( irq_to_iommu == NULL )
        goto error_out;
    memset(irq_to_iommu, 0, nr_irqs * sizeof(struct iommu*));

    ivrs_bdf_entries = amd_iommu_get_ivrs_dev_entries();

    if ( !ivrs_bdf_entries )
        goto error_out;

    if ( init_ivrs_mapping() != 0 )
        goto error_out;

    if ( amd_iommu_update_ivrs_mapping_acpi() != 0 )
        goto error_out;

    /* initialize io-apic interrupt remapping entries */
    if ( amd_iommu_setup_ioapic_remapping() != 0 )
        goto error_out;

    /* allocate and initialize a global device table shared by all iommus */
    if ( amd_iommu_setup_device_table() != 0 )
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
    set_iommu_translation_control(iommu, IOMMU_CONTROL_DISABLED);

    iommu->enabled = 0;

    spin_unlock_irqrestore(&iommu->lock, flags);

}

static void invalidate_all_domain_pages(void)
{
    struct domain *d;
    for_each_domain( d )
        invalidate_all_iommu_pages(d);
}

static void invalidate_all_devices(void)
{
    int bdf, req_id;
    unsigned long flags;
    struct amd_iommu *iommu;

    for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
    {
        iommu = find_iommu_for_device(bdf);
        req_id = ivrs_mappings[bdf].dte_requestor_id;
        if ( iommu )
        {
            spin_lock_irqsave(&iommu->lock, flags);
            invalidate_dev_table_entry(iommu, req_id);
            invalidate_interrupt_table(iommu, req_id);
            flush_command_buffer(iommu);
            spin_unlock_irqrestore(&iommu->lock, flags);
        }
    }
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
    invalidate_all_devices();
    invalidate_all_domain_pages();
}
