/*
 * Copyright (C) 2011 Advanced Micro Devices, Inc.
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

#include "iommu.h"
#include "../ats.h"

#define CMD_COMPLETION_INIT 0
#define CMD_COMPLETION_DONE 1

static void send_iommu_command(struct amd_iommu *iommu,
                               const uint32_t cmd[4])
{
    uint32_t tail;
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);

    tail = iommu->cmd_buffer.tail + sizeof(cmd_entry_t);
    if ( tail == iommu->cmd_buffer.size )
        tail = 0;

    while ( tail == (readl(iommu->mmio_base +
                           IOMMU_CMD_BUFFER_HEAD_OFFSET) &
                     IOMMU_RING_BUFFER_PTR_MASK) )
    {
        printk_once(XENLOG_ERR "AMD IOMMU %pp: no cmd slot available\n",
                    &PCI_SBDF(iommu->seg, iommu->bdf));
        cpu_relax();
    }

    memcpy(iommu->cmd_buffer.buffer + iommu->cmd_buffer.tail,
           cmd, sizeof(cmd_entry_t));

    iommu->cmd_buffer.tail = tail;

    writel(tail, iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET);

    spin_unlock_irqrestore(&iommu->lock, flags);
}

static void flush_command_buffer(struct amd_iommu *iommu,
                                 unsigned int timeout_base)
{
    static DEFINE_PER_CPU(uint64_t, poll_slot);
    uint64_t *this_poll_slot = &this_cpu(poll_slot);
    paddr_t addr = virt_to_maddr(this_poll_slot);
    /* send a COMPLETION_WAIT command to flush command buffer */
    uint32_t cmd[4] = {
        addr | MASK_INSR(IOMMU_CONTROL_ENABLED,
                         IOMMU_COMP_WAIT_S_FLAG_MASK),
        (addr >> 32) | MASK_INSR(IOMMU_CMD_COMPLETION_WAIT,
                                 IOMMU_CMD_OPCODE_MASK),
        CMD_COMPLETION_DONE,
        0
    };
    s_time_t start, timeout;
    static unsigned int __read_mostly threshold = 1;

    ACCESS_ONCE(*this_poll_slot) = CMD_COMPLETION_INIT;

    send_iommu_command(iommu, cmd);

    start = NOW();
    timeout = start + (timeout_base ?: 100) * MILLISECS(threshold);
    while ( ACCESS_ONCE(*this_poll_slot) != CMD_COMPLETION_DONE )
    {
        if ( timeout && NOW() > timeout )
        {
            threshold |= threshold << 1;
            printk(XENLOG_WARNING
                   "AMD IOMMU %pp: %scompletion wait taking too long\n",
                   &PCI_SBDF(iommu->seg, iommu->bdf),
                   timeout_base ? "iotlb " : "");
            timeout = 0;
        }
        cpu_relax();
    }

    if ( !timeout )
        printk(XENLOG_WARNING
               "AMD IOMMU %pp: %scompletion wait took %lums\n",
               &PCI_SBDF(iommu->seg, iommu->bdf),
               timeout_base ? "iotlb " : "",
               (NOW() - start) / 10000000);
}

/* Build low level iommu command messages */
static void invalidate_iommu_pages(struct amd_iommu *iommu,
                                   u64 io_addr, u16 domain_id, u16 order)
{
    u64 addr_lo, addr_hi;
    u32 cmd[4], entry;
    int sflag = 0, pde = 0;

    ASSERT ( order == 0 || order == 9 || order == 18 );

    /* All pages associated with the domainID are invalidated */
    if ( order || (io_addr == INV_IOMMU_ALL_PAGES_ADDRESS ) )
    {
        sflag = 1;
        pde = 1;
    }

    /* If sflag == 1, the size of the invalidate command is determined
     by the first zero bit in the address starting from Address[12] */
    if ( order )
    {
        u64 mask = 1ULL << (order - 1 + PAGE_SHIFT);
        io_addr &= ~mask;
        io_addr |= mask - 1;
    }

    addr_lo = io_addr & DMA_32BIT_MASK;
    addr_hi = io_addr >> 32;

    set_field_in_reg_u32(domain_id, 0,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_MASK,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_IOMMU_PAGES, entry,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    set_field_in_reg_u32(sflag, 0,
                         IOMMU_INV_IOMMU_PAGES_S_FLAG_MASK,
                         IOMMU_INV_IOMMU_PAGES_S_FLAG_SHIFT, &entry);
    set_field_in_reg_u32(pde, entry,
                         IOMMU_INV_IOMMU_PAGES_PDE_FLAG_MASK,
                         IOMMU_INV_IOMMU_PAGES_PDE_FLAG_SHIFT, &entry);
    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, entry,
                         IOMMU_INV_IOMMU_PAGES_ADDR_LOW_MASK,
                         IOMMU_INV_IOMMU_PAGES_ADDR_LOW_SHIFT, &entry);
    cmd[2] = entry;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_INV_IOMMU_PAGES_ADDR_HIGH_MASK,
                         IOMMU_INV_IOMMU_PAGES_ADDR_HIGH_SHIFT, &entry);
    cmd[3] = entry;

    cmd[0] = 0;
    send_iommu_command(iommu, cmd);
}

static void invalidate_iotlb_pages(struct amd_iommu *iommu,
                                   u16 maxpend, u32 pasid, u16 queueid,
                                   u64 io_addr, u16 dev_id, u16 order)
{
    u64 addr_lo, addr_hi;
    u32 cmd[4], entry;
    int sflag = 0;

    ASSERT ( order == 0 || order == 9 || order == 18 );

    if ( order || (io_addr == INV_IOMMU_ALL_PAGES_ADDRESS ) )
        sflag = 1;

    /* If sflag == 1, the size of the invalidate command is determined
     by the first zero bit in the address starting from Address[12] */
    if ( order )
    {
        u64 mask = 1ULL << (order - 1 + PAGE_SHIFT);
        io_addr &= ~mask;
        io_addr |= mask - 1;
    }

    addr_lo = io_addr & DMA_32BIT_MASK;
    addr_hi = io_addr >> 32;

    set_field_in_reg_u32(dev_id, 0,
                         IOMMU_INV_IOTLB_PAGES_DEVICE_ID_MASK,
                         IOMMU_INV_IOTLB_PAGES_DEVICE_ID_SHIFT, &entry);

    set_field_in_reg_u32(maxpend, entry,
                         IOMMU_INV_IOTLB_PAGES_MAXPEND_MASK,
                         IOMMU_INV_IOTLB_PAGES_MAXPEND_SHIFT, &entry);

    set_field_in_reg_u32(pasid & 0xff, entry,
                         IOMMU_INV_IOTLB_PAGES_PASID1_MASK,
                         IOMMU_INV_IOTLB_PAGES_PASID1_SHIFT, &entry);
    cmd[0] = entry;

    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_IOTLB_PAGES, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);

    set_field_in_reg_u32(pasid >> 8, entry,
                         IOMMU_INV_IOTLB_PAGES_PASID2_MASK,
                         IOMMU_INV_IOTLB_PAGES_PASID2_SHIFT,
                         &entry);

    set_field_in_reg_u32(queueid, entry,
                         IOMMU_INV_IOTLB_PAGES_QUEUEID_MASK,
                         IOMMU_INV_IOTLB_PAGES_QUEUEID_SHIFT,
                         &entry);
    cmd[1] = entry;

    set_field_in_reg_u32(sflag, 0,
                         IOMMU_INV_IOTLB_PAGES_S_FLAG_MASK,
                         IOMMU_INV_IOTLB_PAGES_S_FLAG_MASK, &entry);

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, entry,
                         IOMMU_INV_IOTLB_PAGES_ADDR_LOW_MASK,
                         IOMMU_INV_IOTLB_PAGES_ADDR_LOW_SHIFT, &entry);
    cmd[2] = entry;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_INV_IOTLB_PAGES_ADDR_HIGH_MASK,
                         IOMMU_INV_IOTLB_PAGES_ADDR_HIGH_SHIFT, &entry);
    cmd[3] = entry;

    send_iommu_command(iommu, cmd);
}

static void invalidate_dev_table_entry(struct amd_iommu *iommu,
                                       u16 device_id)
{
    u32 cmd[4], entry;

    cmd[3] = cmd[2] = 0;
    set_field_in_reg_u32(device_id, 0,
                         IOMMU_INV_DEVTAB_ENTRY_DEVICE_ID_MASK,
                         IOMMU_INV_DEVTAB_ENTRY_DEVICE_ID_SHIFT, &entry);
    cmd[0] = entry;

    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_DEVTAB_ENTRY, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    send_iommu_command(iommu, cmd);
}

static void invalidate_interrupt_table(struct amd_iommu *iommu, u16 device_id)
{
    u32 cmd[4], entry;

    cmd[3] = cmd[2] = 0;
    set_field_in_reg_u32(device_id, 0,
                         IOMMU_INV_INT_TABLE_DEVICE_ID_MASK,
                         IOMMU_INV_INT_TABLE_DEVICE_ID_SHIFT, &entry);
    cmd[0] = entry;
    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_INT_TABLE, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;
    send_iommu_command(iommu, cmd);
}

static void invalidate_iommu_all(struct amd_iommu *iommu)
{
    u32 cmd[4], entry;

    cmd[3] = cmd[2] = cmd[0] = 0;

    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_IOMMU_ALL, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    send_iommu_command(iommu, cmd);
}

void amd_iommu_flush_iotlb(u8 devfn, const struct pci_dev *pdev,
                           daddr_t daddr, unsigned int order)
{
    struct amd_iommu *iommu;
    unsigned int req_id, queueid, maxpend;

    if ( !ats_enabled )
        return;

    if ( !pci_ats_enabled(pdev->seg, pdev->bus, pdev->devfn) )
        return;

    iommu = find_iommu_for_device(pdev->seg, pdev->sbdf.bdf);

    if ( !iommu )
    {
        AMD_IOMMU_WARN("can't find IOMMU for %pp\n",
                       &PCI_SBDF(pdev->seg, pdev->bus, devfn));
        return;
    }

    if ( !iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
        return;

    req_id = get_dma_requestor_id(iommu->seg, PCI_BDF(pdev->bus, devfn));
    queueid = req_id;
    maxpend = pdev->ats.queue_depth & 0xff;

    /* send INVALIDATE_IOTLB_PAGES command */
    invalidate_iotlb_pages(iommu, maxpend, 0, queueid, daddr, req_id, order);
    flush_command_buffer(iommu, iommu_dev_iotlb_timeout);
}

static void amd_iommu_flush_all_iotlbs(const struct domain *d, daddr_t daddr,
                                       unsigned int order)
{
    struct pci_dev *pdev;

    for_each_pdev( d, pdev )
    {
        u8 devfn = pdev->devfn;

        do {
            amd_iommu_flush_iotlb(devfn, pdev, daddr, order);
            devfn += pdev->phantom_stride;
        } while ( devfn != pdev->devfn &&
                  PCI_SLOT(devfn) == PCI_SLOT(pdev->devfn) );
    }
}

/* Flush iommu cache after p2m changes. */
static void _amd_iommu_flush_pages(struct domain *d,
                                   daddr_t daddr, unsigned int order)
{
    struct amd_iommu *iommu;
    unsigned int dom_id = d->domain_id;

    /* send INVALIDATE_IOMMU_PAGES command */
    for_each_amd_iommu ( iommu )
    {
        invalidate_iommu_pages(iommu, daddr, dom_id, order);
        flush_command_buffer(iommu, 0);
    }

    if ( ats_enabled )
    {
        amd_iommu_flush_all_iotlbs(d, daddr, order);

        /*
         * Hidden devices are associated with DomXEN but usable by the
         * hardware domain. Hence they need dealing with here as well.
         */
        if ( is_hardware_domain(d) )
            amd_iommu_flush_all_iotlbs(dom_xen, daddr, order);
    }
}

void amd_iommu_flush_all_pages(struct domain *d)
{
    _amd_iommu_flush_pages(d, INV_IOMMU_ALL_PAGES_ADDRESS, 0);
}

void amd_iommu_flush_pages(struct domain *d,
                           unsigned long dfn, unsigned int order)
{
    _amd_iommu_flush_pages(d, __dfn_to_daddr(dfn), order);
}

void amd_iommu_flush_device(struct amd_iommu *iommu, uint16_t bdf,
                            domid_t domid)
{
    invalidate_dev_table_entry(iommu, bdf);
    flush_command_buffer(iommu, 0);

    /* Also invalidate IOMMU TLB entries when flushing the DTE. */
    if ( domid != DOMID_INVALID )
    {
        invalidate_iommu_pages(iommu, INV_IOMMU_ALL_PAGES_ADDRESS, domid, 0);
        flush_command_buffer(iommu, 0);
    }
}

void amd_iommu_flush_intremap(struct amd_iommu *iommu, uint16_t bdf)
{
    invalidate_interrupt_table(iommu, bdf);
    flush_command_buffer(iommu, 0);
}

void amd_iommu_flush_all_caches(struct amd_iommu *iommu)
{
    invalidate_iommu_all(iommu);
    flush_command_buffer(iommu, 0);
}
