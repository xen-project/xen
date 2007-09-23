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

#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <xen/sched.h>
#include <asm/mm.h>
#include "pci-direct.h"
#include "pci_regs.h"

struct list_head amd_iommu_head;
long amd_iommu_poll_comp_wait = COMPLETION_WAIT_DEFAULT_POLLING_COUNT;
static long amd_iommu_cmd_buffer_entries = IOMMU_CMD_BUFFER_DEFAULT_ENTRIES;
int nr_amd_iommus = 0;

/* will set if amd-iommu HW is found */
int amd_iommu_enabled = 0;

static int enable_amd_iommu = 0;
boolean_param("enable_amd_iommu", enable_amd_iommu);

static void deallocate_domain_page_tables(struct hvm_iommu *hd)
{
    if ( hd->root_table )
        free_xenheap_page(hd->root_table);
}

static void deallocate_domain_resources(struct hvm_iommu *hd)
{
    deallocate_domain_page_tables(hd);
}

static void __init init_cleanup(void)
{
    struct amd_iommu *iommu;

    dprintk(XENLOG_ERR, "AMD IOMMU: %s()\n", __FUNCTION__);

    for_each_amd_iommu(iommu) {
        unmap_iommu_mmio_region(iommu);
    }
}

static void __init deallocate_iommu_table_struct(
            struct table_struct *table)
{
    if (table->buffer) {
        free_xenheap_pages(table->buffer,
            get_order_from_bytes(table->alloc_size));
        table->buffer = NULL;
    }
}

static void __init deallocate_iommu_resources(struct amd_iommu *iommu)
{
    deallocate_iommu_table_struct(&iommu->dev_table);
    deallocate_iommu_table_struct(&iommu->cmd_buffer);;
}

static void __init detect_cleanup(void)
{
    struct amd_iommu *iommu;

    dprintk(XENLOG_ERR, "AMD IOMMU: %s()\n", __FUNCTION__);

    for_each_amd_iommu(iommu) {
        list_del(&iommu->list);
        deallocate_iommu_resources(iommu);
        xfree(iommu);
    }
}

static int requestor_id_from_bdf(int bdf)
{
    /* HACK - HACK */
    /* account for possible 'aliasing' by parent device */
   return bdf;
}

static int __init allocate_iommu_table_struct(struct table_struct *table,
            const char *name)
{
    table->buffer = (void *) alloc_xenheap_pages(
        get_order_from_bytes(table->alloc_size));

    if ( !table->buffer ) {
        dprintk(XENLOG_ERR, "AMD IOMMU: Error allocating %s\n", name);
        return -ENOMEM;
    }
    memset(table->buffer, 0, table->alloc_size);

    return 0;
}

static int __init allocate_iommu_resources(struct amd_iommu *iommu)
{
    /* allocate 'device table' on a 4K boundary */
    iommu->dev_table.alloc_size =
        PAGE_ALIGN(((iommu->last_downstream_bus + 1) *
        IOMMU_DEV_TABLE_ENTRIES_PER_BUS) *
        IOMMU_DEV_TABLE_ENTRY_SIZE);
    iommu->dev_table.entries =
        iommu->dev_table.alloc_size / IOMMU_DEV_TABLE_ENTRY_SIZE;

    if (allocate_iommu_table_struct(&iommu->dev_table,
            "Device Table") != 0)
        goto error_out;

    /* allocate 'command buffer' in power of 2 increments of 4K */
    iommu->cmd_buffer_tail = 0;
    iommu->cmd_buffer.alloc_size =
        PAGE_SIZE << get_order_from_bytes(
        PAGE_ALIGN(amd_iommu_cmd_buffer_entries *
        IOMMU_CMD_BUFFER_ENTRY_SIZE));

   iommu->cmd_buffer.entries =
        iommu->cmd_buffer.alloc_size / IOMMU_CMD_BUFFER_ENTRY_SIZE;

    if ( allocate_iommu_table_struct(&iommu->cmd_buffer,
            "Command Buffer") != 0 )
        goto error_out;

    return 0;

error_out:
    deallocate_iommu_resources(iommu);
    return -ENOMEM;
}

int iommu_detect_callback(u8 bus, u8 dev, u8 func, u8 cap_ptr)
{
    struct amd_iommu *iommu;

    iommu = (struct amd_iommu *) xmalloc(struct amd_iommu);
    if ( !iommu ) {
        dprintk(XENLOG_ERR, "AMD IOMMU: Error allocating amd_iommu\n");
        return -ENOMEM;
    }
    memset(iommu, 0, sizeof(struct amd_iommu));
    spin_lock_init(&iommu->lock);

    /* get capability and topology information */
    if ( get_iommu_capabilities(bus, dev, func, cap_ptr, iommu) != 0 )
        goto error_out;
    if ( get_iommu_last_downstream_bus(iommu) != 0 )
        goto error_out;

    list_add_tail(&iommu->list, &amd_iommu_head);

    /* allocate resources for this IOMMU */
    if (allocate_iommu_resources(iommu) != 0)
        goto error_out;

    return 0;

error_out:
    xfree(iommu);
    return -ENODEV;
}

static int __init amd_iommu_init(void)
{
    struct amd_iommu *iommu;
    unsigned long flags;

    for_each_amd_iommu(iommu) {
        spin_lock_irqsave(&iommu->lock, flags);

        /* register IOMMU data strucures in MMIO space */
        if (map_iommu_mmio_region(iommu) != 0)
            goto error_out;
        register_iommu_dev_table_in_mmio_space(iommu);
        register_iommu_cmd_buffer_in_mmio_space(iommu);

        /* enable IOMMU translation services */
        enable_iommu(iommu);
        nr_amd_iommus++;

        spin_unlock_irqrestore(&iommu->lock, flags);
    }

    amd_iommu_enabled = 1;

    return 0;

error_out:
    init_cleanup();
    return -ENODEV;
}

struct amd_iommu *find_iommu_for_device(int bus, int devfn)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu(iommu) {
        if ( bus == iommu->root_bus ) {
            if ( devfn >= iommu->first_devfn &&
                devfn <= iommu->last_devfn )
                return iommu;
        }
        else if ( bus <= iommu->last_downstream_bus ) {
            if ( iommu->downstream_bus_present[bus] )
                return iommu;
        }
    }

    return NULL;
}

void amd_iommu_setup_domain_device(
    struct domain *domain, struct amd_iommu *iommu, int requestor_id)
{
    void *dte;
    u64 root_ptr;
    unsigned long flags;
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    BUG_ON( !hd->root_table||!hd->paging_mode );

    root_ptr = (u64)virt_to_maddr(hd->root_table);
    dte = iommu->dev_table.buffer +
        (requestor_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    spin_lock_irqsave(&iommu->lock, flags); 

    amd_iommu_set_dev_table_entry((u32 *)dte,
        root_ptr, hd->domain_id, hd->paging_mode);

    dprintk(XENLOG_INFO, "AMD IOMMU: Set DTE req_id:%x, "
            "root_ptr:%"PRIx64", domain_id:%d, paging_mode:%d\n",
            requestor_id, root_ptr, hd->domain_id, hd->paging_mode);

    spin_unlock_irqrestore(&iommu->lock, flags);
}

void __init amd_iommu_setup_dom0_devices(void)
{
    struct hvm_iommu *hd = domain_hvm_iommu(dom0);
    struct amd_iommu *iommu;
    struct pci_dev *pdev;
    int bus, dev, func;
    u32 l;
    int req_id, bdf;

    for ( bus = 0; bus < 256; bus++ ) {
        for ( dev = 0; dev < 32; dev++ ) {
            for ( func = 0; func < 8; func++ ) {
                l = read_pci_config(bus, dev, func, PCI_VENDOR_ID);
                /* some broken boards return 0 or ~0 if a slot is empty: */
                if ( l == 0xffffffff || l == 0x00000000 ||
                    l == 0x0000ffff || l == 0xffff0000 )
                    continue;

                pdev = xmalloc(struct pci_dev);
                pdev->bus = bus;
                pdev->devfn = PCI_DEVFN(dev, func);
                list_add_tail(&pdev->list, &hd->pdev_list);

                bdf = (bus << 8) | pdev->devfn;
                req_id = requestor_id_from_bdf(bdf);
                iommu = find_iommu_for_device(bus, pdev->devfn);

                if ( iommu )
                    amd_iommu_setup_domain_device(dom0, iommu, req_id);
            }
        }
    }
}

int amd_iommu_detect(void)
{
    unsigned long i;

    if ( !enable_amd_iommu ) {
        printk("AMD IOMMU: Disabled\n");
        return 0;
    }

    INIT_LIST_HEAD(&amd_iommu_head);

    if ( scan_for_iommu(iommu_detect_callback) != 0 ) {
        dprintk(XENLOG_ERR, "AMD IOMMU: Error detection\n");
        goto error_out;
    }

    if ( !iommu_found() ) {
        printk("AMD IOMMU: Not found!\n");
        return 0;
    }

    if ( amd_iommu_init() != 0 ) {
        dprintk(XENLOG_ERR, "AMD IOMMU: Error initialization\n");
        goto error_out;
    }

    if ( amd_iommu_domain_init(dom0) != 0 )
        goto error_out;

    /* setup 1:1 page table for dom0 */
    for ( i = 0; i < max_page; i++ )
        amd_iommu_map_page(dom0, i, i);

    amd_iommu_setup_dom0_devices();
    return 0;

error_out:
     detect_cleanup();
     return -ENODEV;

}

static int allocate_domain_resources(struct hvm_iommu *hd)
{
    /* allocate root table */
    hd->root_table = (void *)alloc_xenheap_page();
    if ( !hd->root_table )
        return -ENOMEM;
    memset((u8*)hd->root_table, 0, PAGE_SIZE);

    return 0;
}

static int get_paging_mode(unsigned long entries)
{
    int level = 1;

    BUG_ON ( !max_page );

    if ( entries > max_page )
        entries = max_page;

    while ( entries > PTE_PER_TABLE_SIZE ) {
        entries = PTE_PER_TABLE_ALIGN(entries) >> PTE_PER_TABLE_SHIFT;
        ++level;
        if ( level > 6 )
            return -ENOMEM;
    }

    dprintk(XENLOG_INFO, "AMD IOMMU: paging mode = %d\n", level);

    return level;
}

int amd_iommu_domain_init(struct domain *domain)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    spin_lock_init(&hd->mapping_lock);
    spin_lock_init(&hd->iommu_list_lock);
    INIT_LIST_HEAD(&hd->pdev_list);

    /* allocate page directroy */
    if ( allocate_domain_resources(hd) != 0 ) {
        dprintk(XENLOG_ERR, "AMD IOMMU: %s()\n", __FUNCTION__);
        goto error_out;
    }

    if ( is_hvm_domain(domain) )
        hd->paging_mode = IOMMU_PAGE_TABLE_LEVEL_4;
    else
        hd->paging_mode = get_paging_mode(max_page);

    hd->domain_id = domain->domain_id;

    return 0;

error_out:
    deallocate_domain_resources(hd);
    return -ENOMEM;
}


