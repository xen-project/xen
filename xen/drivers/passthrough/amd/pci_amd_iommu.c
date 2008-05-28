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

#include <xen/sched.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <asm/hvm/svm/amd-iommu-acpi.h>
#include <asm/mm.h>

struct list_head amd_iommu_head;
long amd_iommu_poll_comp_wait = COMPLETION_WAIT_DEFAULT_POLLING_COUNT;
static long amd_iommu_cmd_buffer_entries = IOMMU_CMD_BUFFER_DEFAULT_ENTRIES;
static long amd_iommu_event_log_entries = IOMMU_EVENT_LOG_DEFAULT_ENTRIES;
int nr_amd_iommus;

unsigned short ivrs_bdf_entries;
struct ivrs_mappings *ivrs_mappings;

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

    for_each_amd_iommu ( iommu )
        unmap_iommu_mmio_region(iommu);
}

static void __init deallocate_iommu_table_struct(
    struct table_struct *table)
{
    if ( table->buffer )
    {
        free_xenheap_pages(table->buffer,
                           get_order_from_bytes(table->alloc_size));
        table->buffer = NULL;
    }
}

static void __init deallocate_iommu_resources(struct amd_iommu *iommu)
{
    deallocate_iommu_table_struct(&iommu->dev_table);
    deallocate_iommu_table_struct(&iommu->cmd_buffer);
    deallocate_iommu_table_struct(&iommu->event_log);
}

static int __init allocate_iommu_table_struct(struct table_struct *table,
                                              const char *name)
{
    table->buffer = (void *) alloc_xenheap_pages(
        get_order_from_bytes(table->alloc_size));

    if ( !table->buffer )
    {
        amd_iov_error("Error allocating %s\n", name);
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

    if ( allocate_iommu_table_struct(&iommu->dev_table,
                                     "Device Table") != 0 )
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

    /* allocate 'event log' in power of 2 increments of 4K */
    iommu->event_log_head = 0;
    iommu->event_log.alloc_size =
        PAGE_SIZE << get_order_from_bytes(
            PAGE_ALIGN(amd_iommu_event_log_entries *
                        IOMMU_EVENT_LOG_ENTRY_SIZE));

    iommu->event_log.entries =
        iommu->event_log.alloc_size / IOMMU_EVENT_LOG_ENTRY_SIZE;

    if ( allocate_iommu_table_struct(&iommu->event_log,
                                     "Event Log") != 0 )
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
    if ( !iommu )
    {
        amd_iov_error("Error allocating amd_iommu\n");
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
    if ( allocate_iommu_resources(iommu) != 0 )
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
    u16 bdf;

    for_each_amd_iommu ( iommu )
    {
        spin_lock_irqsave(&iommu->lock, flags);

        /* assign default IOMMU values */
        iommu->coherent = IOMMU_CONTROL_ENABLED;
        iommu->isochronous = IOMMU_CONTROL_ENABLED;
        iommu->res_pass_pw = IOMMU_CONTROL_ENABLED;
        iommu->pass_pw = IOMMU_CONTROL_ENABLED;
        iommu->ht_tunnel_enable = iommu->ht_tunnel_support ?
            IOMMU_CONTROL_ENABLED : IOMMU_CONTROL_DISABLED;
        iommu->exclusion_enable = IOMMU_CONTROL_DISABLED;
        iommu->exclusion_allow_all = IOMMU_CONTROL_DISABLED;

        /* register IOMMU data strucures in MMIO space */
        if ( map_iommu_mmio_region(iommu) != 0 )
            goto error_out;
        register_iommu_dev_table_in_mmio_space(iommu);
        register_iommu_cmd_buffer_in_mmio_space(iommu);
        register_iommu_event_log_in_mmio_space(iommu);

        spin_unlock_irqrestore(&iommu->lock, flags);
    }

    /* assign default values for device entries */
    for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
    {
        ivrs_mappings[bdf].dte_requestor_id = bdf;
        ivrs_mappings[bdf].dte_sys_mgt_enable =
            IOMMU_DEV_TABLE_SYS_MGT_MSG_FORWARDED;
        ivrs_mappings[bdf].dte_allow_exclusion =
            IOMMU_CONTROL_DISABLED;
        ivrs_mappings[bdf].unity_map_enable =
            IOMMU_CONTROL_DISABLED;
    }

    if ( acpi_table_parse(ACPI_IVRS, parse_ivrs_table) != 0 )
        amd_iov_error("Did not find IVRS table!\n");

    for_each_amd_iommu ( iommu )
    {
        /* enable IOMMU translation services */
        enable_iommu(iommu);
        nr_amd_iommus++;
    }

    return 0;

 error_out:
    init_cleanup();
    return -ENODEV;
}

struct amd_iommu *find_iommu_for_device(int bus, int devfn)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu ( iommu )
    {
        if ( bus == iommu->root_bus )
        {
            if ( (devfn >= iommu->first_devfn) &&
                 (devfn <= iommu->last_devfn) )
                return iommu;
        }
        else if ( bus <= iommu->last_downstream_bus )
        {
            if ( iommu->downstream_bus_present[bus] )
                return iommu;
        }
    }

    return NULL;
}

static void amd_iommu_setup_domain_device(
    struct domain *domain, struct amd_iommu *iommu, int bdf)
{
    void *dte;
    u64 root_ptr;
    unsigned long flags;
    int req_id;
    u8 sys_mgt, dev_ex;
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    BUG_ON( !hd->root_table || !hd->paging_mode );

    root_ptr = (u64)virt_to_maddr(hd->root_table);
    /* get device-table entry */
    req_id = ivrs_mappings[bdf].dte_requestor_id;
    dte = iommu->dev_table.buffer +
        (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    if ( !amd_iommu_is_dte_page_translation_valid((u32 *)dte) )
    {
        spin_lock_irqsave(&iommu->lock, flags); 

        /* bind DTE to domain page-tables */
        sys_mgt = ivrs_mappings[req_id].dte_sys_mgt_enable;
        dev_ex = ivrs_mappings[req_id].dte_allow_exclusion;
        amd_iommu_set_dev_table_entry((u32 *)dte, root_ptr,
                                      hd->domain_id, sys_mgt, dev_ex,
                                      hd->paging_mode);

        invalidate_dev_table_entry(iommu, req_id);
        flush_command_buffer(iommu);
        amd_iov_info("Enable DTE:0x%x, "
                "root_ptr:%"PRIx64", domain_id:%d, paging_mode:%d\n",
                req_id, root_ptr, hd->domain_id, hd->paging_mode);

        spin_unlock_irqrestore(&iommu->lock, flags);
    }
}

static void amd_iommu_setup_dom0_devices(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct amd_iommu *iommu;
    struct pci_dev *pdev;
    int bus, dev, func;
    u32 l;
    int bdf;

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( dev = 0; dev < 32; dev++ )
        {
            for ( func = 0; func < 8; func++ )
            {
                l = pci_conf_read32(bus, dev, func, PCI_VENDOR_ID);
                /* some broken boards return 0 or ~0 if a slot is empty: */
                if ( (l == 0xffffffff) || (l == 0x00000000) ||
                     (l == 0x0000ffff) || (l == 0xffff0000) )
                    continue;

                pdev = xmalloc(struct pci_dev);
                pdev->bus = bus;
                pdev->devfn = PCI_DEVFN(dev, func);
                list_add_tail(&pdev->list, &hd->pdev_list);

                bdf = (bus << 8) | pdev->devfn;
                /* supported device? */
                iommu = (bdf < ivrs_bdf_entries) ?
                    find_iommu_for_device(bus, pdev->devfn) : NULL;

                if ( iommu )
                    amd_iommu_setup_domain_device(d, iommu, bdf);
            }
        }
    }
}

int amd_iov_detect(void)
{
    int last_bus;
    struct amd_iommu *iommu, *next;

    INIT_LIST_HEAD(&amd_iommu_head);

    if ( scan_for_iommu(iommu_detect_callback) != 0 )
    {
        amd_iov_error("Error detection\n");
        goto error_out;
    }

    if ( !iommu_found() )
    {
        printk("AMD_IOV: IOMMU not found!\n");
        goto error_out;
    }

    /* allocate 'ivrs mappings' table */
    /* note: the table has entries to accomodate all IOMMUs */
    last_bus = 0;
    for_each_amd_iommu ( iommu )
        if ( iommu->last_downstream_bus > last_bus )
            last_bus = iommu->last_downstream_bus;

    ivrs_bdf_entries = (last_bus + 1) *
        IOMMU_DEV_TABLE_ENTRIES_PER_BUS;
    ivrs_mappings = xmalloc_array( struct ivrs_mappings, ivrs_bdf_entries);
    if ( ivrs_mappings == NULL )
    {
        amd_iov_error("Error allocating IVRS DevMappings table\n");
        goto error_out;
    }
    memset(ivrs_mappings, 0,
           ivrs_bdf_entries * sizeof(struct ivrs_mappings));

    if ( amd_iommu_init() != 0 )
    {
        amd_iov_error("Error initialization\n");
        goto error_out;
    }

    return 0;

 error_out:
    list_for_each_entry_safe ( iommu, next, &amd_iommu_head, list )
    {
        list_del(&iommu->list);
        deallocate_iommu_resources(iommu);
        xfree(iommu);
    }

    if ( ivrs_mappings )
    {
        xfree(ivrs_mappings);
        ivrs_mappings = NULL;
    }

    return -ENODEV;
}

static int allocate_domain_resources(struct hvm_iommu *hd)
{
    /* allocate root table */
    unsigned long flags;

    spin_lock_irqsave(&hd->mapping_lock, flags);
    if ( !hd->root_table )
    {
        hd->root_table = (void *)alloc_xenheap_page();
        if ( !hd->root_table )
            goto error_out;
        memset((u8*)hd->root_table, 0, PAGE_SIZE);
    }
    spin_unlock_irqrestore(&hd->mapping_lock, flags);

    return 0;

 error_out:
    spin_unlock_irqrestore(&hd->mapping_lock, flags);
    return -ENOMEM;
}

static int get_paging_mode(unsigned long entries)
{
    int level = 1;

    BUG_ON(!max_page);

    if ( entries > max_page )
        entries = max_page;

    while ( entries > PTE_PER_TABLE_SIZE )
    {
        entries = PTE_PER_TABLE_ALIGN(entries) >> PTE_PER_TABLE_SHIFT;
        if ( ++level > 6 )
            return -ENOMEM;
    }

    return level;
}

static int amd_iommu_domain_init(struct domain *domain)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    /* allocate page directroy */
    if ( allocate_domain_resources(hd) != 0 )
    {
        deallocate_domain_resources(hd);
        return -ENOMEM;
    }

    hd->paging_mode = is_hvm_domain(domain)?
        IOMMU_PAGE_TABLE_LEVEL_4 : get_paging_mode(max_page);

    if ( domain->domain_id == 0 )
    {
        unsigned long i; 
       /* setup 1:1 page table for dom0 */
        for ( i = 0; i < max_page; i++ )
            amd_iommu_map_page(domain, i, i);

        amd_iommu_setup_dom0_devices(domain);
    }

    hd->domain_id = domain->domain_id;

    return 0;
}

static void amd_iommu_disable_domain_device(
    struct domain *domain, struct amd_iommu *iommu, int bdf)
{
    void *dte;
    unsigned long flags;
    int req_id;

    req_id = ivrs_mappings[bdf].dte_requestor_id;
    dte = iommu->dev_table.buffer +
        (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    if ( amd_iommu_is_dte_page_translation_valid((u32 *)dte) )
    {
        spin_lock_irqsave(&iommu->lock, flags); 
        memset (dte, 0, IOMMU_DEV_TABLE_ENTRY_SIZE);
        invalidate_dev_table_entry(iommu, req_id);
        flush_command_buffer(iommu);
        amd_iov_info("Disable DTE:0x%x,"
                " domain_id:%d, paging_mode:%d\n",
                req_id,  domain_hvm_iommu(domain)->domain_id,
                domain_hvm_iommu(domain)->paging_mode);
        spin_unlock_irqrestore(&iommu->lock, flags);
    }
}

extern void pdev_flr(u8 bus, u8 devfn);

static int reassign_device( struct domain *source, struct domain *target,
                            u8 bus, u8 devfn)
{
    struct hvm_iommu *source_hd = domain_hvm_iommu(source);
    struct hvm_iommu *target_hd = domain_hvm_iommu(target);
    struct pci_dev *pdev;
    struct amd_iommu *iommu;
    int bdf;
    unsigned long flags;

    for_each_pdev ( source, pdev )
    {
        if ( (pdev->bus != bus) || (pdev->devfn != devfn) )
            continue;

        pdev->bus = bus;
        pdev->devfn = devfn;

        bdf = (bus << 8) | devfn;
        /* supported device? */
        iommu = (bdf < ivrs_bdf_entries) ?
            find_iommu_for_device(bus, pdev->devfn) : NULL;

        if ( !iommu )
        {
            amd_iov_error("Fail to find iommu."
                     " %x:%x.%x cannot be assigned to domain %d\n", 
                     bus, PCI_SLOT(devfn), PCI_FUNC(devfn), target->domain_id);
            return -ENODEV;
        }

        amd_iommu_disable_domain_device(source, iommu, bdf);
        /* Move pci device from the source domain to target domain. */
        spin_lock_irqsave(&source_hd->iommu_list_lock, flags);
        spin_lock_irqsave(&target_hd->iommu_list_lock, flags);
        list_move(&pdev->list, &target_hd->pdev_list);
        spin_unlock_irqrestore(&target_hd->iommu_list_lock, flags);
        spin_unlock_irqrestore(&source_hd->iommu_list_lock, flags);

        amd_iommu_setup_domain_device(target, iommu, bdf);
        amd_iov_info("reassign %x:%x.%x domain %d -> domain %d\n",
                 bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                 source->domain_id, target->domain_id);

        break;
    }
    return 0;
}

static int amd_iommu_assign_device(struct domain *d, u8 bus, u8 devfn)
{
    int bdf = (bus << 8) | devfn;
    int req_id = ivrs_mappings[bdf].dte_requestor_id;

    amd_iommu_sync_p2m(d);

    if ( ivrs_mappings[req_id].unity_map_enable )
    {
        amd_iommu_reserve_domain_unity_map(
            d,
            ivrs_mappings[req_id].addr_range_start,
            ivrs_mappings[req_id].addr_range_length,
            ivrs_mappings[req_id].write_permission,
            ivrs_mappings[req_id].read_permission);
    }

    pdev_flr(bus, devfn);
    return reassign_device(dom0, d, bus, devfn);
}

static void release_domain_devices(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    struct pci_dev *pdev;

    while ( !list_empty(&hd->pdev_list) )
    {
        pdev = list_entry(hd->pdev_list.next, typeof(*pdev), list);
        pdev_flr(pdev->bus, pdev->devfn);
        amd_iov_info("release domain %d devices %x:%x.%x\n", d->domain_id,
                 pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
        reassign_device(d, dom0, pdev->bus, pdev->devfn);
    }
}

static void deallocate_next_page_table(void *table, unsigned long index,
                                       int level)
{
    unsigned long next_index;
    void *next_table, *pde;
    int next_level;

    pde = table + (index * IOMMU_PAGE_TABLE_ENTRY_SIZE);
    next_table = amd_iommu_get_vptr_from_page_table_entry((u32 *)pde);

    if ( next_table )
    {
        next_level = level - 1;
        if ( next_level > 1 )
        {
            next_index = 0;
            do
            {
                deallocate_next_page_table(next_table,
                                           next_index, next_level);
                next_index++;
            } while (next_index < PTE_PER_TABLE_SIZE);
        }

        free_xenheap_page(next_table);
    }
}

static void deallocate_iommu_page_tables(struct domain *d)
{
    unsigned long index;
    struct hvm_iommu *hd  = domain_hvm_iommu(d);

    if ( hd ->root_table )
    {
        index = 0;

        do
        {
            deallocate_next_page_table(hd->root_table,
                                       index, hd->paging_mode);
            index++;
        } while ( index < PTE_PER_TABLE_SIZE );

        free_xenheap_page(hd ->root_table);
    }

    hd ->root_table = NULL;
}

static void amd_iommu_domain_destroy(struct domain *d)
{
    deallocate_iommu_page_tables(d);
    release_domain_devices(d);
}

static void amd_iommu_return_device(
    struct domain *s, struct domain *t, u8 bus, u8 devfn)
{
    pdev_flr(bus, devfn);
    reassign_device(s, t, bus, devfn);
}

static int amd_iommu_group_id(u8 bus, u8 devfn)
{
    int rt;
    int bdf = (bus << 8) | devfn;
    rt = ( bdf < ivrs_bdf_entries ) ?
        ivrs_mappings[bdf].dte_requestor_id :
        bdf;
    return rt;
}

struct iommu_ops amd_iommu_ops = {
    .init = amd_iommu_domain_init,
    .assign_device  = amd_iommu_assign_device,
    .teardown = amd_iommu_domain_destroy,
    .map_page = amd_iommu_map_page,
    .unmap_page = amd_iommu_unmap_page,
    .reassign_device = amd_iommu_return_device,
    .get_device_group_id = amd_iommu_group_id,
};
