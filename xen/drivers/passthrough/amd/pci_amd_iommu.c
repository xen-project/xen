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

extern unsigned short ivrs_bdf_entries;
extern struct ivrs_mappings *ivrs_mappings;
extern void *int_remap_table;

int __init amd_iommu_init(void)
{
    struct amd_iommu *iommu;

    BUG_ON( !iommu_found() );

    ivrs_bdf_entries = amd_iommu_get_ivrs_dev_entries();

    if ( !ivrs_bdf_entries )
        goto error_out;

    if ( amd_iommu_setup_shared_tables() != 0 )
        goto error_out;

    if ( amd_iommu_update_ivrs_mapping_acpi() != 0 )
        goto error_out;

    for_each_amd_iommu ( iommu )
        if ( amd_iommu_init_one(iommu) != 0 )
            goto error_out;

    return 0;

error_out:
    amd_iommu_init_cleanup();
    return -ENODEV;
}

struct amd_iommu *find_iommu_for_device(int bus, int devfn)
{
    u16 bdf = (bus << 8) | devfn;
    BUG_ON ( bdf >= ivrs_bdf_entries );
    return ivrs_mappings[bdf].iommu;
}

static void amd_iommu_setup_domain_device(
    struct domain *domain, struct amd_iommu *iommu, int bdf)
{
    void *dte;
    unsigned long flags;
    int req_id;
    u8 sys_mgt, dev_ex, valid = 1, int_valid = 1;
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    BUG_ON( !hd->root_table || !hd->paging_mode || !int_remap_table );

    /* get device-table entry */
    req_id = ivrs_mappings[bdf].dte_requestor_id;
    dte = iommu->dev_table.buffer + (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    spin_lock_irqsave(&iommu->lock, flags);

    if ( !amd_iommu_is_dte_page_translation_valid((u32 *)dte) )
    {
        /* bind DTE to domain page-tables */
        sys_mgt = ivrs_mappings[req_id].dte_sys_mgt_enable;
        dev_ex = ivrs_mappings[req_id].dte_allow_exclusion;

        if ( iommu_passthrough && (domain->domain_id == 0) )
            valid = 0;
        if ( !iommu_intremap )
            int_valid = 0;

        amd_iommu_set_dev_table_entry((u32 *)dte,
                                      page_to_maddr(hd->root_table),
                                      virt_to_maddr(int_remap_table),
                                      hd->domain_id, sys_mgt, dev_ex,
                                      hd->paging_mode, valid, int_valid);

        invalidate_dev_table_entry(iommu, req_id);
        invalidate_interrupt_table(iommu, req_id);
        flush_command_buffer(iommu);
        amd_iov_info("Enable DTE:0x%x, "
                "root_table:%"PRIx64", interrupt_table:%"PRIx64", "
                "domain_id:%d, paging_mode:%d\n",
                req_id, (u64)page_to_maddr(hd->root_table),
                (u64)virt_to_maddr(int_remap_table), hd->domain_id,
                hd->paging_mode);
    }

    spin_unlock_irqrestore(&iommu->lock, flags);

}

static void amd_iommu_setup_dom0_devices(struct domain *d)
{
    struct amd_iommu *iommu;
    struct pci_dev *pdev;
    int bus, dev, func;
    u32 l;
    int bdf;

    spin_lock(&pcidevs_lock);
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

                pdev = alloc_pdev(bus, PCI_DEVFN(dev, func));
                pdev->domain = d;
                list_add(&pdev->domain_list, &d->arch.pdev_list);

                bdf = (bus << 8) | pdev->devfn;
                /* supported device? */
                iommu = (bdf < ivrs_bdf_entries) ?
                    find_iommu_for_device(bus, pdev->devfn) : NULL;

                if ( iommu )
                    amd_iommu_setup_domain_device(d, iommu, bdf);
            }
        }
    }
    spin_unlock(&pcidevs_lock);
}

int amd_iov_detect(void)
{
    INIT_LIST_HEAD(&amd_iommu_head);

    if ( amd_iommu_detect_acpi() != 0 )
    {
        amd_iov_error("Error detection\n");
        return -ENODEV;
    }

    if ( !iommu_found() )
    {
        printk("AMD_IOV: IOMMU not found!\n");
        return -ENODEV;
    }

    if ( amd_iommu_init() != 0 )
    {
        amd_iov_error("Error initialization\n");
        return -ENODEV;
    }
    return 0;
}

static int allocate_domain_resources(struct hvm_iommu *hd)
{
    /* allocate root table */
    spin_lock(&hd->mapping_lock);
    if ( !hd->root_table )
    {
        hd->root_table = alloc_amd_iommu_pgtable();
        if ( !hd->root_table )
        {
            spin_unlock(&hd->mapping_lock);
            return -ENOMEM;
        }
    }
    spin_unlock(&hd->mapping_lock);
    return 0;
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
        if ( hd->root_table )
            free_domheap_page(hd->root_table);
        return -ENOMEM;
    }

    hd->paging_mode = is_hvm_domain(domain)?
        IOMMU_PAGE_TABLE_LEVEL_4 : get_paging_mode(max_page);

    if ( domain->domain_id == 0 )
    {
        unsigned long i; 

        if ( !iommu_passthrough )
        {
            /* setup 1:1 page table for dom0 */
            for ( i = 0; i < max_page; i++ )
                amd_iommu_map_page(domain, i, i);
        }

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
    dte = iommu->dev_table.buffer + (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    spin_lock_irqsave(&iommu->lock, flags); 
    if ( amd_iommu_is_dte_page_translation_valid((u32 *)dte) )
    {
        memset (dte, 0, IOMMU_DEV_TABLE_ENTRY_SIZE);
        invalidate_dev_table_entry(iommu, req_id);
        flush_command_buffer(iommu);
        amd_iov_info("Disable DTE:0x%x,"
                " domain_id:%d, paging_mode:%d\n",
                req_id,  domain_hvm_iommu(domain)->domain_id,
                domain_hvm_iommu(domain)->paging_mode);
    }
    spin_unlock_irqrestore(&iommu->lock, flags);
}

static int reassign_device( struct domain *source, struct domain *target,
                            u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    struct amd_iommu *iommu;
    int bdf;

    ASSERT(spin_is_locked(&pcidevs_lock));
    pdev = pci_get_pdev_by_domain(source, bus, devfn);
    if ( !pdev )
        return -ENODEV;

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

    list_move(&pdev->domain_list, &target->arch.pdev_list);
    pdev->domain = target;

    amd_iommu_setup_domain_device(target, iommu, bdf);
    amd_iov_info("reassign %x:%x.%x domain %d -> domain %d\n",
                 bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                 source->domain_id, target->domain_id);

    return 0;
}

static int amd_iommu_assign_device(struct domain *d, u8 bus, u8 devfn)
{
    int bdf = (bus << 8) | devfn;
    int req_id = ivrs_mappings[bdf].dte_requestor_id;

    if ( ivrs_mappings[req_id].unity_map_enable )
    {
        amd_iommu_reserve_domain_unity_map(
            d,
            ivrs_mappings[req_id].addr_range_start,
            ivrs_mappings[req_id].addr_range_length,
            ivrs_mappings[req_id].write_permission,
            ivrs_mappings[req_id].read_permission);
    }

    return reassign_device(dom0, d, bus, devfn);
}

static void deallocate_next_page_table(struct page_info* pg, int level)
{
    void *table_vaddr, *pde;
    u64 next_table_maddr;
    int index;

    table_vaddr = map_domain_page(page_to_mfn(pg));

    if ( level > 1 )
    {
        for ( index = 0; index < PTE_PER_TABLE_SIZE; index++ )
        {
            pde = table_vaddr + (index * IOMMU_PAGE_TABLE_ENTRY_SIZE);
            next_table_maddr = amd_iommu_get_next_table_from_pte(pde);
            if ( next_table_maddr != 0 )
            {
                deallocate_next_page_table(
                    maddr_to_page(next_table_maddr), level - 1);
            }
        }
    }

    unmap_domain_page(table_vaddr);
    free_amd_iommu_pgtable(pg);
}

static void deallocate_iommu_page_tables(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);

    spin_lock(&hd->mapping_lock);
    if ( hd->root_table )
    {
        deallocate_next_page_table(hd->root_table, hd->paging_mode);
        hd->root_table = NULL;
    }
    spin_unlock(&hd->mapping_lock);
}


static void amd_iommu_domain_destroy(struct domain *d)
{
    deallocate_iommu_page_tables(d);
    invalidate_all_iommu_pages(d);
}

static int amd_iommu_return_device(
    struct domain *s, struct domain *t, u8 bus, u8 devfn)
{
    return reassign_device(s, t, bus, devfn);
}

static int amd_iommu_add_device(struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    u16 bdf;
    if ( !pdev->domain )
        return -EINVAL;

    bdf = (pdev->bus << 8) | pdev->devfn;
    iommu = (bdf < ivrs_bdf_entries) ?
    find_iommu_for_device(pdev->bus, pdev->devfn) : NULL;

    if ( !iommu )
    {
        amd_iov_error("Fail to find iommu."
            " %x:%x.%x cannot be assigned to domain %d\n", 
            pdev->bus, PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn), pdev->domain->domain_id);
        return -ENODEV;
    }

    amd_iommu_setup_domain_device(pdev->domain, iommu, bdf);
    return 0;
}

static int amd_iommu_remove_device(struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    u16 bdf;
    if ( !pdev->domain )
        return -EINVAL;

    bdf = (pdev->bus << 8) | pdev->devfn;
    iommu = (bdf < ivrs_bdf_entries) ?
    find_iommu_for_device(pdev->bus, pdev->devfn) : NULL;

    if ( !iommu )
    {
        amd_iov_error("Fail to find iommu."
            " %x:%x.%x cannot be removed from domain %d\n", 
            pdev->bus, PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn), pdev->domain->domain_id);
        return -ENODEV;
    }

    amd_iommu_disable_domain_device(pdev->domain, iommu, bdf);
    return 0;
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
    .add_device = amd_iommu_add_device,
    .remove_device = amd_iommu_remove_device,
    .assign_device  = amd_iommu_assign_device,
    .teardown = amd_iommu_domain_destroy,
    .map_page = amd_iommu_map_page,
    .unmap_page = amd_iommu_unmap_page,
    .reassign_device = amd_iommu_return_device,
    .get_device_group_id = amd_iommu_group_id,
    .update_ire_from_apic = amd_iommu_ioapic_update_ire,
    .update_ire_from_msi = amd_iommu_msi_msg_update_ire,
    .read_apic_from_ire = amd_iommu_read_ioapic_from_ire,
    .read_msi_from_ire = amd_iommu_read_msi_from_ire,
    .suspend = amd_iommu_suspend,
    .resume = amd_iommu_resume,
};
