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

#include <xen/sched.h>
#include <xen/iocap.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/paging.h>
#include <xen/softirq.h>
#include <asm/hvm/iommu.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include "../ats.h"

static bool_t __read_mostly init_done;

struct amd_iommu *find_iommu_for_device(int seg, int bdf)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);

    if ( !ivrs_mappings || bdf >= ivrs_bdf_entries )
        return NULL;

    if ( unlikely(!ivrs_mappings[bdf].iommu) && likely(init_done) )
    {
        unsigned int bd0 = bdf & ~PCI_FUNC(~0);

        if ( ivrs_mappings[bd0].iommu )
        {
            struct ivrs_mappings tmp = ivrs_mappings[bd0];

            tmp.iommu = NULL;
            if ( tmp.dte_requestor_id == bd0 )
                tmp.dte_requestor_id = bdf;
            ivrs_mappings[bdf] = tmp;

            printk(XENLOG_WARNING "%04x:%02x:%02x.%u not found in ACPI tables;"
                   " using same IOMMU as function 0\n",
                   seg, PCI_BUS(bdf), PCI_SLOT(bdf), PCI_FUNC(bdf));

            /* write iommu field last */
            ivrs_mappings[bdf].iommu = ivrs_mappings[bd0].iommu;
        }
    }

    return ivrs_mappings[bdf].iommu;
}

/*
 * Some devices will use alias id and original device id to index interrupt
 * table and I/O page table respectively. Such devices will have
 * both alias entry and select entry in IVRS structure.
 *
 * Return original device id, if device has valid interrupt remapping
 * table setup for both select entry and alias entry.
 */
int get_dma_requestor_id(u16 seg, u16 bdf)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);
    int req_id;

    BUG_ON ( bdf >= ivrs_bdf_entries );
    req_id = ivrs_mappings[bdf].dte_requestor_id;
    if ( (ivrs_mappings[bdf].intremap_table != NULL) &&
         (ivrs_mappings[req_id].intremap_table != NULL) )
        req_id = bdf;

    return req_id;
}

static int is_translation_valid(u32 *entry)
{
    return (get_field_from_reg_u32(entry[0],
                                   IOMMU_DEV_TABLE_VALID_MASK,
                                   IOMMU_DEV_TABLE_VALID_SHIFT) &&
            get_field_from_reg_u32(entry[0],
                                   IOMMU_DEV_TABLE_TRANSLATION_VALID_MASK,
                                   IOMMU_DEV_TABLE_TRANSLATION_VALID_SHIFT));
}

static void disable_translation(u32 *dte)
{
    u32 entry;

    entry = dte[0];
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_DEV_TABLE_TRANSLATION_VALID_MASK,
                         IOMMU_DEV_TABLE_TRANSLATION_VALID_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_DEV_TABLE_VALID_MASK,
                         IOMMU_DEV_TABLE_VALID_SHIFT, &entry);
    dte[0] = entry;
}

static void amd_iommu_setup_domain_device(
    struct domain *domain, struct amd_iommu *iommu,
    u8 devfn, struct pci_dev *pdev)
{
    void *dte;
    unsigned long flags;
    int req_id, valid = 1;
    int dte_i = 0;
    u8 bus = pdev->bus;

    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    BUG_ON( !hd->arch.root_table || !hd->arch.paging_mode ||
            !iommu->dev_table.buffer );

    if ( iommu_passthrough && is_hardware_domain(domain) )
        valid = 0;

    if ( ats_enabled )
        dte_i = 1;

    /* get device-table entry */
    req_id = get_dma_requestor_id(iommu->seg, PCI_BDF2(bus, devfn));
    dte = iommu->dev_table.buffer + (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    spin_lock_irqsave(&iommu->lock, flags);

    if ( !is_translation_valid((u32 *)dte) )
    {
        /* bind DTE to domain page-tables */
        amd_iommu_set_root_page_table(
            (u32 *)dte, page_to_maddr(hd->arch.root_table), domain->domain_id,
            hd->arch.paging_mode, valid);

        if ( pci_ats_device(iommu->seg, bus, pdev->devfn) &&
             iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
            iommu_dte_set_iotlb((u32 *)dte, dte_i);

        amd_iommu_flush_device(iommu, req_id);

        AMD_IOMMU_DEBUG("Setup I/O page table: device id = %#x, type = %#x, "
                        "root table = %#"PRIx64", "
                        "domain = %d, paging mode = %d\n",
                        req_id, pdev->type,
                        page_to_maddr(hd->arch.root_table),
                        domain->domain_id, hd->arch.paging_mode);
    }

    spin_unlock_irqrestore(&iommu->lock, flags);

    ASSERT(spin_is_locked(&pcidevs_lock));

    if ( pci_ats_device(iommu->seg, bus, pdev->devfn) &&
         !pci_ats_enabled(iommu->seg, bus, pdev->devfn) )
    {
        if ( devfn == pdev->devfn )
            enable_ats_device(iommu->seg, bus, devfn, iommu);

        amd_iommu_flush_iotlb(devfn, pdev, INV_IOMMU_ALL_PAGES_ADDRESS, 0);
    }
}

static int __hwdom_init amd_iommu_setup_hwdom_device(
    u8 devfn, struct pci_dev *pdev)
{
    int bdf = PCI_BDF2(pdev->bus, pdev->devfn);
    struct amd_iommu *iommu = find_iommu_for_device(pdev->seg, bdf);

    if ( unlikely(!iommu) )
    {
        /* Filter the bridge devices */
        if ( pdev->type == DEV_TYPE_PCI_HOST_BRIDGE )
        {
            AMD_IOMMU_DEBUG("Skipping host bridge %04x:%02x:%02x.%u\n",
                            pdev->seg, PCI_BUS(bdf), PCI_SLOT(bdf),
                            PCI_FUNC(bdf));
            return 0;
        }

        AMD_IOMMU_DEBUG("No iommu for device %04x:%02x:%02x.%u\n",
                        pdev->seg, pdev->bus,
                        PCI_SLOT(devfn), PCI_FUNC(devfn));
        return -ENODEV;
    }

    amd_iommu_setup_domain_device(pdev->domain, iommu, devfn, pdev);
    return 0;
}

int __init amd_iov_detect(void)
{
    INIT_LIST_HEAD(&amd_iommu_head);

    if ( !iommu_enable && !iommu_intremap )
        return 0;

    if ( (amd_iommu_detect_acpi() !=0) || (iommu_found() == 0) )
    {
        printk("AMD-Vi: IOMMU not found!\n");
        iommu_intremap = 0;
        return -ENODEV;
    }

    if ( amd_iommu_init() != 0 )
    {
        printk("AMD-Vi: Error initialization\n");
        return -ENODEV;
    }

    init_done = 1;

    if ( !amd_iommu_perdev_intremap )
        printk(XENLOG_WARNING "AMD-Vi: Using global interrupt remap table is not recommended (see XSA-36)!\n");
    return scan_pci_devices();
}

static int allocate_domain_resources(struct hvm_iommu *hd)
{
    /* allocate root table */
    spin_lock(&hd->arch.mapping_lock);
    if ( !hd->arch.root_table )
    {
        hd->arch.root_table = alloc_amd_iommu_pgtable();
        if ( !hd->arch.root_table )
        {
            spin_unlock(&hd->arch.mapping_lock);
            return -ENOMEM;
        }
    }
    spin_unlock(&hd->arch.mapping_lock);
    return 0;
}

static int get_paging_mode(unsigned long entries)
{
    int level = 1;

    BUG_ON( !entries );

    while ( entries > PTE_PER_TABLE_SIZE )
    {
        entries = PTE_PER_TABLE_ALIGN(entries) >> PTE_PER_TABLE_SHIFT;
        if ( ++level > 6 )
            return -ENOMEM;
    }

    return level;
}

static int amd_iommu_domain_init(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    /* allocate page directroy */
    if ( allocate_domain_resources(hd) != 0 )
    {
        if ( hd->arch.root_table )
            free_domheap_page(hd->arch.root_table);
        return -ENOMEM;
    }

    /* For pv and dom0, stick with get_paging_mode(max_page)
     * For HVM dom0, use 2 level page table at first */
    hd->arch.paging_mode = is_hvm_domain(d) ?
                      IOMMU_PAGING_MODE_LEVEL_2 :
                      get_paging_mode(max_page);

    guest_iommu_init(d);

    return 0;
}

static void __hwdom_init amd_iommu_hwdom_init(struct domain *d)
{
    unsigned long i; 
    const struct amd_iommu *iommu;

    if ( !iommu_passthrough && !need_iommu(d) )
    {
        /* Set up 1:1 page table for dom0 */
        for ( i = 0; i < max_pdx; i++ )
        {
            unsigned long pfn = pdx_to_pfn(i);

            /*
             * XXX Should we really map all non-RAM (above 4G)? Minimally
             * a pfn_valid() check would seem desirable here.
             */
            if ( mfn_valid(pfn) )
                amd_iommu_map_page(d, pfn, pfn, 
                                   IOMMUF_readable|IOMMUF_writable);

            if ( !(i & 0xfffff) )
                process_pending_softirqs();
        }
    }

    for_each_amd_iommu ( iommu )
        if ( iomem_deny_access(d, PFN_DOWN(iommu->mmio_base_phys),
                               PFN_DOWN(iommu->mmio_base_phys +
                                        IOMMU_MMIO_REGION_LENGTH - 1)) )
            BUG();

    setup_hwdom_pci_devices(d, amd_iommu_setup_hwdom_device);
}

void amd_iommu_disable_domain_device(struct domain *domain,
                                     struct amd_iommu *iommu,
                                     u8 devfn, struct pci_dev *pdev)
{
    void *dte;
    unsigned long flags;
    int req_id;
    u8 bus = pdev->bus;

    BUG_ON ( iommu->dev_table.buffer == NULL );
    req_id = get_dma_requestor_id(iommu->seg, PCI_BDF2(bus, devfn));
    dte = iommu->dev_table.buffer + (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    spin_lock_irqsave(&iommu->lock, flags);
    if ( is_translation_valid((u32 *)dte) )
    {
        disable_translation((u32 *)dte);

        if ( pci_ats_device(iommu->seg, bus, pdev->devfn) &&
             iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
            iommu_dte_set_iotlb((u32 *)dte, 0);

        amd_iommu_flush_device(iommu, req_id);

        AMD_IOMMU_DEBUG("Disable: device id = %#x, "
                        "domain = %d, paging mode = %d\n",
                        req_id,  domain->domain_id,
                        domain_hvm_iommu(domain)->arch.paging_mode);
    }
    spin_unlock_irqrestore(&iommu->lock, flags);

    ASSERT(spin_is_locked(&pcidevs_lock));

    if ( devfn == pdev->devfn &&
         pci_ats_device(iommu->seg, bus, devfn) &&
         pci_ats_enabled(iommu->seg, bus, devfn) )
        disable_ats_device(iommu->seg, bus, devfn);
}

static int reassign_device(struct domain *source, struct domain *target,
                           u8 devfn, struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    int bdf;
    struct hvm_iommu *t = domain_hvm_iommu(target);

    bdf = PCI_BDF2(pdev->bus, pdev->devfn);
    iommu = find_iommu_for_device(pdev->seg, bdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Fail to find iommu."
                        " %04x:%02x:%x02.%x cannot be assigned to dom%d\n",
                        pdev->seg, pdev->bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                        target->domain_id);
        return -ENODEV;
    }

    amd_iommu_disable_domain_device(source, iommu, devfn, pdev);

    if ( devfn == pdev->devfn )
    {
        list_move(&pdev->domain_list, &target->arch.pdev_list);
        pdev->domain = target;
    }

    /* IO page tables might be destroyed after pci-detach the last device
     * In this case, we have to re-allocate root table for next pci-attach.*/
    if ( t->arch.root_table == NULL )
        allocate_domain_resources(t);

    amd_iommu_setup_domain_device(target, iommu, devfn, pdev);
    AMD_IOMMU_DEBUG("Re-assign %04x:%02x:%02x.%u from dom%d to dom%d\n",
                    pdev->seg, pdev->bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                    source->domain_id, target->domain_id);

    return 0;
}

static int amd_iommu_assign_device(struct domain *d, u8 devfn,
                                   struct pci_dev *pdev,
                                   u32 flag)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(pdev->seg);
    int bdf = PCI_BDF2(pdev->bus, devfn);
    int req_id = get_dma_requestor_id(pdev->seg, bdf);

    if ( ivrs_mappings[req_id].unity_map_enable )
    {
        amd_iommu_reserve_domain_unity_map(
            d,
            ivrs_mappings[req_id].addr_range_start,
            ivrs_mappings[req_id].addr_range_length,
            ivrs_mappings[req_id].write_permission,
            ivrs_mappings[req_id].read_permission);
    }

    return reassign_device(hardware_domain, d, devfn, pdev);
}

static void deallocate_next_page_table(struct page_info *pg, int level)
{
    PFN_ORDER(pg) = level;
    spin_lock(&iommu_pt_cleanup_lock);
    page_list_add_tail(pg, &iommu_pt_cleanup_list);
    spin_unlock(&iommu_pt_cleanup_lock);
}

static void deallocate_page_table(struct page_info *pg)
{
    void *table_vaddr, *pde;
    u64 next_table_maddr;
    unsigned int index, level = PFN_ORDER(pg), next_level;

    PFN_ORDER(pg) = 0;

    if ( level <= 1 )
    {
        free_amd_iommu_pgtable(pg);
        return;
    }

    table_vaddr = __map_domain_page(pg);

    for ( index = 0; index < PTE_PER_TABLE_SIZE; index++ )
    {
        pde = table_vaddr + (index * IOMMU_PAGE_TABLE_ENTRY_SIZE);
        next_table_maddr = amd_iommu_get_next_table_from_pte(pde);
        next_level = iommu_next_level((u32*)pde);

        if ( (next_table_maddr != 0) && (next_level != 0) &&
             iommu_is_pte_present((u32*)pde) )
        {
            /* We do not support skip levels yet */
            ASSERT(next_level == level - 1);
            deallocate_next_page_table(maddr_to_page(next_table_maddr), 
                                       next_level);
        }
    }

    unmap_domain_page(table_vaddr);
    free_amd_iommu_pgtable(pg);
}

static void deallocate_iommu_page_tables(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);

    if ( iommu_use_hap_pt(d) )
        return;

    spin_lock(&hd->arch.mapping_lock);
    if ( hd->arch.root_table )
    {
        deallocate_next_page_table(hd->arch.root_table, hd->arch.paging_mode);
        hd->arch.root_table = NULL;
    }
    spin_unlock(&hd->arch.mapping_lock);
}


static void amd_iommu_domain_destroy(struct domain *d)
{
    guest_iommu_destroy(d);
    deallocate_iommu_page_tables(d);
    amd_iommu_flush_all_pages(d);
}

static int amd_iommu_add_device(u8 devfn, struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    u16 bdf;
    if ( !pdev->domain )
        return -EINVAL;

    bdf = PCI_BDF2(pdev->bus, pdev->devfn);
    iommu = find_iommu_for_device(pdev->seg, bdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Fail to find iommu."
                        " %04x:%02x:%02x.%u cannot be assigned to dom%d\n",
                        pdev->seg, pdev->bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                        pdev->domain->domain_id);
        return -ENODEV;
    }

    amd_iommu_setup_domain_device(pdev->domain, iommu, devfn, pdev);
    return 0;
}

static int amd_iommu_remove_device(u8 devfn, struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    u16 bdf;
    if ( !pdev->domain )
        return -EINVAL;

    bdf = PCI_BDF2(pdev->bus, pdev->devfn);
    iommu = find_iommu_for_device(pdev->seg, bdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Fail to find iommu."
                        " %04x:%02x:%02x.%u cannot be removed from dom%d\n",
                        pdev->seg, pdev->bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                        pdev->domain->domain_id);
        return -ENODEV;
    }

    amd_iommu_disable_domain_device(pdev->domain, iommu, devfn, pdev);
    return 0;
}

static int amd_iommu_group_id(u16 seg, u8 bus, u8 devfn)
{
    int bdf = PCI_BDF2(bus, devfn);

    return (bdf < ivrs_bdf_entries) ? get_dma_requestor_id(seg, bdf) : bdf;
}

#include <asm/io_apic.h>

static void amd_dump_p2m_table_level(struct page_info* pg, int level, 
                                     paddr_t gpa, int indent)
{
    paddr_t address;
    void *table_vaddr, *pde;
    paddr_t next_table_maddr;
    int index, next_level, present;
    u32 *entry;

    if ( level < 1 )
        return;

    table_vaddr = __map_domain_page(pg);
    if ( table_vaddr == NULL )
    {
        printk("Failed to map IOMMU domain page %"PRIpaddr"\n", 
                page_to_maddr(pg));
        return;
    }

    for ( index = 0; index < PTE_PER_TABLE_SIZE; index++ )
    {
        if ( !(index % 2) )
            process_pending_softirqs();

        pde = table_vaddr + (index * IOMMU_PAGE_TABLE_ENTRY_SIZE);
        next_table_maddr = amd_iommu_get_next_table_from_pte(pde);
        entry = (u32*)pde;

        present = get_field_from_reg_u32(entry[0],
                                         IOMMU_PDE_PRESENT_MASK,
                                         IOMMU_PDE_PRESENT_SHIFT);

        if ( !present )
            continue;

        next_level = get_field_from_reg_u32(entry[0],
                                            IOMMU_PDE_NEXT_LEVEL_MASK,
                                            IOMMU_PDE_NEXT_LEVEL_SHIFT);

        if ( next_level && (next_level != (level - 1)) )
        {
            printk("IOMMU p2m table error. next_level = %d, expected %d\n",
                   next_level, level - 1);

            continue;
        }

        address = gpa + amd_offset_level_address(index, level);
        if ( next_level >= 1 )
            amd_dump_p2m_table_level(
                maddr_to_page(next_table_maddr), next_level,
                address, indent + 1);
        else
            printk("%*sgfn: %08lx  mfn: %08lx\n",
                   indent, "",
                   (unsigned long)PFN_DOWN(address),
                   (unsigned long)PFN_DOWN(next_table_maddr));
    }

    unmap_domain_page(table_vaddr);
}

static void amd_dump_p2m_table(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);

    if ( !hd->arch.root_table )
        return;

    printk("p2m table has %d levels\n", hd->arch.paging_mode);
    amd_dump_p2m_table_level(hd->arch.root_table, hd->arch.paging_mode, 0, 0);
}

const struct iommu_ops amd_iommu_ops = {
    .init = amd_iommu_domain_init,
    .hwdom_init = amd_iommu_hwdom_init,
    .add_device = amd_iommu_add_device,
    .remove_device = amd_iommu_remove_device,
    .assign_device  = amd_iommu_assign_device,
    .teardown = amd_iommu_domain_destroy,
    .map_page = amd_iommu_map_page,
    .unmap_page = amd_iommu_unmap_page,
    .free_page_table = deallocate_page_table,
    .reassign_device = reassign_device,
    .get_device_group_id = amd_iommu_group_id,
    .update_ire_from_apic = amd_iommu_ioapic_update_ire,
    .update_ire_from_msi = amd_iommu_msi_msg_update_ire,
    .read_apic_from_ire = amd_iommu_read_ioapic_from_ire,
    .read_msi_from_ire = amd_iommu_read_msi_from_ire,
    .setup_hpet_msi = amd_setup_hpet_msi,
    .suspend = amd_iommu_suspend,
    .resume = amd_iommu_resume,
    .share_p2m = amd_iommu_share_p2m,
    .crash_shutdown = amd_iommu_suspend,
    .dump_p2m_table = amd_dump_p2m_table,
};
