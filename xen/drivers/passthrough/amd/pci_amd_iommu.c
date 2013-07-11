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
#include <xen/paging.h>
#include <xen/softirq.h>
#include <asm/hvm/iommu.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include "../ats.h"

struct amd_iommu *find_iommu_for_device(int seg, int bdf)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);

    return ivrs_mappings && bdf < ivrs_bdf_entries ? ivrs_mappings[bdf].iommu
                                                   : NULL;
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
    struct domain *domain, struct amd_iommu *iommu, int bdf)
{
    void *dte;
    unsigned long flags;
    int req_id, valid = 1;
    int dte_i = 0;
    u8 bus = PCI_BUS(bdf);
    u8 devfn = PCI_DEVFN2(bdf);

    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    BUG_ON( !hd->root_table || !hd->paging_mode || !iommu->dev_table.buffer );

    if ( iommu_passthrough && (domain->domain_id == 0) )
        valid = 0;

    if ( ats_enabled )
        dte_i = 1;

    /* get device-table entry */
    req_id = get_dma_requestor_id(iommu->seg, bdf);
    dte = iommu->dev_table.buffer + (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    spin_lock_irqsave(&iommu->lock, flags);

    if ( !is_translation_valid((u32 *)dte) )
    {
        /* bind DTE to domain page-tables */
        amd_iommu_set_root_page_table(
            (u32 *)dte, page_to_maddr(hd->root_table), hd->domain_id,
            hd->paging_mode, valid);

        if ( pci_ats_device(iommu->seg, bus, devfn) &&
             iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
            iommu_dte_set_iotlb((u32 *)dte, dte_i);

        amd_iommu_flush_device(iommu, req_id);

        AMD_IOMMU_DEBUG("Setup I/O page table: device id = 0x%04x, "
                        "root table = 0x%"PRIx64", "
                        "domain = %d, paging mode = %d\n", req_id,
                        page_to_maddr(hd->root_table),
                        hd->domain_id, hd->paging_mode);
    }

    spin_unlock_irqrestore(&iommu->lock, flags);

    ASSERT(spin_is_locked(&pcidevs_lock));

    if ( pci_ats_device(iommu->seg, bus, devfn) &&
         !pci_ats_enabled(iommu->seg, bus, devfn) )
    {
        struct pci_dev *pdev;

        enable_ats_device(iommu->seg, bus, devfn);

        ASSERT(spin_is_locked(&pcidevs_lock));
        pdev = pci_get_pdev(iommu->seg, bus, devfn);

        ASSERT( pdev != NULL );
        amd_iommu_flush_iotlb(pdev, INV_IOMMU_ALL_PAGES_ADDRESS, 0);
    }
}

static void __init amd_iommu_setup_dom0_device(struct pci_dev *pdev)
{
    int bdf = PCI_BDF2(pdev->bus, pdev->devfn);
    struct amd_iommu *iommu = find_iommu_for_device(pdev->seg, bdf);

    if ( likely(iommu != NULL) )
        amd_iommu_setup_domain_device(pdev->domain, iommu, bdf);
    else
        AMD_IOMMU_DEBUG("No iommu for device %04x:%02x:%02x.%u\n",
                        pdev->seg, pdev->bus,
                        PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
}

int __init amd_iov_detect(void)
{
    INIT_LIST_HEAD(&amd_iommu_head);

    if ( (amd_iommu_detect_acpi() !=0) || (iommu_found() == 0) )
    {
        printk("AMD-Vi: IOMMU not found!\n");
        return -ENODEV;
    }

    if ( amd_iommu_init() != 0 )
    {
        printk("AMD-Vi: Error initialization\n");
        return -ENODEV;
    }

    /*
     * AMD IOMMUs don't distinguish between vectors destined for
     * different cpus when doing interrupt remapping.  This means
     * that interrupts going through the same intremap table
     * can't share the same vector.
     *
     * If irq_vector_map isn't specified, choose a sensible default:
     * - If we're using per-device interemap tables, per-device
     *   vector non-sharing maps
     * - If we're using a global interemap table, global vector
     *   non-sharing map
     */
    if ( opt_irq_vector_map == OPT_IRQ_VECTOR_MAP_DEFAULT )
    {
        if ( amd_iommu_perdev_intremap )
        {
            /* Per-device vector map logic is broken for devices with multiple
             * MSI-X interrupts (and would also be for multiple MSI, if Xen
             * supported it).
             *
             * Until this is fixed, use global vector tables as far as the irq
             * logic is concerned to avoid the buggy behaviour of per-device
             * maps in map_domain_pirq(), and use per-device tables as far as
             * intremap code is concerned to avoid the security issue.
             */
            printk(XENLOG_WARNING "AMD-Vi: per-device vector map logic is broken.  "
                   "Using per-device-global maps instead until a fix is found.\n");

            opt_irq_vector_map = OPT_IRQ_VECTOR_MAP_GLOBAL;
        }
        else
        {
            printk("AMD-Vi: Enabling global vector map\n");
            opt_irq_vector_map = OPT_IRQ_VECTOR_MAP_GLOBAL;
        }
    }
    else
    {
        printk("AMD-Vi: Not overriding irq_vector_map setting\n");

        if ( opt_irq_vector_map != OPT_IRQ_VECTOR_MAP_GLOBAL )
            printk(XENLOG_WARNING "AMD-Vi: per-device vector map logic is broken.  "
                   "Use irq_vector_map=global to work around.\n");
    }
    if ( !amd_iommu_perdev_intremap )
        printk(XENLOG_WARNING "AMD-Vi: Using global interrupt remap table is not recommended (see XSA-36)!\n");
    return scan_pci_devices();
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
        if ( hd->root_table )
            free_domheap_page(hd->root_table);
        return -ENOMEM;
    }

    /* For pv and dom0, stick with get_paging_mode(max_page)
     * For HVM dom0, use 2 level page table at first */
    hd->paging_mode = is_hvm_domain(d) ?
                      IOMMU_PAGING_MODE_LEVEL_2 :
                      get_paging_mode(max_page);

    hd->domain_id = d->domain_id;

    guest_iommu_init(d);

    return 0;
}

static void __init amd_iommu_dom0_init(struct domain *d)
{
    unsigned long i; 

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

    setup_dom0_pci_devices(d, amd_iommu_setup_dom0_device);
}

void amd_iommu_disable_domain_device(struct domain *domain,
                                     struct amd_iommu *iommu, int bdf)
{
    void *dte;
    unsigned long flags;
    int req_id;
    u8 bus = PCI_BUS(bdf);
    u8 devfn = PCI_DEVFN2(bdf);

    BUG_ON ( iommu->dev_table.buffer == NULL );
    req_id = get_dma_requestor_id(iommu->seg, bdf);
    dte = iommu->dev_table.buffer + (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    spin_lock_irqsave(&iommu->lock, flags);
    if ( is_translation_valid((u32 *)dte) )
    {
        disable_translation((u32 *)dte);

        if ( pci_ats_device(iommu->seg, bus, devfn) &&
             iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
            iommu_dte_set_iotlb((u32 *)dte, 0);

        amd_iommu_flush_device(iommu, req_id);

        AMD_IOMMU_DEBUG("Disable: device id = 0x%04x, "
                        "domain = %d, paging mode = %d\n",
                        req_id,  domain_hvm_iommu(domain)->domain_id,
                        domain_hvm_iommu(domain)->paging_mode);
    }
    spin_unlock_irqrestore(&iommu->lock, flags);

    ASSERT(spin_is_locked(&pcidevs_lock));

    if ( pci_ats_device(iommu->seg, bus, devfn) &&
         pci_ats_enabled(iommu->seg, bus, devfn) )
        disable_ats_device(iommu->seg, bus, devfn);
}

static int reassign_device( struct domain *source, struct domain *target,
                            u16 seg, u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    struct amd_iommu *iommu;
    int bdf;
    struct hvm_iommu *t = domain_hvm_iommu(target);

    ASSERT(spin_is_locked(&pcidevs_lock));
    pdev = pci_get_pdev_by_domain(source, seg, bus, devfn);
    if ( !pdev )
        return -ENODEV;

    bdf = PCI_BDF2(bus, devfn);
    iommu = find_iommu_for_device(seg, bdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Fail to find iommu."
                        " %04x:%02x:%x02.%x cannot be assigned to dom%d\n",
                        seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                        target->domain_id);
        return -ENODEV;
    }

    amd_iommu_disable_domain_device(source, iommu, bdf);

    list_move(&pdev->domain_list, &target->arch.pdev_list);
    pdev->domain = target;

    /* IO page tables might be destroyed after pci-detach the last device
     * In this case, we have to re-allocate root table for next pci-attach.*/
    if ( t->root_table == NULL )
        allocate_domain_resources(t);

    amd_iommu_setup_domain_device(target, iommu, bdf);
    AMD_IOMMU_DEBUG("Re-assign %04x:%02x:%02x.%u from dom%d to dom%d\n",
                    seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                    source->domain_id, target->domain_id);

    return 0;
}

static int amd_iommu_assign_device(struct domain *d, u16 seg, u8 bus, u8 devfn)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);
    int bdf = (bus << 8) | devfn;
    int req_id = get_dma_requestor_id(seg, bdf);

    if ( ivrs_mappings[req_id].unity_map_enable )
    {
        amd_iommu_reserve_domain_unity_map(
            d,
            ivrs_mappings[req_id].addr_range_start,
            ivrs_mappings[req_id].addr_range_length,
            ivrs_mappings[req_id].write_permission,
            ivrs_mappings[req_id].read_permission);
    }

    return reassign_device(dom0, d, seg, bus, devfn);
}

static void deallocate_next_page_table(struct page_info* pg, int level)
{
    void *table_vaddr, *pde;
    u64 next_table_maddr;
    int index, next_level, present;
    u32 *entry;

    table_vaddr = __map_domain_page(pg);

    if ( level > 1 )
    {
        for ( index = 0; index < PTE_PER_TABLE_SIZE; index++ )
        {
            pde = table_vaddr + (index * IOMMU_PAGE_TABLE_ENTRY_SIZE);
            next_table_maddr = amd_iommu_get_next_table_from_pte(pde);
            entry = (u32*)pde;

            next_level = get_field_from_reg_u32(entry[0],
                                                IOMMU_PDE_NEXT_LEVEL_MASK,
                                                IOMMU_PDE_NEXT_LEVEL_SHIFT);

            present = get_field_from_reg_u32(entry[0],
                                             IOMMU_PDE_PRESENT_MASK,
                                             IOMMU_PDE_PRESENT_SHIFT);

            if ( (next_table_maddr != 0) && (next_level != 0)
                && present )
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

    if ( iommu_use_hap_pt(d) )
        return;

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
    guest_iommu_destroy(d);
    deallocate_iommu_page_tables(d);
    amd_iommu_flush_all_pages(d);
}

static int amd_iommu_return_device(
    struct domain *s, struct domain *t, u16 seg, u8 bus, u8 devfn)
{
    return reassign_device(s, t, seg, bus, devfn);
}

static int amd_iommu_add_device(struct pci_dev *pdev)
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
                        pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
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

    bdf = PCI_BDF2(pdev->bus, pdev->devfn);
    iommu = find_iommu_for_device(pdev->seg, bdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Fail to find iommu."
                        " %04x:%02x:%02x.%u cannot be removed from dom%d\n",
                        pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                        PCI_FUNC(pdev->devfn), pdev->domain->domain_id);
        return -ENODEV;
    }

    amd_iommu_disable_domain_device(pdev->domain, iommu, bdf);
    return 0;
}

static int amd_iommu_group_id(u16 seg, u8 bus, u8 devfn)
{
    int rt;
    int bdf = (bus << 8) | devfn;
    rt = ( bdf < ivrs_bdf_entries ) ?
        get_dma_requestor_id(seg, bdf) :
        bdf;
    return rt;
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

    if ( !hd->root_table ) 
        return;

    printk("p2m table has %d levels\n", hd->paging_mode);
    amd_dump_p2m_table_level(hd->root_table, hd->paging_mode, 0, 0);
}

const struct iommu_ops amd_iommu_ops = {
    .init = amd_iommu_domain_init,
    .dom0_init = amd_iommu_dom0_init,
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
    .read_apic_from_ire = __io_apic_read,
    .read_msi_from_ire = amd_iommu_read_msi_from_ire,
    .suspend = amd_iommu_suspend,
    .resume = amd_iommu_resume,
    .share_p2m = amd_iommu_share_p2m,
    .crash_shutdown = amd_iommu_suspend,
    .dump_p2m_table = amd_dump_p2m_table,
};
