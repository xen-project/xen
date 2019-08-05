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
#include <asm/acpi.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include "../ats.h"

static bool_t __read_mostly init_done;

static const struct iommu_init_ops _iommu_init_ops;

struct amd_iommu *find_iommu_for_device(int seg, int bdf)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);

    if ( !ivrs_mappings || bdf >= ivrs_bdf_entries )
        return NULL;

    if ( unlikely(!ivrs_mappings[bdf].iommu) && likely(init_done) )
    {
        unsigned int bd0 = bdf & ~PCI_FUNC(~0);

        if ( ivrs_mappings[bd0].iommu && ivrs_mappings[bd0].iommu->bdf != bdf )
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
int get_dma_requestor_id(uint16_t seg, uint16_t bdf)
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

static void amd_iommu_setup_domain_device(
    struct domain *domain, struct amd_iommu *iommu,
    uint8_t devfn, struct pci_dev *pdev)
{
    struct amd_iommu_dte *table, *dte;
    unsigned long flags;
    int req_id, valid = 1;
    int dte_i = 0;
    u8 bus = pdev->bus;
    const struct domain_iommu *hd = dom_iommu(domain);

    BUG_ON( !hd->arch.root_table || !hd->arch.paging_mode ||
            !iommu->dev_table.buffer );

    if ( iommu_hwdom_passthrough && is_hardware_domain(domain) )
        valid = 0;

    if ( ats_enabled )
        dte_i = 1;

    /* get device-table entry */
    req_id = get_dma_requestor_id(iommu->seg, PCI_BDF2(bus, devfn));
    table = iommu->dev_table.buffer;
    dte = &table[req_id];

    spin_lock_irqsave(&iommu->lock, flags);

    if ( !dte->v || !dte->tv )
    {
        /* bind DTE to domain page-tables */
        amd_iommu_set_root_page_table(
            dte, page_to_maddr(hd->arch.root_table), domain->domain_id,
            hd->arch.paging_mode, valid);

        if ( pci_ats_device(iommu->seg, bus, pdev->devfn) &&
             iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
            dte->i = dte_i;

        amd_iommu_flush_device(iommu, req_id);

        AMD_IOMMU_DEBUG("Setup I/O page table: device id = %#x, type = %#x, "
                        "root table = %#"PRIx64", "
                        "domain = %d, paging mode = %d\n",
                        req_id, pdev->type,
                        page_to_maddr(hd->arch.root_table),
                        domain->domain_id, hd->arch.paging_mode);
    }

    spin_unlock_irqrestore(&iommu->lock, flags);

    ASSERT(pcidevs_locked());

    if ( pci_ats_device(iommu->seg, bus, pdev->devfn) &&
         !pci_ats_enabled(iommu->seg, bus, pdev->devfn) )
    {
        if ( devfn == pdev->devfn )
            enable_ats_device(pdev, &iommu->ats_devices);

        amd_iommu_flush_iotlb(devfn, pdev, INV_IOMMU_ALL_PAGES_ADDRESS, 0);
    }
}

int __init acpi_ivrs_init(void)
{
    if ( !iommu_enable && !iommu_intremap )
        return 0;

    if ( (amd_iommu_detect_acpi() !=0) || (iommu_found() == 0) )
    {
        iommu_intremap = 0;
        return -ENODEV;
    }

    iommu_init_ops = &_iommu_init_ops;

    return 0;
}

static int __init iov_detect(void)
{
    if ( !iommu_enable && !iommu_intremap )
        return 0;

    else if ( (init_done ? amd_iommu_init_interrupt()
                         : amd_iommu_init(false)) != 0 )
    {
        printk("AMD-Vi: Error initialization\n");
        return -ENODEV;
    }

    init_done = 1;

    if ( !amd_iommu_perdev_intremap )
        printk(XENLOG_WARNING "AMD-Vi: Using global interrupt remap table is not recommended (see XSA-36)!\n");

    return 0;
}

static int iov_enable_xt(void)
{
    int rc;

    if ( system_state >= SYS_STATE_active )
        return 0;

    if ( (rc = amd_iommu_init(true)) != 0 )
    {
        printk("AMD-Vi: Error %d initializing for x2APIC mode\n", rc);
        /* -ENXIO has special meaning to the caller - convert it. */
        return rc != -ENXIO ? rc : -ENODATA;
    }

    init_done = true;

    return 0;
}

int amd_iommu_alloc_root(struct domain_iommu *hd)
{
    if ( unlikely(!hd->arch.root_table) )
    {
        hd->arch.root_table = alloc_amd_iommu_pgtable();
        if ( !hd->arch.root_table )
            return -ENOMEM;
    }

    return 0;
}

static int __must_check allocate_domain_resources(struct domain_iommu *hd)
{
    int rc;

    spin_lock(&hd->arch.mapping_lock);
    rc = amd_iommu_alloc_root(hd);
    spin_unlock(&hd->arch.mapping_lock);

    return rc;
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
    struct domain_iommu *hd = dom_iommu(d);

    /* For pv and dom0, stick with get_paging_mode(max_page)
     * For HVM dom0, use 2 level page table at first */
    hd->arch.paging_mode = is_hvm_domain(d) ? 2 : get_paging_mode(max_page);
    return 0;
}

static int amd_iommu_add_device(u8 devfn, struct pci_dev *pdev);

static void __hwdom_init amd_iommu_hwdom_init(struct domain *d)
{
    const struct amd_iommu *iommu;

    if ( allocate_domain_resources(dom_iommu(d)) )
        BUG();

    for_each_amd_iommu ( iommu )
        if ( iomem_deny_access(d, PFN_DOWN(iommu->mmio_base_phys),
                               PFN_DOWN(iommu->mmio_base_phys +
                                        IOMMU_MMIO_REGION_LENGTH - 1)) )
            BUG();

    /* Make sure workarounds are applied (if needed) before adding devices. */
    arch_iommu_hwdom_init(d);
    setup_hwdom_pci_devices(d, amd_iommu_add_device);
}

void amd_iommu_disable_domain_device(struct domain *domain,
                                     struct amd_iommu *iommu,
                                     u8 devfn, struct pci_dev *pdev)
{
    struct amd_iommu_dte *table, *dte;
    unsigned long flags;
    int req_id;
    u8 bus = pdev->bus;

    BUG_ON ( iommu->dev_table.buffer == NULL );
    req_id = get_dma_requestor_id(iommu->seg, PCI_BDF2(bus, devfn));
    table = iommu->dev_table.buffer;
    dte = &table[req_id];

    spin_lock_irqsave(&iommu->lock, flags);
    if ( dte->tv && dte->v )
    {
        dte->tv = 0;
        dte->v = 0;

        if ( pci_ats_device(iommu->seg, bus, pdev->devfn) &&
             iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
            dte->i = 0;

        amd_iommu_flush_device(iommu, req_id);

        AMD_IOMMU_DEBUG("Disable: device id = %#x, "
                        "domain = %d, paging mode = %d\n",
                        req_id,  domain->domain_id,
                        dom_iommu(domain)->arch.paging_mode);
    }
    spin_unlock_irqrestore(&iommu->lock, flags);

    ASSERT(pcidevs_locked());

    if ( devfn == pdev->devfn &&
         pci_ats_device(iommu->seg, bus, devfn) &&
         pci_ats_enabled(iommu->seg, bus, devfn) )
        disable_ats_device(pdev);
}

static int reassign_device(struct domain *source, struct domain *target,
                           u8 devfn, struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    int bdf, rc;
    struct domain_iommu *t = dom_iommu(target);

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
        list_move(&pdev->domain_list, &target->pdev_list);
        pdev->domain = target;
    }

    rc = allocate_domain_resources(t);
    if ( rc )
        return rc;

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
    struct amd_iommu_pte *table_vaddr;
    unsigned int index, level = PFN_ORDER(pg);

    PFN_ORDER(pg) = 0;

    if ( level <= 1 )
    {
        free_amd_iommu_pgtable(pg);
        return;
    }

    table_vaddr = __map_domain_page(pg);

    for ( index = 0; index < PTE_PER_TABLE_SIZE; index++ )
    {
        struct amd_iommu_pte *pde = &table_vaddr[index];

        if ( pde->mfn && pde->next_level && pde->pr )
        {
            /* We do not support skip levels yet */
            ASSERT(pde->next_level == level - 1);
            deallocate_next_page_table(mfn_to_page(_mfn(pde->mfn)),
                                       pde->next_level);
        }
    }

    unmap_domain_page(table_vaddr);
    free_amd_iommu_pgtable(pg);
}

static void deallocate_iommu_page_tables(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

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

    for_each_amd_iommu(iommu)
        if ( pdev->seg == iommu->seg && bdf == iommu->bdf )
            return is_hardware_domain(pdev->domain) ? 0 : -ENODEV;

    iommu = find_iommu_for_device(pdev->seg, bdf);
    if ( unlikely(!iommu) )
    {
        /* Filter bridge devices. */
        if ( pdev->type == DEV_TYPE_PCI_HOST_BRIDGE &&
             is_hardware_domain(pdev->domain) )
        {
            AMD_IOMMU_DEBUG("Skipping host bridge %04x:%02x:%02x.%u\n",
                            pdev->seg, pdev->bus, PCI_SLOT(devfn),
                            PCI_FUNC(devfn));
            return 0;
        }

        AMD_IOMMU_DEBUG("No iommu for %04x:%02x:%02x.%u; cannot be handed to d%d\n",
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
    struct amd_iommu_pte *table_vaddr;
    int index;

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
        struct amd_iommu_pte *pde = &table_vaddr[index];

        if ( !(index % 2) )
            process_pending_softirqs();

        if ( !pde->pr )
            continue;

        if ( pde->next_level && (pde->next_level != (level - 1)) )
        {
            printk("IOMMU p2m table error. next_level = %d, expected %d\n",
                   pde->next_level, level - 1);

            continue;
        }

        address = gpa + amd_offset_level_address(index, level);
        if ( pde->next_level >= 1 )
            amd_dump_p2m_table_level(
                mfn_to_page(_mfn(pde->mfn)), pde->next_level,
                address, indent + 1);
        else
            printk("%*sdfn: %08lx  mfn: %08lx\n",
                   indent, "",
                   (unsigned long)PFN_DOWN(address),
                   (unsigned long)PFN_DOWN(pfn_to_paddr(pde->mfn)));
    }

    unmap_domain_page(table_vaddr);
}

static void amd_dump_p2m_table(struct domain *d)
{
    const struct domain_iommu *hd = dom_iommu(d);

    if ( !hd->arch.root_table )
        return;

    printk("p2m table has %d levels\n", hd->arch.paging_mode);
    amd_dump_p2m_table_level(hd->arch.root_table, hd->arch.paging_mode, 0, 0);
}

static const struct iommu_ops __initconstrel _iommu_ops = {
    .init = amd_iommu_domain_init,
    .hwdom_init = amd_iommu_hwdom_init,
    .add_device = amd_iommu_add_device,
    .remove_device = amd_iommu_remove_device,
    .assign_device  = amd_iommu_assign_device,
    .teardown = amd_iommu_domain_destroy,
    .map_page = amd_iommu_map_page,
    .unmap_page = amd_iommu_unmap_page,
    .iotlb_flush = amd_iommu_flush_iotlb_pages,
    .iotlb_flush_all = amd_iommu_flush_iotlb_all,
    .free_page_table = deallocate_page_table,
    .reassign_device = reassign_device,
    .get_device_group_id = amd_iommu_group_id,
    .enable_x2apic = iov_enable_xt,
    .update_ire_from_apic = amd_iommu_ioapic_update_ire,
    .update_ire_from_msi = amd_iommu_msi_msg_update_ire,
    .read_apic_from_ire = amd_iommu_read_ioapic_from_ire,
    .read_msi_from_ire = amd_iommu_read_msi_from_ire,
    .setup_hpet_msi = amd_setup_hpet_msi,
    .adjust_irq_affinities = iov_adjust_irq_affinities,
    .suspend = amd_iommu_suspend,
    .resume = amd_iommu_resume,
    .crash_shutdown = amd_iommu_crash_shutdown,
    .dump_p2m_table = amd_dump_p2m_table,
};

static const struct iommu_init_ops __initconstrel _iommu_init_ops = {
    .ops = &_iommu_ops,
    .setup = iov_detect,
    .supports_x2apic = iov_supports_xt,
};
