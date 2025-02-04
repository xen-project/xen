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

#include <xen/iocap.h>
#include <xen/softirq.h>

#include <asm/acpi.h>

#include "iommu.h"
#include "../ats.h"

/* dom_io is used as a sentinel for quarantined devices */
#define QUARANTINE_SKIP(d, p) ((d) == dom_io && !(p)->arch.amd.root_table)

static bool __read_mostly init_done;

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

            printk(XENLOG_WARNING "%pp not found in ACPI tables;"
                   " using same IOMMU as function 0\n", &PCI_SBDF(seg, bdf));

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
 * Return original device id if both the specific entry and the alias entry
 * have been marked valid.
 */
int get_dma_requestor_id(uint16_t seg, uint16_t bdf)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);
    int req_id;

    BUG_ON ( bdf >= ivrs_bdf_entries );
    req_id = ivrs_mappings[bdf].dte_requestor_id;
    if ( ivrs_mappings[bdf].valid && ivrs_mappings[req_id].valid )
        req_id = bdf;

    return req_id;
}

static int __must_check allocate_domain_resources(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    int rc;

    spin_lock(&hd->arch.mapping_lock);
    rc = amd_iommu_alloc_root(d);
    spin_unlock(&hd->arch.mapping_lock);

    return rc;
}

static bool any_pdev_behind_iommu(const struct domain *d,
                                  const struct pci_dev *exclude,
                                  const struct amd_iommu *iommu)
{
    const struct pci_dev *pdev;

    for_each_pdev ( d, pdev )
    {
        if ( pdev == exclude )
            continue;

        if ( find_iommu_for_device(pdev->seg, pdev->sbdf.bdf) == iommu )
            return true;
    }

    return false;
}

static bool use_ats(
    const struct pci_dev *pdev,
    const struct amd_iommu *iommu,
    const struct ivrs_mappings *ivrs_dev)
{
    return !ivrs_dev->block_ats &&
           iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) &&
           pci_ats_device(iommu->seg, pdev->bus, pdev->devfn);
}

static int __must_check amd_iommu_setup_domain_device(
    struct domain *domain, struct amd_iommu *iommu,
    uint8_t devfn, struct pci_dev *pdev)
{
    struct amd_iommu_dte *table, *dte;
    unsigned long flags;
    unsigned int req_id, sr_flags;
    int rc;
    u8 bus = pdev->bus;
    struct domain_iommu *hd = dom_iommu(domain);
    const struct ivrs_mappings *ivrs_dev;
    const struct page_info *root_pg;
    domid_t domid;

    if ( QUARANTINE_SKIP(domain, pdev) )
        return 0;

    BUG_ON(!hd->arch.amd.paging_mode || !iommu->dev_table.buffer);

    rc = allocate_domain_resources(domain);
    if ( rc )
        return rc;

    req_id = get_dma_requestor_id(iommu->seg, pdev->sbdf.bdf);
    ivrs_dev = &get_ivrs_mappings(iommu->seg)[req_id];
    sr_flags = (iommu_hwdom_passthrough && is_hardware_domain(domain)
                ? 0 : SET_ROOT_VALID)
               | (ivrs_dev->unity_map ? SET_ROOT_WITH_UNITY_MAP : 0);

    /* get device-table entry */
    req_id = get_dma_requestor_id(iommu->seg, PCI_BDF(bus, devfn));
    table = iommu->dev_table.buffer;
    dte = &table[req_id];
    ivrs_dev = &get_ivrs_mappings(iommu->seg)[req_id];

    if ( domain != dom_io )
    {
        root_pg = hd->arch.amd.root_table;
        domid = domain->domain_id;
    }
    else
    {
        root_pg = pdev->arch.amd.root_table;
        domid = pdev->arch.pseudo_domid;
    }

    spin_lock_irqsave(&iommu->lock, flags);

    if ( !dte->v || !dte->tv )
    {
        /* bind DTE to domain page-tables */
        rc = amd_iommu_set_root_page_table(
                 dte, page_to_maddr(root_pg), domid,
                 hd->arch.amd.paging_mode, sr_flags);
        if ( rc )
        {
            ASSERT(rc < 0);
            spin_unlock_irqrestore(&iommu->lock, flags);
            return rc;
        }

        /* Undo what amd_iommu_disable_domain_device() may have done. */
        if ( dte->it_root )
        {
            dte->int_ctl = IOMMU_DEV_TABLE_INT_CONTROL_TRANSLATED;
            smp_wmb();
        }
        dte->iv = iommu_intremap;
        dte->ex = ivrs_dev->dte_allow_exclusion;
        dte->sys_mgt = MASK_EXTR(ivrs_dev->device_flags, ACPI_IVHD_SYSTEM_MGMT);

        if ( use_ats(pdev, iommu, ivrs_dev) )
            dte->i = ats_enabled;

        spin_unlock_irqrestore(&iommu->lock, flags);

        /* DTE didn't have DMA translations enabled, do not flush the TLB. */
        amd_iommu_flush_device(iommu, req_id, DOMID_INVALID);
    }
    else if ( dte->pt_root != mfn_x(page_to_mfn(root_pg)) )
    {
        domid_t prev_domid = dte->domain_id;

        /*
         * Strictly speaking if the device is the only one with this requestor
         * ID, it could be allowed to be re-assigned regardless of unity map
         * presence.  But let's deal with that case only if it is actually
         * found in the wild.
         */
        if ( req_id != PCI_BDF(bus, devfn) &&
             (sr_flags & SET_ROOT_WITH_UNITY_MAP) )
            rc = -EOPNOTSUPP;
        else
            rc = amd_iommu_set_root_page_table(
                     dte, page_to_maddr(root_pg), domid,
                     hd->arch.amd.paging_mode, sr_flags);
        if ( rc < 0 )
        {
            spin_unlock_irqrestore(&iommu->lock, flags);
            return rc;
        }
        if ( rc &&
             domain != pdev->domain &&
             /*
              * By non-atomically updating the DTE's domain ID field last,
              * during a short window in time TLB entries with the old domain
              * ID but the new page tables may have been inserted.  This could
              * affect I/O of other devices using this same (old) domain ID.
              * Such updating therefore is not a problem if this was the only
              * device associated with the old domain ID.  Diverting I/O of any
              * of a dying domain's devices to the quarantine page tables is
              * intended anyway.
              */
             !pdev->domain->is_dying &&
             pdev->domain != dom_io &&
             (any_pdev_behind_iommu(pdev->domain, pdev, iommu) ||
              pdev->phantom_stride) )
            AMD_IOMMU_WARN(" %pp: reassignment may cause %pd data corruption\n",
                           &PCI_SBDF(pdev->seg, bus, devfn), pdev->domain);

        /*
         * Check remaining settings are still in place from an earlier call
         * here. They're all independent of the domain, so should not have
         * changed.
         */
        if ( dte->it_root )
            ASSERT(dte->int_ctl == IOMMU_DEV_TABLE_INT_CONTROL_TRANSLATED);
        ASSERT(dte->iv == !!iommu_intremap);
        ASSERT(dte->ex == ivrs_dev->dte_allow_exclusion);
        ASSERT(dte->sys_mgt == MASK_EXTR(ivrs_dev->device_flags,
                                         ACPI_IVHD_SYSTEM_MGMT));

        if ( use_ats(pdev, iommu, ivrs_dev) )
            ASSERT(dte->i == ats_enabled);

        spin_unlock_irqrestore(&iommu->lock, flags);

        amd_iommu_flush_device(iommu, req_id, prev_domid);
    }
    else
        spin_unlock_irqrestore(&iommu->lock, flags);

    AMD_IOMMU_DEBUG("Setup I/O page table: device id = %#x, type = %#x, "
                    "root table = %#"PRIx64", "
                    "domain = %d, paging mode = %d\n",
                    req_id, pdev->type, page_to_maddr(root_pg),
                    domid, hd->arch.amd.paging_mode);

    ASSERT(pcidevs_locked());

    if ( use_ats(pdev, iommu, ivrs_dev) &&
         !pci_ats_enabled(iommu->seg, bus, pdev->devfn) )
    {
        if ( devfn == pdev->devfn )
            enable_ats_device(pdev, &iommu->ats_devices);

        amd_iommu_flush_iotlb(devfn, pdev, INV_IOMMU_ALL_PAGES_ADDRESS, 0);
    }

    return 0;
}

int __init acpi_ivrs_init(void)
{
    int rc;

    rc = amd_iommu_get_supported_ivhd_type();
    if ( rc < 0 )
        return rc;
    BUG_ON(!rc);
    ivhd_type = rc;

    if ( (amd_iommu_detect_acpi() !=0) || (iommu_found() == 0) )
        return -ENODEV;

    iommu_init_ops = &_iommu_init_ops;

    return 0;
}

static int __init cf_check iov_detect(void)
{
    if ( !iommu_enable && !iommu_intremap )
        return 0;

    if ( unlikely(!cpu_has_cx16) )
    {
        AMD_IOMMU_ERROR("no CMPXCHG16B support, disabling IOMMU\n");
        return -ENODEV;
    }

    if ( (init_done ? amd_iommu_init_late()
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

static int cf_check iov_enable_xt(void)
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

int amd_iommu_alloc_root(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( unlikely(!hd->arch.amd.root_table) && d != dom_io )
    {
        hd->arch.amd.root_table = iommu_alloc_pgtable(hd, 0);
        if ( !hd->arch.amd.root_table )
            return -ENOMEM;
    }

    return 0;
}

unsigned int __read_mostly amd_iommu_max_paging_mode = IOMMU_MAX_PT_LEVELS;
int __read_mostly amd_iommu_min_paging_mode = 1;

static int cf_check amd_iommu_domain_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    int pglvl = amd_iommu_get_paging_mode(
                    1UL << (domain_max_paddr_bits(d) - PAGE_SHIFT));

    if ( pglvl < 0 )
        return pglvl;

    /*
     * Choose the number of levels for the IOMMU page tables, taking into
     * account unity maps.
     */
    hd->arch.amd.paging_mode = max(pglvl, amd_iommu_min_paging_mode);

    return 0;
}

static int cf_check amd_iommu_add_device(u8 devfn, struct pci_dev *pdev);

static void __hwdom_init cf_check amd_iommu_hwdom_init(struct domain *d)
{
    const struct amd_iommu *iommu;

    if ( allocate_domain_resources(d) )
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

static void amd_iommu_disable_domain_device(const struct domain *domain,
                                            struct amd_iommu *iommu,
                                            uint8_t devfn, struct pci_dev *pdev)
{
    struct amd_iommu_dte *table, *dte;
    unsigned long flags;
    int req_id;
    u8 bus = pdev->bus;

    if ( QUARANTINE_SKIP(domain, pdev) )
        return;

    ASSERT(pcidevs_locked());

    if ( pci_ats_device(iommu->seg, bus, pdev->devfn) &&
         pci_ats_enabled(iommu->seg, bus, pdev->devfn) )
        disable_ats_device(pdev);

    BUG_ON ( iommu->dev_table.buffer == NULL );
    req_id = get_dma_requestor_id(iommu->seg, PCI_BDF(bus, devfn));
    table = iommu->dev_table.buffer;
    dte = &table[req_id];

    spin_lock_irqsave(&iommu->lock, flags);
    if ( dte->tv || dte->v )
    {
        domid_t prev_domid = dte->domain_id;

        /* See the comment in amd_iommu_setup_device_table(). */
        dte->int_ctl = IOMMU_DEV_TABLE_INT_CONTROL_ABORTED;
        smp_wmb();
        dte->iv = true;
        dte->tv = false;
        dte->gv = false;
        dte->i = false;
        dte->ex = false;
        dte->sa = false;
        dte->se = false;
        dte->sd = false;
        dte->sys_mgt = IOMMU_DEV_TABLE_SYS_MGT_DMA_ABORTED;
        dte->ioctl = IOMMU_DEV_TABLE_IO_CONTROL_ABORTED;
        smp_wmb();
        dte->v = true;

        spin_unlock_irqrestore(&iommu->lock, flags);

        amd_iommu_flush_device(iommu, req_id, prev_domid);

        AMD_IOMMU_DEBUG("Disable: device id = %#x, "
                        "domain = %d, paging mode = %d\n",
                        req_id, dte->domain_id,
                        dom_iommu(domain)->arch.amd.paging_mode);
    }
    else
        spin_unlock_irqrestore(&iommu->lock, flags);
}

static int cf_check reassign_device(
    struct domain *source, struct domain *target, u8 devfn,
    struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    int rc;

    iommu = find_iommu_for_device(pdev->seg, pdev->sbdf.bdf);
    if ( !iommu )
    {
        AMD_IOMMU_WARN("failed to find IOMMU: %pp cannot be assigned to %pd\n",
                       &PCI_SBDF(pdev->seg, pdev->bus, devfn), target);
        return -ENODEV;
    }

    if ( !QUARANTINE_SKIP(target, pdev) )
    {
        rc = amd_iommu_setup_domain_device(target, iommu, devfn, pdev);
        if ( rc )
            return rc;
    }
    else
        amd_iommu_disable_domain_device(source, iommu, devfn, pdev);

    if ( devfn == pdev->devfn && pdev->domain != target )
    {
        write_lock(&source->pci_lock);
        list_del(&pdev->domain_list);
        write_unlock(&source->pci_lock);

        pdev->domain = target;

        write_lock(&target->pci_lock);
        list_add(&pdev->domain_list, &target->pdev_list);
        write_unlock(&target->pci_lock);
    }

    /*
     * If the device belongs to the hardware domain, and it has a unity mapping,
     * don't remove it from the hardware domain, because BIOS may reference that
     * mapping.
     */
    if ( !is_hardware_domain(source) )
    {
        const struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(pdev->seg);
        unsigned int bdf = PCI_BDF(pdev->bus, devfn);

        rc = amd_iommu_reserve_domain_unity_unmap(
                 source,
                 ivrs_mappings[get_dma_requestor_id(pdev->seg, bdf)].unity_map);
        if ( rc )
            return rc;
    }

    AMD_IOMMU_DEBUG("Re-assign %pp from %pd to %pd\n",
                    &PCI_SBDF(pdev->seg, pdev->bus, devfn), source, target);

    return 0;
}

static int cf_check amd_iommu_assign_device(
    struct domain *d, u8 devfn, struct pci_dev *pdev, u32 flag)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(pdev->seg);
    unsigned int bdf = PCI_BDF(pdev->bus, devfn);
    int req_id = get_dma_requestor_id(pdev->seg, bdf);
    int rc = amd_iommu_reserve_domain_unity_map(
                 d, ivrs_mappings[req_id].unity_map, flag);

    if ( !rc )
        rc = reassign_device(pdev->domain, d, devfn, pdev);

    if ( rc && !is_hardware_domain(d) )
    {
        int ret = amd_iommu_reserve_domain_unity_unmap(
                      d, ivrs_mappings[req_id].unity_map);

        if ( ret )
        {
            printk(XENLOG_ERR "AMD-Vi: "
                   "unity-unmap for %pd/%04x:%02x:%02x.%u failed (%d)\n",
                   d, pdev->seg, pdev->bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn), ret);
            domain_crash(d);
        }
    }

    return rc;
}

static void cf_check amd_iommu_clear_root_pgtable(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    spin_lock(&hd->arch.mapping_lock);
    hd->arch.amd.root_table = NULL;
    spin_unlock(&hd->arch.mapping_lock);
}

static void cf_check amd_iommu_domain_destroy(struct domain *d)
{
    iommu_identity_map_teardown(d);
    ASSERT(!dom_iommu(d)->arch.amd.root_table);
}

static int cf_check amd_iommu_add_device(u8 devfn, struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    u16 bdf;
    struct ivrs_mappings *ivrs_mappings;
    bool fresh_domid = false;
    int ret;

    if ( !pdev->domain )
        return -EINVAL;

    for_each_amd_iommu(iommu)
        if ( pdev->seg == iommu->seg && pdev->sbdf.bdf == iommu->bdf )
            return is_hardware_domain(pdev->domain) ? 0 : -ENODEV;

    iommu = find_iommu_for_device(pdev->seg, pdev->sbdf.bdf);
    if ( unlikely(!iommu) )
    {
        /* Filter bridge devices. */
        if ( pdev->type == DEV_TYPE_PCI_HOST_BRIDGE &&
             is_hardware_domain(pdev->domain) )
        {
            AMD_IOMMU_DEBUG("Skipping host bridge %pp\n", &pdev->sbdf);
            return 0;
        }

        AMD_IOMMU_WARN("no IOMMU for %pp; cannot be handed to %pd\n",
                        &PCI_SBDF(pdev->seg, pdev->bus, devfn), pdev->domain);
        return -ENODEV;
    }

    ivrs_mappings = get_ivrs_mappings(pdev->seg);
    bdf = PCI_BDF(pdev->bus, devfn);
    if ( !ivrs_mappings ||
         !ivrs_mappings[ivrs_mappings[bdf].dte_requestor_id].valid )
        return -EPERM;

    if ( iommu_intremap &&
         ivrs_mappings[bdf].dte_requestor_id == bdf &&
         !ivrs_mappings[bdf].intremap_table )
    {
        unsigned long flags;

        if ( pdev->msix || pdev->msi_maxvec )
        {
            ivrs_mappings[bdf].intremap_table =
                amd_iommu_alloc_intremap_table(
                    iommu, &ivrs_mappings[bdf].intremap_inuse,
                    pdev->msix ? pdev->msix->nr_entries
                               : pdev->msi_maxvec);
            if ( !ivrs_mappings[bdf].intremap_table )
                return -ENOMEM;
        }

        spin_lock_irqsave(&iommu->lock, flags);

        amd_iommu_set_intremap_table(
            iommu->dev_table.buffer + (bdf * IOMMU_DEV_TABLE_ENTRY_SIZE),
            ivrs_mappings[bdf].intremap_table, iommu, iommu_intremap);

        spin_unlock_irqrestore(&iommu->lock, flags);

        /* DTE didn't have DMA translations enabled, do not flush the TLB. */
        amd_iommu_flush_device(iommu, bdf, DOMID_INVALID);
    }

    if ( amd_iommu_reserve_domain_unity_map(
             pdev->domain,
             ivrs_mappings[ivrs_mappings[bdf].dte_requestor_id].unity_map,
             0) )
        AMD_IOMMU_WARN("%pd: unity mapping failed for %pp\n",
                       pdev->domain, &PCI_SBDF(pdev->seg, bdf));

    if ( iommu_quarantine && pdev->arch.pseudo_domid == DOMID_INVALID )
    {
        pdev->arch.pseudo_domid = iommu_alloc_domid(iommu->domid_map);
        if ( pdev->arch.pseudo_domid == DOMID_INVALID )
            return -ENOSPC;
        fresh_domid = true;
    }

    ret = amd_iommu_setup_domain_device(pdev->domain, iommu, devfn, pdev);
    if ( ret && fresh_domid )
    {
        iommu_free_domid(pdev->arch.pseudo_domid, iommu->domid_map);
        pdev->arch.pseudo_domid = DOMID_INVALID;
    }

    return ret;
}

static int cf_check amd_iommu_remove_device(u8 devfn, struct pci_dev *pdev)
{
    struct amd_iommu *iommu;
    u16 bdf;
    struct ivrs_mappings *ivrs_mappings;

    if ( !pdev->domain )
        return -EINVAL;

    iommu = find_iommu_for_device(pdev->seg, pdev->sbdf.bdf);
    if ( !iommu )
    {
        AMD_IOMMU_WARN("failed to find IOMMU: %pp cannot be removed from %pd\n",
                        &PCI_SBDF(pdev->seg, pdev->bus, devfn), pdev->domain);
        return -ENODEV;
    }

    amd_iommu_disable_domain_device(pdev->domain, iommu, devfn, pdev);

    ivrs_mappings = get_ivrs_mappings(pdev->seg);
    bdf = PCI_BDF(pdev->bus, devfn);

    if ( amd_iommu_reserve_domain_unity_unmap(
             pdev->domain,
             ivrs_mappings[ivrs_mappings[bdf].dte_requestor_id].unity_map) )
        AMD_IOMMU_WARN("%pd: unity unmapping failed for %pp\n",
                       pdev->domain, &PCI_SBDF(pdev->seg, bdf));

    amd_iommu_quarantine_teardown(pdev);

    iommu_free_domid(pdev->arch.pseudo_domid, iommu->domid_map);
    pdev->arch.pseudo_domid = DOMID_INVALID;

    if ( amd_iommu_perdev_intremap &&
         ivrs_mappings[bdf].dte_requestor_id == bdf &&
         ivrs_mappings[bdf].intremap_table )
        amd_iommu_free_intremap_table(iommu, &ivrs_mappings[bdf], bdf);

    return 0;
}

static int cf_check amd_iommu_group_id(u16 seg, u8 bus, u8 devfn)
{
    unsigned int bdf = PCI_BDF(bus, devfn);

    return (bdf < ivrs_bdf_entries) ? get_dma_requestor_id(seg, bdf) : bdf;
}

#include <asm/io_apic.h>

static void amd_dump_page_table_level(struct page_info *pg, int level,
                                      paddr_t gpa, int indent)
{
    paddr_t address;
    const union amd_iommu_pte *table_vaddr;
    int index;

    if ( level < 1 )
        return;

    table_vaddr = __map_domain_page(pg);

    for ( index = 0; index < PTE_PER_TABLE_SIZE; index++ )
    {
        const union amd_iommu_pte *pde = &table_vaddr[index];

        if ( !(index % 2) )
            process_pending_softirqs();

        if ( !pde->pr )
            continue;

        if ( pde->next_level && (pde->next_level != (level - 1)) )
        {
            printk("AMD IOMMU table error. next_level = %d, expected %d\n",
                   pde->next_level, level - 1);

            continue;
        }

        address = gpa + amd_offset_level_address(index, level);
        if ( pde->next_level >= 1 )
            amd_dump_page_table_level(
                mfn_to_page(_mfn(pde->mfn)), pde->next_level,
                address, indent + 1);
        else
            printk("%*sdfn: %08lx  mfn: %08lx  %c%c\n",
                   indent, "",
                   (unsigned long)PFN_DOWN(address),
                   (unsigned long)PFN_DOWN(pfn_to_paddr(pde->mfn)),
                   pde->ir ? 'r' : '-', pde->iw ? 'w' : '-');
    }

    unmap_domain_page(table_vaddr);
}

static void cf_check amd_dump_page_tables(struct domain *d)
{
    const struct domain_iommu *hd = dom_iommu(d);

    if ( !hd->arch.amd.root_table )
        return;

    printk("AMD IOMMU %pd table has %u levels\n", d, hd->arch.amd.paging_mode);
    amd_dump_page_table_level(hd->arch.amd.root_table,
                              hd->arch.amd.paging_mode, 0, 0);
}

static const struct iommu_ops __initconst_cf_clobber _iommu_ops = {
    .page_sizes = PAGE_SIZE_4K | PAGE_SIZE_2M | PAGE_SIZE_1G,
    .init = amd_iommu_domain_init,
    .hwdom_init = amd_iommu_hwdom_init,
    .quarantine_init = amd_iommu_quarantine_init,
    .add_device = amd_iommu_add_device,
    .remove_device = amd_iommu_remove_device,
    .assign_device  = amd_iommu_assign_device,
    .teardown = amd_iommu_domain_destroy,
    .clear_root_pgtable = amd_iommu_clear_root_pgtable,
    .map_page = amd_iommu_map_page,
    .unmap_page = amd_iommu_unmap_page,
    .iotlb_flush = amd_iommu_flush_iotlb_pages,
    .reassign_device = reassign_device,
    .get_device_group_id = amd_iommu_group_id,
    .enable_x2apic = iov_enable_xt,
    .update_ire_from_apic = amd_iommu_ioapic_update_ire,
    .update_ire_from_msi = amd_iommu_msi_msg_update_ire,
    .read_apic_from_ire = amd_iommu_read_ioapic_from_ire,
    .setup_hpet_msi = amd_setup_hpet_msi,
    .adjust_irq_affinities = iov_adjust_irq_affinities,
    .suspend = amd_iommu_suspend,
    .resume = amd_iommu_resume,
    .crash_shutdown = amd_iommu_crash_shutdown,
    .get_reserved_device_memory = amd_iommu_get_reserved_device_memory,
    .dump_page_tables = amd_dump_page_tables,
    .quiesce = amd_iommu_quiesce,
};

static const struct iommu_init_ops __initconstrel _iommu_init_ops = {
    .ops = &_iommu_ops,
    .setup = iov_detect,
    .supports_x2apic = iov_supports_xt,
};
