/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Author: Allen Kay <allen.m.kay@intel.com>
 */

#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/msi.h>
#include "../iommu.h"
#include "../dmar.h"
#include "../vtd.h"
#include "../extern.h"
#include "../../ats.h"

static LIST_HEAD(ats_dev_drhd_units);

struct acpi_drhd_unit * find_ats_dev_drhd(struct iommu *iommu)
{
    struct acpi_drhd_unit *drhd;
    list_for_each_entry ( drhd, &ats_dev_drhd_units, list )
    {
        if ( drhd->iommu == iommu )
            return drhd;
    }
    return NULL;
}

int ats_device(const struct pci_dev *pdev, const struct acpi_drhd_unit *drhd)
{
    struct acpi_drhd_unit *ats_drhd;
    int pos;

    if ( !ats_enabled || !iommu_qinval )
        return 0;

    if ( !ecap_queued_inval(drhd->iommu->ecap) ||
         !ecap_dev_iotlb(drhd->iommu->ecap) )
        return 0;

    if ( !acpi_find_matched_atsr_unit(pdev) )
        return 0;

    ats_drhd = find_ats_dev_drhd(drhd->iommu);
    pos = pci_find_ext_capability(pdev->seg, pdev->bus, pdev->devfn,
                                  PCI_EXT_CAP_ID_ATS);

    if ( pos && (ats_drhd == NULL) )
    {
        ats_drhd = xmalloc(struct acpi_drhd_unit);
        if ( !ats_drhd )
            return -ENOMEM;
        *ats_drhd = *drhd;
        list_add_tail(&ats_drhd->list, &ats_dev_drhd_units);
    }
    return pos;
}

static int device_in_domain(struct iommu *iommu, struct pci_ats_dev *pdev, u16 did)
{
    struct root_entry *root_entry = NULL;
    struct context_entry *ctxt_entry = NULL;
    int tt, found = 0;

    root_entry = (struct root_entry *) map_vtd_domain_page(iommu->root_maddr);
    if ( !root_entry || !root_present(root_entry[pdev->bus]) )
        goto out;

    ctxt_entry = (struct context_entry *)
                 map_vtd_domain_page(root_entry[pdev->bus].val);

    if ( ctxt_entry == NULL )
        goto out;

    if ( context_domain_id(ctxt_entry[pdev->devfn]) != did )
        goto out;

    tt = context_translation_type(ctxt_entry[pdev->devfn]);
    if ( tt != CONTEXT_TT_DEV_IOTLB )
        goto out;

    found = 1;
out:
    if ( root_entry )
        unmap_vtd_domain_page(root_entry);

    if ( ctxt_entry )
        unmap_vtd_domain_page(ctxt_entry);

    return found;
}

int dev_invalidate_iotlb(struct iommu *iommu, u16 did,
    u64 addr, unsigned int size_order, u64 type)
{
    struct pci_ats_dev *pdev;
    int ret = 0;

    if ( !ecap_dev_iotlb(iommu->ecap) )
        return ret;

    list_for_each_entry( pdev, &ats_devices, list )
    {
        u16 sid = PCI_BDF2(pdev->bus, pdev->devfn);
        bool_t sbit;
        int rc = 0;

        /* Only invalidate devices that belong to this IOMMU */
        if ( pdev->iommu != iommu )
            continue;

        switch ( type )
        {
        case DMA_TLB_DSI_FLUSH:
            if ( !device_in_domain(iommu, pdev, did) )
                break;
            /* fall through if DSI condition met */
        case DMA_TLB_GLOBAL_FLUSH:
            /* invalidate all translations: sbit=1,bit_63=0,bit[62:12]=1 */
            sbit = 1;
            addr = (~0 << PAGE_SHIFT_4K) & 0x7FFFFFFFFFFFFFFF;
            rc = qinval_device_iotlb(iommu, pdev->ats_queue_depth,
                                     sid, sbit, addr);
            break;
        case DMA_TLB_PSI_FLUSH:
            if ( !device_in_domain(iommu, pdev, did) )
                break;

            /* if size <= 4K, set sbit = 0, else set sbit = 1 */
            sbit = size_order ? 1 : 0;

            /* clear lower bits */
            addr &= ~0 << PAGE_SHIFT_4K;

            /* if sbit == 1, zero out size_order bit and set lower bits to 1 */
            if ( sbit )
            {
                addr &= ~((u64)PAGE_SIZE_4K << (size_order - 1));
                addr |= (((u64)1 << (size_order - 1)) - 1) << PAGE_SHIFT_4K;
            }

            rc = qinval_device_iotlb(iommu, pdev->ats_queue_depth,
                                     sid, sbit, addr);
            break;
        default:
            dprintk(XENLOG_WARNING VTDPREFIX, "invalid vt-d flush type\n");
            return -EOPNOTSUPP;
        }

        if ( !ret )
            ret = rc;
    }

    return ret;
}
