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

LIST_HEAD(ats_dev_drhd_units);

#define ATS_REG_CAP    4
#define ATS_REG_CTL    6
#define ATS_QUEUE_DEPTH_MASK     0xF
#define ATS_ENABLE               (1<<15)

struct pci_ats_dev {
    struct list_head list;
    u8 bus;
    u8 devfn;
    u16 ats_queue_depth;    /* ATS device invalidation queue depth */
    spinlock_t lock;
};
static LIST_HEAD(ats_devices);

static void parse_ats_param(char *s);
custom_param("ats", parse_ats_param);

int ats_enabled = 1;

static void parse_ats_param(char *s)
{
    char *ss;

    do {
        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        if ( !strcmp(s, "off") || !strcmp(s, "no") || !strcmp(s, "false") ||
             !strcmp(s, "0") || !strcmp(s, "disable") )
            ats_enabled = 0;

        if ( !strcmp(s, "on") || !strcmp(s, "yes") || !strcmp(s, "true") ||
             !strcmp(s, "1") || !strcmp(s, "enable") )
            ats_enabled = 1;

        s = ss + 1;
    } while ( ss );
}

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

int ats_device(int seg, int bus, int devfn)
{
    struct acpi_drhd_unit *drhd, *ats_drhd, *new_drhd;
    struct pci_dev *pdev;
    int pos = 0;

    if ( !ats_enabled || !iommu_qinval )
        return 0;

    pdev = pci_get_pdev(bus, devfn);
    drhd = acpi_find_matched_drhd_unit(pdev);
    if ( !ecap_queued_inval(drhd->iommu->ecap) ||
         !ecap_dev_iotlb(drhd->iommu->ecap) )
        return 0;

    if ( !acpi_find_matched_atsr_unit(bus, devfn) )
        return 0;

    ats_drhd = find_ats_dev_drhd(drhd->iommu);
    pos = pci_find_ext_capability(seg, bus, devfn, PCI_EXT_CAP_ID_ATS);

    if ( pos && (ats_drhd == NULL) )
    {
        new_drhd = xmalloc(struct acpi_drhd_unit);
        memcpy(new_drhd, drhd, sizeof(struct acpi_drhd_unit));
        list_add_tail(&new_drhd->list, &ats_dev_drhd_units);
    }
    return pos;
}

int enable_ats_device(int seg, int bus, int devfn)
{
    struct pci_ats_dev *pdev;
    u32 value;
    u16 queue_depth;
    int pos;

    if ( acpi_find_matched_atsr_unit(bus, devfn) )
        return 0;

    pos = pci_find_ext_capability(seg, bus, devfn, PCI_EXT_CAP_ID_ATS);
    if ( !pos )
    {
        dprintk(XENLOG_ERR VTDPREFIX, "ats capability not found %x:%x.%x\n",
                bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        return 0;
    }
    else
        dprintk(XENLOG_ERR VTDPREFIX, "ats capability found %x:%x.%x\n",
                bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

    /* BUGBUG: add back seg when multi-seg platform support is enabled */
    value = pci_conf_read16(bus, PCI_SLOT(devfn),
                            PCI_FUNC(devfn), pos + ATS_REG_CAP);
    queue_depth = value & ATS_QUEUE_DEPTH_MASK;

    value = pci_conf_read16(bus, PCI_SLOT(devfn),
                            PCI_FUNC(devfn), pos + ATS_REG_CTL);
    value |= ATS_ENABLE;
    pci_conf_write16(bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                     pos + ATS_REG_CTL, value);

    pdev = xmalloc(struct pci_ats_dev);
    pdev->bus = bus;
    pdev->devfn = devfn;
    pdev->ats_queue_depth = queue_depth;
    list_add(&(pdev->list), &ats_devices);

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

    if ( found )
        return 1;

    return 0;
}

int dev_invalidate_iotlb(struct iommu *iommu, u16 did,
    u64 addr, unsigned int size_order, u64 type)
{
    struct pci_ats_dev *pdev;
    int sbit, ret = 0;
    u16 sid;

    if ( !ecap_dev_iotlb(iommu->ecap) )
        return ret;

    list_for_each_entry( pdev, &ats_devices, list )
    {
        sid = (pdev->bus << 8) | pdev->devfn;

        switch ( type ) {
        case DMA_TLB_DSI_FLUSH:
            if ( !device_in_domain(iommu, pdev, did) )
                break;
            /* fall through if DSI condition met */
        case DMA_TLB_GLOBAL_FLUSH:
            /* invalidate all translations: sbit=1,bit_63=0,bit[62:12]=1 */
            sbit = 1;
            addr = (~0 << PAGE_SHIFT_4K) & 0x7FFFFFFFFFFFFFFF;
            ret |= qinval_device_iotlb(iommu, pdev->ats_queue_depth,
                                       sid, sbit, addr);
            break;
        case DMA_TLB_PSI_FLUSH:
            if ( !device_in_domain(iommu, pdev, did) )
                break;

            addr &= ~0 << (PAGE_SHIFT + size_order);

            /* if size <= 4K, set sbit = 0, else set sbit = 1 */
            sbit = size_order ? 1 : 0;

            /* clear lower bits */
            addr &= (~0 << (PAGE_SHIFT + size_order));

            /* if sbit == 1, zero out size_order bit and set lower bits to 1 */
            if ( sbit )
                addr &= (~0  & ~(1 << (PAGE_SHIFT + size_order)));

            ret |= qinval_device_iotlb(iommu, pdev->ats_queue_depth,
                                       sid, sbit, addr);
            break;
        default:
            dprintk(XENLOG_WARNING VTDPREFIX, "invalid vt-d flush type\n");
            break;
        }
    }
    return ret;
}
