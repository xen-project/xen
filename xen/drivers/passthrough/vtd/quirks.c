/*
 * Copyright (c) 2010, Intel Corporation.
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

#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>
#include <xen/domain_page.h>
#include <xen/iommu.h>
#include <asm/hvm/iommu.h>
#include <xen/numa.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/keyhandler.h>
#include <asm/msi.h>
#include <asm/irq.h>
#include <asm/pci.h>
#include <mach_apic.h>
#include "iommu.h"
#include "dmar.h"
#include "extern.h"
#include "vtd.h"

#define IOH_DEV      0
#define IGD_DEV      2

#define IGD_BAR_MASK 0xFFFFFFFFFFFF0000
#define GGC 0x52
#define GGC_MEMORY_VT_ENABLED  (0x8 << 8)

#define IS_CTG(id)    (id == 0x2a408086)
#define IS_ILK(id)    (id == 0x00408086 || id == 0x00448086 || id== 0x00628086 || id == 0x006A8086)
#define IS_CPT(id)    (id == 0x01008086 || id == 0x01048086)

static u32 __read_mostly ioh_id;
static u32 __initdata igd_id;
bool_t __read_mostly rwbf_quirk;
static bool_t __read_mostly is_cantiga_b3;
static bool_t __read_mostly is_snb_gfx;
static u8 *__read_mostly igd_reg_va;
static spinlock_t igd_lock;

/*
 * QUIRK to workaround Xen boot issue on Calpella/Ironlake OEM BIOS
 * not enabling VT-d properly in IGD.  The workaround is to not enabling
 * IGD VT-d translation if VT is not enabled in IGD.
 */
int is_igd_vt_enabled_quirk(void)
{
    u16 ggc;

    if ( !IS_ILK(ioh_id) )
        return 1;

    /* integrated graphics on Intel platforms is located at 0:2.0 */
    ggc = pci_conf_read16(0, 0, IGD_DEV, 0, GGC);
    return ( ggc & GGC_MEMORY_VT_ENABLED ? 1 : 0 );
}

/*
 * QUIRK to workaround cantiga VT-d buffer flush issue.
 * The workaround is to force write buffer flush even if
 * VT-d capability indicates it is not required.
 */
static void __init cantiga_b3_errata_init(void)
{
    u16 vid;
    u8 did_hi, rid;

    vid = pci_conf_read16(0, 0, IGD_DEV, 0, 0);
    if ( vid != 0x8086 )
        return;

    did_hi = pci_conf_read8(0, 0, IGD_DEV, 0, 3);
    rid = pci_conf_read8(0, 0, IGD_DEV, 0, 8);

    if ( (did_hi == 0x2A) && (rid == 0x7) )
        is_cantiga_b3 = 1;
}

/* check for Sandybridge IGD device ID's */
static void __init snb_errata_init(void)
{
    is_snb_gfx = IS_SNB_GFX(igd_id);
    spin_lock_init(&igd_lock);
}

/*
 * QUIRK to workaround Cantiga IGD VT-d low power errata.
 * This errata impacts IGD assignment on Cantiga systems
 * and can potentially cause VT-d operations to hang.
 * The workaround is to access an IGD PCI config register
 * to get IGD out of low power state before VT-d translation
 * enable/disable and IOTLB flushes.
 */

/*
 * map IGD MMIO+0x2000 page to allow Xen access to IGD 3D register.
 */
static void __init map_igd_reg(void)
{
    u64 igd_mmio, igd_reg;

    if ( !is_cantiga_b3 && !is_snb_gfx )
        return;

    if ( igd_reg_va )
        return;

    /* get IGD mmio address in PCI BAR */
    igd_mmio = ((u64)pci_conf_read32(0, 0, IGD_DEV, 0, 0x14) << 32) +
                     pci_conf_read32(0, 0, IGD_DEV, 0, 0x10);

    /* offset of IGD regster we want to access is in 0x2000 range */
    igd_reg = (igd_mmio & IGD_BAR_MASK) + 0x2000;

    /* ioremap this physical page */
#if defined(CONFIG_X86)
    set_fixmap_nocache(FIX_IGD_MMIO, igd_reg);
    igd_reg_va = (u8 *)fix_to_virt(FIX_IGD_MMIO);
#else
    igd_reg_va = ioremap_nocache(igd_reg, 0x1000);
#endif
}

/*
 * force IGD to exit low power mode by accessing a IGD 3D regsiter.
 */
static int cantiga_vtd_ops_preamble(struct iommu* iommu)
{
    struct intel_iommu *intel = iommu->intel;
    struct acpi_drhd_unit *drhd = intel ? intel->drhd : NULL;

    if ( !is_igd_drhd(drhd) || !is_cantiga_b3 )
        return 0;

    if ( !igd_reg_va )
        return 0;

    /*
     * read IGD register at IGD MMIO + 0x20A4 to force IGD
     * to exit low power state.  Since map_igd_reg()
     * already mapped page starting 0x2000, we just need to
     * add page offset 0x0A4 to virtual address base.
     */
    return ( *((volatile int *)(igd_reg_va + 0x0A4)) );
}

/*
 * Sandybridge RC6 power management inhibit state erratum.
 * This can cause power high power consumption.
 * Workaround is to prevent graphics get into RC6
 * state when doing VT-d IOTLB operations, do the VT-d
 * IOTLB operation, and then re-enable RC6 state.
 */
static void snb_vtd_ops_preamble(struct iommu* iommu)
{
    struct intel_iommu *intel = iommu->intel;
    struct acpi_drhd_unit *drhd = intel ? intel->drhd : NULL;
    s_time_t start_time;

    if ( !is_igd_drhd(drhd) || !is_snb_gfx )
        return;

    if ( !igd_reg_va )
        return;

    *((volatile u32 *)(igd_reg_va + 0x54)) = 0x000FFFFF;
    *((volatile u32 *)(igd_reg_va + 0x700)) = 0;

    start_time = NOW();
    while ( (*((volatile u32 *)(igd_reg_va + 0x2AC)) & 0xF) != 0 )
    {
        if ( NOW() > start_time + DMAR_OPERATION_TIMEOUT )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "snb_vtd_ops_preamble: failed to disable idle handshake\n");
            break;
        }
        cpu_relax();
    }

    *((volatile u32*)(igd_reg_va + 0x50)) = 0x10001;
}

static void snb_vtd_ops_postamble(struct iommu* iommu)
{
    struct intel_iommu *intel = iommu->intel;
    struct acpi_drhd_unit *drhd = intel ? intel->drhd : NULL;

    if ( !is_igd_drhd(drhd) || !is_snb_gfx )
        return;

    if ( !igd_reg_va )
        return;

    *((volatile u32 *)(igd_reg_va + 0x54)) = 0xA;
    *((volatile u32 *)(igd_reg_va + 0x50)) = 0x10000;
}

/*
 * call before VT-d translation enable and IOTLB flush operations.
 */

static int snb_igd_quirk;
boolean_param("snb_igd_quirk", snb_igd_quirk);

void vtd_ops_preamble_quirk(struct iommu* iommu)
{
    cantiga_vtd_ops_preamble(iommu);
    if ( snb_igd_quirk )
    {
        spin_lock(&igd_lock);

        /* match unlock in postamble */
        snb_vtd_ops_preamble(iommu);
    }
}

/*
 * call after VT-d translation enable and IOTLB flush operations.
 */
void vtd_ops_postamble_quirk(struct iommu* iommu)
{
    if ( snb_igd_quirk )
    {
        snb_vtd_ops_postamble(iommu);

        /* match the lock in preamble */
        spin_unlock(&igd_lock);
    }
}

/* 5500/5520/X58 Chipset Interrupt remapping errata, for stepping B-3.
 * Fixed in stepping C-2. */
static void __init tylersburg_intremap_quirk(void)
{
    uint32_t bus, device;
    uint8_t rev;

    for ( bus = 0; bus < 0x100; bus++ )
    {
        /* Match on System Management Registers on Device 20 Function 0 */
        device = pci_conf_read32(0, bus, 20, 0, PCI_VENDOR_ID);
        rev = pci_conf_read8(0, bus, 20, 0, PCI_REVISION_ID);

        if ( rev == 0x13 && device == 0x342e8086 )
        {
            printk(XENLOG_WARNING VTDPREFIX
                   "Disabling IOMMU due to Intel 5500/5520/X58 Chipset errata #47, #53\n");
            iommu_enabled = 0;
            break;
        }
    }
}

/* initialize platform identification flags */
void __init platform_quirks_init(void)
{
    ioh_id = pci_conf_read32(0, 0, IOH_DEV, 0, 0);
    igd_id = pci_conf_read32(0, 0, IGD_DEV, 0, 0);

    /* Mobile 4 Series Chipset neglects to set RWBF capability. */
    if ( ioh_id == 0x2a408086 )
    {
        dprintk(XENLOG_INFO VTDPREFIX, "DMAR: Forcing write-buffer flush\n");
        rwbf_quirk = 1;
    }

    /* initialize cantiga B3 identification */
    cantiga_b3_errata_init();

    snb_errata_init();

    /* ioremap IGD MMIO+0x2000 page */
    map_igd_reg();

    /* Tylersburg interrupt remap quirk */
    if ( iommu_intremap )
        tylersburg_intremap_quirk();
}

/*
 * QUIRK to workaround wifi direct assignment issue.  This issue
 * impacts only cases where Intel integrated wifi device is directly
 * is directly assigned to a guest.
 *
 * The workaround is to map ME phantom device 0:3.7 or 0:22.7
 * to the ME vt-d engine if detect the user is trying to directly
 * assigning Intel integrated wifi device to a guest.
 */

static void map_me_phantom_function(struct domain *domain, u32 dev, int map)
{
    struct acpi_drhd_unit *drhd;
    struct pci_dev *pdev;

    /* find ME VT-d engine base on a real ME device */
    pdev = pci_get_pdev(0, 0, PCI_DEVFN(dev, 0));
    drhd = acpi_find_matched_drhd_unit(pdev);

    /* map or unmap ME phantom function */
    if ( map )
        domain_context_mapping_one(domain, drhd->iommu, 0,
                                   PCI_DEVFN(dev, 7));
    else
        domain_context_unmap_one(domain, drhd->iommu, 0,
                                 PCI_DEVFN(dev, 7));
}

void me_wifi_quirk(struct domain *domain, u8 bus, u8 devfn, int map)
{
    u32 id;

    id = pci_conf_read32(0, 0, 0, 0, 0);
    if ( IS_CTG(id) )
    {
        /* quit if ME does not exist */
        if ( pci_conf_read32(0, 0, 3, 0, 0) == 0xffffffff )
            return;

        /* if device is WLAN device, map ME phantom device 0:3.7 */
        id = pci_conf_read32(0, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), 0);
        switch (id)
        {
            case 0x42328086:
            case 0x42358086:
            case 0x42368086:
            case 0x42378086:
            case 0x423a8086:
            case 0x423b8086:
            case 0x423c8086:
            case 0x423d8086:
                map_me_phantom_function(domain, 3, map);
                break;
            default:
                break;
        }
    }
    else if ( IS_ILK(id) || IS_CPT(id) )
    {
        /* quit if ME does not exist */
        if ( pci_conf_read32(0, 0, 22, 0, 0) == 0xffffffff )
            return;

        /* if device is WLAN device, map ME phantom device 0:22.7 */
        id = pci_conf_read32(0, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), 0);
        switch (id)
        {
            case 0x00878086:        /* Kilmer Peak */
            case 0x00898086:
            case 0x00828086:        /* Taylor Peak */
            case 0x00858086:
            case 0x008F8086:        /* Rainbow Peak */
            case 0x00908086:
            case 0x00918086:
            case 0x42388086:        /* Puma Peak */
            case 0x422b8086:
            case 0x422c8086:
                map_me_phantom_function(domain, 22, map);
                break;
            default:
                break;
        }
    }
}

/*
 * Mask reporting Intel VT-d faults to IOH core logic:
 *   - Some platform escalates VT-d faults to platform errors 
 *   - This can cause system failure upon non-fatal VT-d faults
 *   - Potential security issue if malicious guest trigger VT-d faults
 */
void __init pci_vtd_quirk(struct pci_dev *pdev)
{
#ifdef CONFIG_X86_64
    int seg = pdev->seg;
    int bus = pdev->bus;
    int dev = PCI_SLOT(pdev->devfn);
    int func = PCI_FUNC(pdev->devfn);
    int id, val;

    id = pci_conf_read32(seg, bus, dev, func, 0);
    if ( id == 0x342e8086 || id == 0x3c288086 )
    {
        val = pci_conf_read32(seg, bus, dev, func, 0x1AC);
        pci_conf_write32(seg, bus, dev, func, 0x1AC, val | (1 << 31));
    }
#endif
}
