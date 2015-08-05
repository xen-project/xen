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
 * this program; If not, see <http://www.gnu.org/licenses/>.
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
#include <xen/pci_ids.h>
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

/* SandyBridge IGD timeouts in milliseconds */
#define SNB_IGD_TIMEOUT_LEGACY    1000
#define SNB_IGD_TIMEOUT            670
static unsigned int snb_igd_timeout;

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

    if ( !iommu_igfx )
        return 0;

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
    u64 igd_mmio;

    if ( !is_cantiga_b3 && !is_snb_gfx )
        return;

    if ( igd_reg_va )
        return;

    igd_mmio   = pci_conf_read32(0, 0, IGD_DEV, 0, PCI_BASE_ADDRESS_1);
    igd_mmio <<= 32;
    igd_mmio  += pci_conf_read32(0, 0, IGD_DEV, 0, PCI_BASE_ADDRESS_0);
    igd_reg_va = ioremap(igd_mmio & IGD_BAR_MASK, 0x3000);
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
     * Read IGD register at IGD MMIO + 0x20A4 to force IGD
     * to exit low power state.
     */
    return *(volatile int *)(igd_reg_va + 0x20A4);
}

/*
 * Sandybridge RC6 power management inhibit state erratum.
 * This can cause power high power consumption.
 * Workaround is to prevent graphics get into RC6
 * state when doing VT-d IOTLB operations, do the VT-d
 * IOTLB operation, and then re-enable RC6 state.
 *
 * This quirk is enabled with the snb_igd_quirk command
 * line parameter.  Specifying snb_igd_quirk with no value
 * (or any of the standard boolean values) enables this
 * quirk and sets the timeout to the legacy timeout of
 * 1000 msec.  Setting this parameter to the string
 * "cap" enables this quirk and sets the timeout to
 * the theoretical maximum of 670 msec.  Setting this
 * parameter to a numerical value enables the quirk and
 * sets the timeout to that numerical number of msecs.
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

    *(volatile u32 *)(igd_reg_va + 0x2054) = 0x000FFFFF;
    *(volatile u32 *)(igd_reg_va + 0x2700) = 0;

    start_time = NOW();
    while ( (*(volatile u32 *)(igd_reg_va + 0x22AC) & 0xF) != 0 )
    {
        if ( NOW() > start_time + snb_igd_timeout )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "snb_vtd_ops_preamble: failed to disable idle handshake\n");
            break;
        }
        cpu_relax();
    }

    *(volatile u32 *)(igd_reg_va + 0x2050) = 0x10001;
}

static void snb_vtd_ops_postamble(struct iommu* iommu)
{
    struct intel_iommu *intel = iommu->intel;
    struct acpi_drhd_unit *drhd = intel ? intel->drhd : NULL;

    if ( !is_igd_drhd(drhd) || !is_snb_gfx )
        return;

    if ( !igd_reg_va )
        return;

    *(volatile u32 *)(igd_reg_va + 0x2054) = 0xA;
    *(volatile u32 *)(igd_reg_va + 0x2050) = 0x10000;
}

/*
 * call before VT-d translation enable and IOTLB flush operations.
 */

void vtd_ops_preamble_quirk(struct iommu* iommu)
{
    cantiga_vtd_ops_preamble(iommu);
    if ( snb_igd_timeout != 0 )
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
    if ( snb_igd_timeout != 0 )
    {
        snb_vtd_ops_postamble(iommu);

        /* match the lock in preamble */
        spin_unlock(&igd_lock);
    }
}

static void __init parse_snb_timeout(const char *s)
{
    int t;

    t = parse_bool(s);
    if ( t < 0 )
    {
        if ( *s == '\0' )
            t = SNB_IGD_TIMEOUT_LEGACY;
        else if ( strcmp(s, "cap") == 0 )
            t = SNB_IGD_TIMEOUT;
        else
            t = strtoul(s, NULL, 0);
    }
    else
        t = t ? SNB_IGD_TIMEOUT_LEGACY : 0;
    snb_igd_timeout = MILLISECS(t);

    return;
}
custom_param("snb_igd_quirk", parse_snb_timeout);

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
            iommu_enable = 0;
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
                                   PCI_DEVFN(dev, 7), NULL);
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

void pci_vtd_quirk(const struct pci_dev *pdev)
{
    int seg = pdev->seg;
    int bus = pdev->bus;
    int dev = PCI_SLOT(pdev->devfn);
    int func = PCI_FUNC(pdev->devfn);
    int pos;
    bool_t ff;
    u32 val, val2;
    u64 bar;
    paddr_t pa;
    const char *action;

    if ( pci_conf_read16(seg, bus, dev, func, PCI_VENDOR_ID) !=
         PCI_VENDOR_ID_INTEL )
        return;

    switch ( pci_conf_read16(seg, bus, dev, func, PCI_DEVICE_ID) )
    {
    /*
     * Mask reporting Intel VT-d faults to IOH core logic:
     *   - Some platform escalates VT-d faults to platform errors.
     *   - This can cause system failure upon non-fatal VT-d faults.
     *   - Potential security issue if malicious guest trigger VT-d faults.
     */
    case 0x0e28: /* Xeon-E5v2 (IvyBridge) */
    case 0x342e: /* Tylersburg chipset (Nehalem / Westmere systems) */
    case 0x3728: /* Xeon C5500/C3500 (JasperForest) */
    case 0x3c28: /* Sandybridge */
        val = pci_conf_read32(seg, bus, dev, func, 0x1AC);
        pci_conf_write32(seg, bus, dev, func, 0x1AC, val | (1 << 31));
        printk(XENLOG_INFO "Masked VT-d error signaling on %04x:%02x:%02x.%u\n",
               seg, bus, dev, func);
        break;

    /* Tylersburg (EP)/Boxboro (MP) chipsets (NHM-EP/EX, WSM-EP/EX) */
    case 0x3400 ... 0x3407: /* host bridges */
    case 0x3408 ... 0x3411: case 0x3420 ... 0x3421: /* root ports */
    /* JasperForest (Intel Xeon Processor C5500/C3500 */
    case 0x3700 ... 0x370f: /* host bridges */
    case 0x3720 ... 0x3724: /* root ports */
    /* Sandybridge-EP (Romley) */
    case 0x3c00: /* host bridge */
    case 0x3c01 ... 0x3c0b: /* root ports */
        pos = pci_find_ext_capability(seg, bus, pdev->devfn,
                                      PCI_EXT_CAP_ID_ERR);
        if ( !pos )
        {
            pos = pci_find_ext_capability(seg, bus, pdev->devfn,
                                          PCI_EXT_CAP_ID_VNDR);
            while ( pos )
            {
                val = pci_conf_read32(seg, bus, dev, func, pos + PCI_VNDR_HEADER);
                if ( PCI_VNDR_HEADER_ID(val) == 4 && PCI_VNDR_HEADER_REV(val) == 1 )
                {
                    pos += PCI_VNDR_HEADER;
                    break;
                }
                pos = pci_find_next_ext_capability(seg, bus, pdev->devfn, pos,
                                                   PCI_EXT_CAP_ID_VNDR);
            }
            ff = 0;
        }
        else
            ff = pcie_aer_get_firmware_first(pdev);
        if ( !pos )
        {
            printk(XENLOG_WARNING "%04x:%02x:%02x.%u without AER capability?\n",
                   seg, bus, dev, func);
            break;
        }

        val = pci_conf_read32(seg, bus, dev, func, pos + PCI_ERR_UNCOR_MASK);
        val2 = pci_conf_read32(seg, bus, dev, func, pos + PCI_ERR_COR_MASK);
        if ( (val & PCI_ERR_UNC_UNSUP) && (val2 & PCI_ERR_COR_ADV_NFAT) )
            action = "Found masked";
        else if ( !ff )
        {
            pci_conf_write32(seg, bus, dev, func, pos + PCI_ERR_UNCOR_MASK,
                             val | PCI_ERR_UNC_UNSUP);
            pci_conf_write32(seg, bus, dev, func, pos + PCI_ERR_COR_MASK,
                             val2 | PCI_ERR_COR_ADV_NFAT);
            action = "Masked";
        }
        else
            action = "Must not mask";

        /* XPUNCERRMSK Send Completion with Unsupported Request */
        val = pci_conf_read32(seg, bus, dev, func, 0x20c);
        pci_conf_write32(seg, bus, dev, func, 0x20c, val | (1 << 4));

        printk(XENLOG_INFO "%s UR signaling on %04x:%02x:%02x.%u\n",
               action, seg, bus, dev, func);
        break;

    case 0x0040: case 0x0044: case 0x0048: /* Nehalem/Westmere */
    case 0x0100: case 0x0104: case 0x0108: /* Sandybridge */
    case 0x0150: case 0x0154: case 0x0158: /* Ivybridge */
    case 0x0a00: case 0x0a04: case 0x0a08: case 0x0a0f: /* Haswell ULT */
    case 0x0c00: case 0x0c04: case 0x0c08: case 0x0c0f: /* Haswell */
    case 0x0d00: case 0x0d04: case 0x0d08: case 0x0d0f: /* Haswell */
    case 0x1600: case 0x1604: case 0x1608: case 0x160f: /* Broadwell */
    case 0x1610: case 0x1614: case 0x1618: /* Broadwell */
    case 0x1900: case 0x1904: case 0x1908: case 0x190c: case 0x190f: /* Skylake */
    case 0x1910: case 0x1918: case 0x191f: /* Skylake */
        bar = pci_conf_read32(seg, bus, dev, func, 0x6c);
        bar = (bar << 32) | pci_conf_read32(seg, bus, dev, func, 0x68);
        pa = bar & 0x7ffffff000UL; /* bits 12...38 */
        if ( (bar & 1) && pa &&
             page_is_ram_type(paddr_to_pfn(pa), RAM_TYPE_RESERVED) )
        {
            u32 __iomem *va = ioremap(pa, PAGE_SIZE);

            if ( va )
            {
                __set_bit(0x1c8 * 8 + 20, va);
                iounmap(va);
                printk(XENLOG_INFO "Masked UR signaling on %04x:%02x:%02x.%u\n",
                       seg, bus, dev, func);
            }
            else
                printk(XENLOG_ERR "Could not map %"PRIpaddr" for %04x:%02x:%02x.%u\n",
                       pa, seg, bus, dev, func);
        }
        else
            printk(XENLOG_WARNING "Bogus DMIBAR %#"PRIx64" on %04x:%02x:%02x.%u\n",
                   bar, seg, bus, dev, func);
        break;
    }
}
