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
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 */

#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/iommu.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/msi.h>
#include "iommu.h"
#include "dmar.h"
#include "vtd.h"

#define INTEL   0x8086
#define SEABURG 0x4000
#define C_STEP  2

int is_usb_device(struct pci_dev *pdev)
{
    u8 bus = pdev->bus;
    u8 dev = PCI_SLOT(pdev->devfn);
    u8 func = PCI_FUNC(pdev->devfn);
    u16 class = pci_conf_read16(bus, dev, func, PCI_CLASS_DEVICE);
    return (class == 0xc03);
}

int vtd_hw_check(void)
{
    u16 vendor, device;
    u8 revision, stepping;

    vendor   = pci_conf_read16(0, 0, 0, PCI_VENDOR_ID);
    device   = pci_conf_read16(0, 0, 0, PCI_DEVICE_ID);
    revision = pci_conf_read8(0, 0, 0, PCI_REVISION_ID);
    stepping = revision & 0xf;

    if ( (vendor == INTEL) && (device == SEABURG) )
    {
        if ( stepping < C_STEP )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "*** VT-d disabled - pre C0-step Seaburg found\n");
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "***  vendor = %x device = %x revision = %x\n",
                    vendor, device, revision);
            return -ENODEV;
        }
    }

    return 0;
}

/* Disable vt-d protected memory registers. */
void disable_pmr(struct iommu *iommu)
{
    s_time_t start_time;
    unsigned int val;

    val = dmar_readl(iommu->reg, DMAR_PMEN_REG);
    if ( !(val & DMA_PMEN_PRS) )
        return;

    dmar_writel(iommu->reg, DMAR_PMEN_REG, val & ~DMA_PMEN_EPM);
    start_time = NOW();

    for ( ; ; )
    {
        val = dmar_readl(iommu->reg, DMAR_PMEN_REG);
        if ( (val & DMA_PMEN_PRS) == 0 )
            break;

        if ( NOW() > start_time + DMAR_OPERATION_TIMEOUT )
            panic("Disable PMRs timeout\n");

        cpu_relax();
    }

    dprintk(XENLOG_INFO VTDPREFIX,
            "Disabled protected memory registers\n");
}

#define PCI_D3hot   (3)
#define PCI_CONFIG_DWORD_SIZE   (64)
#define PCI_EXP_DEVCAP_FLR      (1 << 28)
#define PCI_EXP_DEVCTL_FLR      (1 << 15)

void pdev_flr(u8 bus, u8 devfn)
{
    u8 pos;
    u32 dev_cap, dev_status, pm_ctl;
    int flr = 0;
    u8 dev = PCI_SLOT(devfn);
    u8 func = PCI_FUNC(devfn);

    pos = pci_find_cap_offset(bus, dev, func, PCI_CAP_ID_EXP);
    if ( pos != 0 )
    {
        dev_cap = pci_conf_read32(bus, dev, func, pos + PCI_EXP_DEVCAP);
        if ( dev_cap & PCI_EXP_DEVCAP_FLR )
        {
            pci_conf_write32(bus, dev, func,
                             pos + PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_FLR);
            do {
                dev_status = pci_conf_read32(bus, dev, func,
                                             pos + PCI_EXP_DEVSTA);
            } while ( dev_status & PCI_EXP_DEVSTA_TRPND );

            flr = 1;
        }
    }

    /* If this device doesn't support function level reset,
     * program device from D0 t0 D3hot, and then return to D0
     * to implement function level reset
     */
    if ( flr == 0 )
    {
        pos = pci_find_cap_offset(bus, dev, func, PCI_CAP_ID_PM);
        if ( pos != 0 )
        {
            int i;
            u32 config[PCI_CONFIG_DWORD_SIZE];
            for ( i = 0; i < PCI_CONFIG_DWORD_SIZE; i++ )
                config[i] = pci_conf_read32(bus, dev, func, i*4);

            /* Enter D3hot without soft reset */
            pm_ctl = pci_conf_read32(bus, dev, func, pos + PCI_PM_CTRL);
            pm_ctl |= PCI_PM_CTRL_NO_SOFT_RESET;
            pm_ctl &= ~PCI_PM_CTRL_STATE_MASK;
            pm_ctl |= PCI_D3hot;
            pci_conf_write32(bus, dev, func, pos + PCI_PM_CTRL, pm_ctl);
            mdelay(10);

            /* From D3hot to D0 */
            pci_conf_write32(bus, dev, func, pos + PCI_PM_CTRL, 0);
            mdelay(10);

            /* Write saved configurations to device */
            for ( i = 0; i < PCI_CONFIG_DWORD_SIZE; i++ )
                pci_conf_write32(bus, dev, func, i*4, config[i]);

            flr = 1;
        }
    }
}

void print_iommu_regs(struct acpi_drhd_unit *drhd)
{
    struct iommu *iommu = drhd->iommu;

    printk("---- print_iommu_regs ----\n");
    printk("print_iommu_regs: drhd->address = %"PRIx64"\n", drhd->address);
    printk("print_iommu_regs: DMAR_VER_REG = %x\n",
           dmar_readl(iommu->reg,DMAR_VER_REG));
    printk("print_iommu_regs: DMAR_CAP_REG = %"PRIx64"\n",
           dmar_readq(iommu->reg,DMAR_CAP_REG));
    printk("print_iommu_regs: n_fault_reg = %"PRIx64"\n",
           cap_num_fault_regs(dmar_readq(iommu->reg, DMAR_CAP_REG)));
    printk("print_iommu_regs: fault_recording_offset_l = %"PRIx64"\n",
           cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)));
    printk("print_iommu_regs: fault_recording_offset_h = %"PRIx64"\n",
           cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)) + 8);
    printk("print_iommu_regs: fault_recording_reg_l = %"PRIx64"\n",
           dmar_readq(iommu->reg,
               cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG))));
    printk("print_iommu_regs: fault_recording_reg_h = %"PRIx64"\n",
           dmar_readq(iommu->reg,
               cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)) + 8));
    printk("print_iommu_regs: DMAR_ECAP_REG = %"PRIx64"\n",
           dmar_readq(iommu->reg,DMAR_ECAP_REG));
    printk("print_iommu_regs: DMAR_GCMD_REG = %x\n",
           dmar_readl(iommu->reg,DMAR_GCMD_REG));
    printk("print_iommu_regs: DMAR_GSTS_REG = %x\n",
           dmar_readl(iommu->reg,DMAR_GSTS_REG));
    printk("print_iommu_regs: DMAR_RTADDR_REG = %"PRIx64"\n",
           dmar_readq(iommu->reg,DMAR_RTADDR_REG));
    printk("print_iommu_regs: DMAR_CCMD_REG = %"PRIx64"\n",
           dmar_readq(iommu->reg,DMAR_CCMD_REG));
    printk("print_iommu_regs: DMAR_FSTS_REG = %x\n",
           dmar_readl(iommu->reg,DMAR_FSTS_REG));
    printk("print_iommu_regs: DMAR_FECTL_REG = %x\n",
           dmar_readl(iommu->reg,DMAR_FECTL_REG));
    printk("print_iommu_regs: DMAR_FEDATA_REG = %x\n",
           dmar_readl(iommu->reg,DMAR_FEDATA_REG));
    printk("print_iommu_regs: DMAR_FEADDR_REG = %x\n",
           dmar_readl(iommu->reg,DMAR_FEADDR_REG));
    printk("print_iommu_regs: DMAR_FEUADDR_REG = %x\n",
           dmar_readl(iommu->reg,DMAR_FEUADDR_REG));
}

u32 get_level_index(unsigned long gmfn, int level)
{
    while ( --level )
        gmfn = gmfn >> LEVEL_STRIDE;

    return gmfn & LEVEL_MASK;
}

void print_vtd_entries(struct iommu *iommu, int bus, int devfn, u64 gmfn)
{
    struct context_entry *ctxt_entry;
    struct root_entry *root_entry;
    struct dma_pte pte;
    u64 *l;
    u32 l_index, level;

    printk("print_vtd_entries: iommu = %p bdf = %x:%x:%x gmfn = %"PRIx64"\n",
           iommu, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), gmfn);

    if ( iommu->root_maddr == 0 )
    {
        printk("    iommu->root_maddr = 0\n");
        return;
    }

    root_entry = (struct root_entry *)map_vtd_domain_page(iommu->root_maddr);
 
    printk("    root_entry = %p\n", root_entry);
    printk("    root_entry[%x] = %"PRIx64"\n", bus, root_entry[bus].val);
    if ( !root_present(root_entry[bus]) )
    {
        unmap_vtd_domain_page(root_entry);
        printk("    root_entry[%x] not present\n", bus);
        return;
    }

    ctxt_entry =
        (struct context_entry *)map_vtd_domain_page(root_entry[bus].val);
    if ( ctxt_entry == NULL )
    {
        unmap_vtd_domain_page(root_entry);
        printk("    ctxt_entry == NULL\n");
        return;
    }

    printk("    context = %p\n", ctxt_entry);
    printk("    context[%x] = %"PRIx64"_%"PRIx64"\n",
           devfn, ctxt_entry[devfn].hi, ctxt_entry[devfn].lo);
    if ( !context_present(ctxt_entry[devfn]) )
    {
        unmap_vtd_domain_page(ctxt_entry);
        unmap_vtd_domain_page(root_entry);
        printk("    ctxt_entry[%x] not present\n", devfn);
        return;
    }

    level = agaw_to_level(context_address_width(ctxt_entry[devfn]));
    if ( level != VTD_PAGE_TABLE_LEVEL_3 &&
         level != VTD_PAGE_TABLE_LEVEL_4)
    {
        unmap_vtd_domain_page(ctxt_entry);
        unmap_vtd_domain_page(root_entry);
        printk("Unsupported VTD page table level (%d)!\n", level);
    }

    l = maddr_to_virt(ctxt_entry[devfn].lo);
    do
    {
        l = (u64*)(((unsigned long)l >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        printk("    l%d = %p\n", level, l);
        if ( l == NULL )
        {
            unmap_vtd_domain_page(ctxt_entry);
            unmap_vtd_domain_page(root_entry);
            printk("    l%d == NULL\n", level);
            break;
        }
        l_index = get_level_index(gmfn, level);
        printk("    l%d_index = %x\n", level, l_index);
        printk("    l%d[%x] = %"PRIx64"\n", level, l_index, l[l_index]);

        pte.val = l[l_index];
        if ( !dma_pte_present(pte) )
        {
            unmap_vtd_domain_page(ctxt_entry);
            unmap_vtd_domain_page(root_entry);
            printk("    l%d[%x] not present\n", level, l_index);
            break;
        }

        l = maddr_to_virt(l[l_index]);
    } while ( --level );
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
