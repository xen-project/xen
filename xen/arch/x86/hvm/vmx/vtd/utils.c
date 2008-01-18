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

#include <xen/init.h>
#include <xen/bitmap.h>
#include <xen/irq.h>
#include <xen/spinlock.h>
#include <xen/sched.h>
#include <asm/delay.h>
#include <asm/iommu.h>
#include <asm/hvm/vmx/intel-iommu.h>
#include "dmar.h"
#include "pci-direct.h"
#include "pci_regs.h"
#include "msi.h"

#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/inttypes.h>

#define INTEL   0x8086
#define SEABURG 0x4000
#define C_STEP  2

int vtd_hw_check(void)
{
    u16 vendor, device;
    u8 revision, stepping;

    vendor   = read_pci_config_16(0, 0, 0, PCI_VENDOR_ID);
    device   = read_pci_config_16(0, 0, 0, PCI_DEVICE_ID);
    revision = read_pci_config_byte(0, 0, 0, PCI_REVISION_ID);
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
            vtd_enabled = 0;
            return -ENODEV;
        }
    }
    return 0;
}

/* Disable vt-d protected memory registers. */
void disable_pmr(struct iommu *iommu)
{
    unsigned long start_time;
    unsigned int val;

    val = dmar_readl(iommu->reg, DMAR_PMEN_REG);
    if ( !(val & DMA_PMEN_PRS) )
        return;

    dmar_writel(iommu->reg, DMAR_PMEN_REG, val & ~DMA_PMEN_EPM);
    start_time = jiffies;

    for ( ; ; )
    {
        val = dmar_readl(iommu->reg, DMAR_PMEN_REG);
        if ( (val & DMA_PMEN_PRS) == 0 )
            break;

        if ( time_after(jiffies, start_time + DMAR_OPERATION_TIMEOUT) )
            panic("Disable PMRs timeout\n");

        cpu_relax();
    }

    dprintk(XENLOG_INFO VTDPREFIX,
            "Disabled protected memory registers\n");
}


void print_iommu_regs(struct acpi_drhd_unit *drhd)
{
    struct iommu *iommu = drhd->iommu;

    printk("---- print_iommu_regs ----\n");
    printk("print_iommu_regs: drhd->address = %lx\n", drhd->address);
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

void print_vtd_entries(
    struct domain *d, 
    struct iommu *iommu,
    int bus, int devfn,
    unsigned long gmfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct acpi_drhd_unit *drhd;
    struct context_entry *ctxt_entry;
    struct root_entry *root_entry;
    struct dma_pte pte;
    u64 *l;
    u32 l_index;
    u32 i = 0;
    int level = agaw_to_level(hd->agaw);

    printk("print_vtd_entries: domain_id = %x bdf = %x:%x:%x gmfn = %lx\n",
           d->domain_id, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), gmfn);

    if ( hd->pgd == NULL )
    {
        printk("    hg->pgd == NULL\n");
        return;
    }
    printk("    d->pgd = %p virt_to_maddr(hd->pgd) = %lx\n",
           hd->pgd, virt_to_maddr(hd->pgd));

    for_each_drhd_unit ( drhd )
    {
        printk("---- print_vtd_entries %d ----\n", i++);

        root_entry = iommu->root_entry;
        if ( root_entry == NULL )
        {
            printk("    root_entry == NULL\n");
            continue;
        }

        printk("    root_entry = %p\n", root_entry);
        printk("    root_entry[%x] = %"PRIx64"\n", bus, root_entry[bus].val);
        if ( !root_present(root_entry[bus]) )
        {
            printk("    root_entry[%x] not present\n", bus);
            continue;
        }

        ctxt_entry =
            maddr_to_virt((root_entry[bus].val >> PAGE_SHIFT) << PAGE_SHIFT);
        if ( ctxt_entry == NULL )
        {
            printk("    ctxt_entry == NULL\n");
            continue;
        }

        printk("    context = %p\n", ctxt_entry);
        printk("    context[%x] = %"PRIx64" %"PRIx64"\n",
               devfn, ctxt_entry[devfn].hi, ctxt_entry[devfn].lo);
        if ( !context_present(ctxt_entry[devfn]) )
        {
            printk("    ctxt_entry[%x] not present\n", devfn);
            continue;
        }

        if ( level != VTD_PAGE_TABLE_LEVEL_3 &&
             level != VTD_PAGE_TABLE_LEVEL_4)
        {
            printk("Unsupported VTD page table level (%d)!\n", level);
            continue;
        }

        l = maddr_to_virt(ctxt_entry[devfn].lo);
        do
        {
            l = (u64*)(((unsigned long)l >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
            printk("    l%d = %p\n", level, l);
            if ( l == NULL )
            {
                printk("    l%d == NULL\n", level);
                break;
            }
            l_index = get_level_index(gmfn, level);
            printk("    l%d_index = %x\n", level, l_index);
            printk("    l%d[%x] = %"PRIx64"\n", level, l_index, l[l_index]);

            pte.val = l[l_index];
            if ( !dma_pte_present(pte) )
            {
                printk("    l%d[%x] not present\n", level, l_index);
                break;
            }

            l = maddr_to_virt(l[l_index]);
        } while ( --level );
    }
}
