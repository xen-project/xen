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

void print_vtd_entries(struct domain *d, int bus, int devfn,
                       unsigned long gmfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    struct context_entry *ctxt_entry;
    struct root_entry *root_entry;
    u64 *l4 = NULL, *l3, *l2, *l1;
    u32 l4_index = 0, l3_index, l2_index, l1_index;
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

        iommu = drhd->iommu;
        root_entry = iommu->root_entry;
        printk("    root_entry = %p\n", root_entry);
        if ( root_entry == NULL )
        {
            printk("    root_entry == NULL\n");
            continue;
        }

        printk("    root_entry[%x] = %"PRIx64"\n", bus, root_entry[bus].val);
        printk("    maddr_to_virt(root_entry[%x]) = %p\n",
               bus, maddr_to_virt(root_entry[bus].val));

        if ( root_entry[bus].val == 0 )
        {
            printk("    root_entry[%x].lo == 0\n", bus);
            continue;
        }

        ctxt_entry =
            maddr_to_virt((root_entry[bus].val >> PAGE_SHIFT) << PAGE_SHIFT);
        if ( ctxt_entry == NULL )
        {
            printk("    ctxt_entry == NULL\n");
            continue;
        }

        if ( ctxt_entry[devfn].lo == 0 )
        {
            printk("    ctxt_entry[%x].lo == 0\n", devfn);
            continue;
        }

        printk("    context = %p\n", ctxt_entry);
        printk("    context[%x] = %"PRIx64" %"PRIx64"\n",
               devfn, ctxt_entry[devfn].hi, ctxt_entry[devfn].lo);
        printk("    maddr_to_virt(context[%x].lo) = %p\n",
               devfn, maddr_to_virt(ctxt_entry[devfn].lo));
        printk("    context[%x] = %"PRIx64"\n", devfn, ctxt_entry[devfn].lo);

        switch ( level )
        {
        case VTD_PAGE_TABLE_LEVEL_3:
            l3 = maddr_to_virt(ctxt_entry[devfn].lo);
            l3 = (u64*)(((unsigned long)l3 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
            printk("    l3 = %p\n", l3);
            if ( l3 == NULL )
                continue;
            l3_index = get_level_index(gmfn, 3);
            printk("    l3_index = %x\n", l3_index);
            printk("    l3[%x] = %"PRIx64"\n", l3_index, l3[l3_index]);

            break;
        case VTD_PAGE_TABLE_LEVEL_4:
            l4 = maddr_to_virt(ctxt_entry[devfn].lo);
            l4 = (u64*)(((unsigned long)l4 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
            printk("    l4 = %p\n", l4);
            if ( l4 == NULL )
                continue;
            l4_index = get_level_index(gmfn, 4);
            printk("    l4_index = %x\n", l4_index);
            printk("    l4[%x] = %"PRIx64"\n", l4_index, l4[l4_index]);

            l3 = maddr_to_virt(l4[l4_index]);
            l3 = (u64*)(((unsigned long)l3 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
            printk("    l3 = %p\n", l3);
            if ( l3 == NULL )
                continue;
            l3_index = get_level_index(gmfn, 3);
            printk("    l3_index = %x\n", l3_index);
            printk("    l3[%x] = %"PRIx64"\n", l3_index, l3[l3_index]);

            break;
        default:
            printk("Unsupported VTD page table level (%d)!\n", level);
            continue;
        }

        l2 = maddr_to_virt(l3[l3_index]);
        l2 = (u64*)(((unsigned long)l2 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        printk("    l2 = %p\n", l2);
        if ( l2 == NULL )
            continue;
        l2_index = get_level_index(gmfn, 2);
        printk("    l2_index = %x\n", l2_index);
        printk("    l2[%x] = %"PRIx64"\n", l2_index, l2[l2_index]);

        l1 = maddr_to_virt(l2[l2_index]);
        l1 = (u64*)(((unsigned long)l1 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        printk("    l1 = %p\n", l1);
        if ( l1 == NULL )
            continue;
        l1_index = get_level_index(gmfn, 1);
        printk("    l1_index = %x\n", l1_index);
        printk("    l1[%x] = %"PRIx64"\n", l1_index, l1[l1_index]);
   }
}
