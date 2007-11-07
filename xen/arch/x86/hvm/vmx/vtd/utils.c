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

#define VTDPREFIX "[VT-D]" 
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

#if defined(__x86_64__)
void print_iommu_regs(struct acpi_drhd_unit *drhd)
{
    struct iommu *iommu = drhd->iommu;
 
    printk("---- print_iommu_regs ----\n"); 
    printk("print_iommu_regs: drhd->address = %lx\n", drhd->address);
    printk("print_iommu_regs: DMAR_VER_REG = %x\n",
                   dmar_readl(iommu->reg,DMAR_VER_REG));
    printk("print_iommu_regs: DMAR_CAP_REG = %lx\n",
                   dmar_readq(iommu->reg,DMAR_CAP_REG));
    printk("print_iommu_regs: n_fault_reg = %lx\n",
                   cap_num_fault_regs(dmar_readq(iommu->reg, DMAR_CAP_REG)));
    printk("print_iommu_regs: fault_recording_offset_l = %lx\n",
                   cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)));
    printk("print_iommu_regs: fault_recording_offset_h = %lx\n",
                   cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)) + 8);
    printk("print_iommu_regs: fault_recording_reg_l = %lx\n",
        dmar_readq(iommu->reg, cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG))));
    printk("print_iommu_regs: fault_recording_reg_h = %lx\n",
        dmar_readq(iommu->reg, cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)) + 8));
    printk("print_iommu_regs: DMAR_ECAP_REG = %lx\n",
                   dmar_readq(iommu->reg,DMAR_ECAP_REG));
    printk("print_iommu_regs: DMAR_GCMD_REG = %x\n",
                   dmar_readl(iommu->reg,DMAR_GCMD_REG));
    printk("print_iommu_regs: DMAR_GSTS_REG = %x\n",
                   dmar_readl(iommu->reg,DMAR_GSTS_REG));
    printk("print_iommu_regs: DMAR_RTADDR_REG = %lx\n",
                   dmar_readq(iommu->reg,DMAR_RTADDR_REG));
    printk("print_iommu_regs: DMAR_CCMD_REG = %lx\n",
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

void print_vtd_entries(struct domain *d, int bus, int devfn,
                       unsigned long gmfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    struct context_entry *ctxt_entry;
    struct root_entry *root_entry;
    u64 *l3, *l2, *l1;
    u32 l3_index, l2_index, l1_index;
    u32 i = 0;

    printk("print_vtd_entries: domain_id = %x bdf = %x:%x:%x devfn = %x, gmfn = %lx\n", d->domain_id, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), devfn, gmfn);

    for_each_drhd_unit(drhd) {
        printk("---- print_vtd_entries %d ----\n", i++);

        if (hd->pgd == NULL) {
            printk("    hg->pgd == NULL\n");
            return;
        }

        iommu = drhd->iommu;
        root_entry = iommu->root_entry;
        printk("    hd->pgd = %p virt_to_maddr(hd->pgd) = %lx\n",
               hd->pgd, virt_to_maddr(hd->pgd));

        printk("    root_entry = %p\n", root_entry);
        if (root_entry == NULL) {
            printk("    root_entry == NULL\n");
            return;
        }

        printk("    root_entry[%x] = %lx\n", bus, root_entry[bus].val);
        printk("    maddr_to_virt(root_entry[%x]) = %p\n",
            bus, maddr_to_virt(root_entry[bus].val));

        if (root_entry[bus].val == 0) {
            printk("    root_entry[%x].lo == 0\n", bus);
            return;
        }
 
        ctxt_entry = maddr_to_virt((root_entry[bus].val >> PAGE_SHIFT) << PAGE_SHIFT);
        if (ctxt_entry == NULL) {
            printk("    ctxt_entry == NULL\n");
            return;
        }

        if (ctxt_entry[devfn].lo == 0) {
            printk("    ctxt_entry[%x].lo == 0\n", devfn);
            return;
        }

        printk("    context = %p\n", ctxt_entry);
        printk("    context[%x] = %lx %lx\n",
               devfn, ctxt_entry[devfn].hi, ctxt_entry[devfn].lo);
        printk("    maddr_to_virt(context[%x].lo) = %p\n",
               devfn, maddr_to_virt(ctxt_entry[devfn].lo));
        printk("    context[%x] = %lx\n", devfn, ctxt_entry[devfn].lo); 

        l3 = maddr_to_virt(ctxt_entry[devfn].lo);
        l3 = (u64*)(((u64) l3 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        printk("    l3 = %p\n", l3); 
        if (l3 == NULL) return;

        l3_index = (gmfn >> 9 >> 9) & 0x1ff;
        printk("    l3_index = %x\n", l3_index);
        printk("    l3[%x] = %lx\n", l3_index, l3[l3_index]);

        l2 = maddr_to_virt(l3[l3_index]);
        l2 = (u64*)(((u64) l2 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        printk("    l2 = %p\n", l2); 
        if (l2 == NULL) return;

        l2_index = (gmfn >> 9) & 0x1ff;
        printk("    gmfn = %lx\n", gmfn);
        printk("    gmfn >> 9= %lx\n", gmfn >> 9);
        printk("    l2_index = %x\n", l2_index);
        printk("    l2[%x] = %lx\n", l2_index, l2[l2_index]);

        l1 = maddr_to_virt(l2[l2_index]);
        l1 = (u64*)(((u64) l1 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        if (l1 == NULL) return;
        l1_index = gmfn & 0x1ff;
        printk("    l1 = %p\n", l1); 
        printk("    l1_index = %x\n", l1_index);
        printk("    l1[%x] = %lx\n", l1_index, l1[l1_index]); 
    }
}

#else    // !m64

void print_iommu_regs(struct acpi_drhd_unit *drhd)
{
    struct iommu *iommu = drhd->iommu;
 
    printk("---- print_iommu_regs ----\n"); 
    printk("print_iommu_regs: drhd->address = %lx\n", drhd->address);
    printk("print_iommu_regs: DMAR_VER_REG = %x\n",
                   dmar_readl(iommu->reg,DMAR_VER_REG));
    printk("print_iommu_regs: DMAR_CAP_REG = %llx\n",
                   dmar_readq(iommu->reg,DMAR_CAP_REG));
    printk("print_iommu_regs: n_fault_reg = %llx\n",
                   cap_num_fault_regs(dmar_readq(iommu->reg, DMAR_CAP_REG)));
    printk("print_iommu_regs: fault_recording_offset_l = %llx\n",
                   cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)));
    printk("print_iommu_regs: fault_recording_offset_h = %llx\n",
                   cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)) + 8);
    printk("print_iommu_regs: fault_recording_reg_l = %llx\n",
        dmar_readq(iommu->reg, cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG))));
    printk("print_iommu_regs: fault_recording_reg_h = %llx\n",
        dmar_readq(iommu->reg, cap_fault_reg_offset(dmar_readq(iommu->reg, DMAR_CAP_REG)) + 8));
    printk("print_iommu_regs: DMAR_ECAP_REG = %llx\n",
                   dmar_readq(iommu->reg,DMAR_ECAP_REG));
    printk("print_iommu_regs: DMAR_GCMD_REG = %x\n",
                   dmar_readl(iommu->reg,DMAR_GCMD_REG));
    printk("print_iommu_regs: DMAR_GSTS_REG = %x\n",
                   dmar_readl(iommu->reg,DMAR_GSTS_REG));
    printk("print_iommu_regs: DMAR_RTADDR_REG = %llx\n",
                   dmar_readq(iommu->reg,DMAR_RTADDR_REG));
    printk("print_iommu_regs: DMAR_CCMD_REG = %llx\n",
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

void print_vtd_entries(struct domain *d, int bus, int devfn,
                       unsigned long gmfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    struct context_entry *ctxt_entry;
    struct root_entry *root_entry;
    u64 *l3, *l2, *l1;
    u32 l3_index, l2_index, l1_index;
    u32 i = 0;

    printk("print_vtd_entries: domain_id = %x bdf = %x:%x:%x devfn = %x, gmfn = %lx\n", d->domain_id, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), devfn, gmfn);

    for_each_drhd_unit(drhd) {
        printk("---- print_vtd_entries %d ----\n", i++);

        if (hd->pgd == NULL) {
            printk("    hg->pgd == NULL\n");
            return;
        }

        iommu = drhd->iommu;
        root_entry = iommu->root_entry;
        printk("    d->pgd = %p virt_to_maddr(hd->pgd) = %lx\n",
               hd->pgd, virt_to_maddr(hd->pgd));

        printk("    root_entry = %p\n", root_entry);
        if (root_entry == NULL) {
            printk("    root_entry == NULL\n");
            return;
        }

        printk("    root_entry[%x] = %llx\n", bus, root_entry[bus].val);
        printk("    maddr_to_virt(root_entry[%x]) = %p\n",
            bus, maddr_to_virt(root_entry[bus].val));

        if (root_entry[bus].val == 0) {
            printk("    root_entry[%x].lo == 0\n", bus);
            return;
        }
 
        ctxt_entry = maddr_to_virt((root_entry[bus].val >> PAGE_SHIFT) << PAGE_SHIFT);
        if (ctxt_entry == NULL) {
            printk("    ctxt_entry == NULL\n");
            return;
        }

        if (ctxt_entry[devfn].lo == 0) {
            printk("    ctxt_entry[%x].lo == 0\n", devfn);
            return;
        }

        printk("    context = %p\n", ctxt_entry);
        printk("    context[%x] = %llx %llx\n",
               devfn, ctxt_entry[devfn].hi, ctxt_entry[devfn].lo);
        printk("    maddr_to_virt(context[%x].lo) = %p\n",
               devfn, maddr_to_virt(ctxt_entry[devfn].lo));
        printk("    context[%x] = %llx\n", devfn, ctxt_entry[devfn].lo); 

        l3 = maddr_to_virt(ctxt_entry[devfn].lo);
        l3 = (u64*)(((u32) l3 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        printk("    l3 = %p\n", l3); 
        if (l3 == NULL) return;

        l3_index = (gmfn >> 9 >> 9) & 0x1ff;
        printk("    l3_index = %x\n", l3_index);
        printk("    l3[%x] = %llx\n", l3_index, l3[l3_index]);

        l2 = maddr_to_virt(l3[l3_index]);
        l2 = (u64*)(((u32) l2 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        printk("    l2 = %p\n", l2); 
        if (l2 == NULL) return;

        l2_index = (gmfn >> 9) & 0x1ff;
        printk("    gmfn = %lx\n", gmfn);
        printk("    gmfn >> 9= %lx\n", gmfn >> 9);
        printk("    l2_index = %x\n", l2_index);
        printk("    l2[%x] = %llx\n", l2_index, l2[l2_index]);

        l1 = maddr_to_virt(l2[l2_index]);
        l1 = (u64*)(((u32) l1 >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K);
        if (l1 == NULL) return;
        l1_index = gmfn & 0x1ff;
        printk("    l1 = %p\n", l1); 
        printk("    l1_index = %x\n", l1_index);
        printk("    l1[%x] = %llx\n", l1_index, l1[l1_index]); 
    }
}
#endif    // !m64
