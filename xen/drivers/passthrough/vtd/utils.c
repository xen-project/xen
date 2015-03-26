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
#include "iommu.h"
#include "dmar.h"
#include "vtd.h"
#include "extern.h"
#include <asm/io_apic.h>

int is_usb_device(u16 seg, u8 bus, u8 devfn)
{
    u16 class = pci_conf_read16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                                PCI_CLASS_DEVICE);
    return (class == 0xc03);
}

/* Disable vt-d protected memory registers. */
void disable_pmr(struct iommu *iommu)
{
    u32 val;
    unsigned long flags;

    val = dmar_readl(iommu->reg, DMAR_PMEN_REG);
    if ( !(val & DMA_PMEN_PRS) )
        return;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writel(iommu->reg, DMAR_PMEN_REG, val & ~DMA_PMEN_EPM);

    IOMMU_WAIT_OP(iommu, DMAR_PMEN_REG, dmar_readl,
                  !(val & DMA_PMEN_PRS), val);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    dprintk(XENLOG_INFO VTDPREFIX,
            "Disabled protected memory registers\n");
}

void print_iommu_regs(struct acpi_drhd_unit *drhd)
{
    struct iommu *iommu = drhd->iommu;
    u64 cap;

    printk("---- print_iommu_regs ----\n");
    printk(" drhd->address = %"PRIx64"\n", drhd->address);
    printk(" VER = %x\n", dmar_readl(iommu->reg, DMAR_VER_REG));
    printk(" CAP = %"PRIx64"\n", cap = dmar_readq(iommu->reg, DMAR_CAP_REG));
    printk(" n_fault_reg = %"PRIx64"\n", cap_num_fault_regs(cap));
    printk(" fault_recording_offset = %"PRIx64"\n", cap_fault_reg_offset(cap));
    if ( cap_fault_reg_offset(cap) < PAGE_SIZE )
    {
        printk(" fault_recording_reg_l = %"PRIx64"\n",
               dmar_readq(iommu->reg, cap_fault_reg_offset(cap)));
        printk(" fault_recording_reg_h = %"PRIx64"\n",
               dmar_readq(iommu->reg, cap_fault_reg_offset(cap) + 8));
    }
    printk(" ECAP = %"PRIx64"\n", dmar_readq(iommu->reg, DMAR_ECAP_REG));
    printk(" GCMD = %x\n", dmar_readl(iommu->reg, DMAR_GCMD_REG));
    printk(" GSTS = %x\n", dmar_readl(iommu->reg, DMAR_GSTS_REG));
    printk(" RTADDR = %"PRIx64"\n", dmar_readq(iommu->reg,DMAR_RTADDR_REG));
    printk(" CCMD = %"PRIx64"\n", dmar_readq(iommu->reg, DMAR_CCMD_REG));
    printk(" FSTS = %x\n", dmar_readl(iommu->reg, DMAR_FSTS_REG));
    printk(" FECTL = %x\n", dmar_readl(iommu->reg, DMAR_FECTL_REG));
    printk(" FEDATA = %x\n", dmar_readl(iommu->reg, DMAR_FEDATA_REG));
    printk(" FEADDR = %x\n", dmar_readl(iommu->reg, DMAR_FEADDR_REG));
    printk(" FEUADDR = %x\n", dmar_readl(iommu->reg, DMAR_FEUADDR_REG));
}

static u32 get_level_index(unsigned long gmfn, int level)
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
    u64 *l, val;
    u32 l_index, level;

    printk("print_vtd_entries: iommu %p dev %04x:%02x:%02x.%u gmfn %"PRIx64"\n",
           iommu, iommu->intel->drhd->segment, bus,
           PCI_SLOT(devfn), PCI_FUNC(devfn), gmfn);

    if ( iommu->root_maddr == 0 )
    {
        printk("    iommu->root_maddr = 0\n");
        return;
    }

    root_entry = (struct root_entry *)map_vtd_domain_page(iommu->root_maddr);
    if ( root_entry == NULL )
    {
        printk("    root_entry == NULL\n");
        return;
    }

    printk("    root_entry = %p\n", root_entry);
    printk("    root_entry[%x] = %"PRIx64"\n", bus, root_entry[bus].val);
    if ( !root_present(root_entry[bus]) )
    {
        unmap_vtd_domain_page(root_entry);
        printk("    root_entry[%x] not present\n", bus);
        return;
    }

    val = root_entry[bus].val;
    unmap_vtd_domain_page(root_entry);
    ctxt_entry = map_vtd_domain_page(val);
    if ( ctxt_entry == NULL )
    {
        printk("    ctxt_entry == NULL\n");
        return;
    }

    printk("    context = %p\n", ctxt_entry);
    val = ctxt_entry[devfn].lo;
    printk("    context[%x] = %"PRIx64"_%"PRIx64"\n",
           devfn, ctxt_entry[devfn].hi, val);
    if ( !context_present(ctxt_entry[devfn]) )
    {
        unmap_vtd_domain_page(ctxt_entry);
        printk("    ctxt_entry[%x] not present\n", devfn);
        return;
    }

    level = agaw_to_level(context_address_width(ctxt_entry[devfn]));
    unmap_vtd_domain_page(ctxt_entry);
    if ( level != VTD_PAGE_TABLE_LEVEL_3 &&
         level != VTD_PAGE_TABLE_LEVEL_4)
    {
        printk("Unsupported VTD page table level (%d)!\n", level);
        return;
    }

    do
    {
        l = map_vtd_domain_page(val);
        printk("    l%d = %p\n", level, l);
        if ( l == NULL )
        {
            printk("    l%d == NULL\n", level);
            break;
        }
        l_index = get_level_index(gmfn, level);
        printk("    l%d_index = %x\n", level, l_index);

        pte.val = l[l_index];
        unmap_vtd_domain_page(l);
        printk("    l%d[%x] = %"PRIx64"\n", level, l_index, pte.val);

        if ( !dma_pte_present(pte) )
        {
            printk("    l%d[%x] not present\n", level, l_index);
            break;
        }
        if ( dma_pte_superpage(pte) )
            break;
        val = dma_pte_addr(pte);
    } while ( --level );
}

static void dump_iommu_info(unsigned char key)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    int i;

    for_each_drhd_unit ( drhd )
    {
        u32 status = 0;

        iommu = drhd->iommu;
        printk("\niommu %x: nr_pt_levels = %x.\n", iommu->index,
            iommu->nr_pt_levels);

        if ( ecap_queued_inval(iommu->ecap) ||  ecap_intr_remap(iommu->ecap) )
            status = dmar_readl(iommu->reg, DMAR_GSTS_REG);

        printk("  Queued Invalidation: %ssupported%s.\n",
            ecap_queued_inval(iommu->ecap) ? "" : "not ",
           (status & DMA_GSTS_QIES) ? " and enabled" : "" );


        printk("  Interrupt Remapping: %ssupported%s.\n",
            ecap_intr_remap(iommu->ecap) ? "" : "not ",
            (status & DMA_GSTS_IRES) ? " and enabled" : "" );

        if ( status & DMA_GSTS_IRES )
        {
            /* Dump interrupt remapping table. */
            u64 iremap_maddr = dmar_readq(iommu->reg, DMAR_IRTA_REG);
            int nr_entry = 1 << ((iremap_maddr & 0xF) + 1);
            struct iremap_entry *iremap_entries = NULL;
            int print_cnt = 0;

            printk("  Interrupt remapping table (nr_entry=%#x. "
                "Only dump P=1 entries here):\n", nr_entry);
            printk("       SVT  SQ   SID      DST  V  AVL DLM TM RH DM "
                   "FPD P\n");
            for ( i = 0; i < nr_entry; i++ )
            {
                struct iremap_entry *p;
                if ( i % (1 << IREMAP_ENTRY_ORDER) == 0 )
                {
                    /* This entry across page boundry */
                    if ( iremap_entries )
                        unmap_vtd_domain_page(iremap_entries);

                    GET_IREMAP_ENTRY(iremap_maddr, i,
                                     iremap_entries, p);
                }
                else
                    p = &iremap_entries[i % (1 << IREMAP_ENTRY_ORDER)];

                if ( !p->lo.p )
                    continue;
                printk("  %04x:  %x   %x  %04x %08x %02x    %x   %x  %x  %x  %x"
                    "   %x %x\n", i,
                    (u32)p->hi.svt, (u32)p->hi.sq, (u32)p->hi.sid,
                    (u32)p->lo.dst, (u32)p->lo.vector, (u32)p->lo.avail,
                    (u32)p->lo.dlm, (u32)p->lo.tm, (u32)p->lo.rh,
                    (u32)p->lo.dm, (u32)p->lo.fpd, (u32)p->lo.p);
                print_cnt++;
            }
            if ( iremap_entries )
                unmap_vtd_domain_page(iremap_entries);
            if ( iommu_ir_ctrl(iommu)->iremap_num != print_cnt )
                printk("Warning: Print %d IRTE (actually have %d)!\n",
                        print_cnt, iommu_ir_ctrl(iommu)->iremap_num);

        }
    }

    /* Dump the I/O xAPIC redirection table(s). */
    if ( iommu_enabled )
    {
        int apic;
        union IO_APIC_reg_01 reg_01;
        struct IO_APIC_route_remap_entry *remap;
        struct ir_ctrl *ir_ctrl;

        for ( apic = 0; apic < nr_ioapics; apic++ )
        {
            iommu = ioapic_to_iommu(mp_ioapics[apic].mpc_apicid);
            ir_ctrl = iommu_ir_ctrl(iommu);
            if ( !ir_ctrl || !ir_ctrl->iremap_maddr || !ir_ctrl->iremap_num )
                continue;

            printk( "\nRedirection table of IOAPIC %x:\n", apic);

            /* IO xAPIC Version Register. */
            reg_01.raw = __io_apic_read(apic, 1);

            printk("  #entry IDX FMT MASK TRIG IRR POL STAT DELI  VECTOR\n");
            for ( i = 0; i <= reg_01.bits.entries; i++ )
            {
                struct IO_APIC_route_entry rte =
                    __ioapic_read_entry(apic, i, TRUE);

                remap = (struct IO_APIC_route_remap_entry *) &rte;
                if ( !remap->format )
                    continue;

                printk("   %02x:  %04x   %x    %x   %x   %x   %x    %x"
                    "    %x     %02x\n", i,
                    (u32)remap->index_0_14 | ((u32)remap->index_15 << 15),
                    (u32)remap->format, (u32)remap->mask, (u32)remap->trigger,
                    (u32)remap->irr, (u32)remap->polarity,
                    (u32)remap->delivery_status, (u32)remap->delivery_mode,
                    (u32)remap->vector);
            }
        }
    }
}

struct keyhandler dump_iommu_info_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_iommu_info,
    .desc = "dump iommu info"
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
