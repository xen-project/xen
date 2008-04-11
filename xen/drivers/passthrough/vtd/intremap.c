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
 * Copyright (C) Xiaohui Xin <xiaohui.xin@intel.com>
 */

#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/time.h>
#include <xen/pci.h>
#include "iommu.h"
#include "dmar.h"
#include "vtd.h"
#include "../pci_regs.h"
#include "msi.h"
#include "extern.h"

u16 apicid_to_bdf(int apic_id)
{
    struct acpi_drhd_unit *drhd = ioapic_to_drhd(apic_id);
    struct acpi_ioapic_unit *acpi_ioapic_unit;

    list_for_each_entry ( acpi_ioapic_unit, &drhd->ioapic_list, list )
        if ( acpi_ioapic_unit->apic_id == apic_id )
            return acpi_ioapic_unit->ioapic.info;

    dprintk(XENLOG_ERR VTDPREFIX, "Didn't find the bdf for the apic_id!\n");
    return 0;
}

static void remap_entry_to_ioapic_rte(
    struct iommu *iommu, struct IO_APIC_route_entry *old_rte)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct IO_APIC_route_remap_entry *remap_rte;
    unsigned int index;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( ir_ctrl == NULL )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "remap_entry_to_ioapic_rte: ir_ctl == NULL");
        return;
    }

    remap_rte = (struct IO_APIC_route_remap_entry *) old_rte;
    index = (remap_rte->index_15 << 15) + remap_rte->index_0_14;

    if ( index > ir_ctrl->iremap_index )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
            "Index is larger than remap table entry size. Error!\n");
        return;
    }

    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    iremap_entries =
        (struct iremap_entry *)map_vtd_domain_page(ir_ctrl->iremap_maddr);
    iremap_entry = &iremap_entries[index];

    old_rte->vector = iremap_entry->lo.vector;
    old_rte->delivery_mode = iremap_entry->lo.dlm;
    old_rte->dest_mode = iremap_entry->lo.dm;
    old_rte->trigger = iremap_entry->lo.tm;
    old_rte->__reserved_2 = 0;
    old_rte->dest.logical.__reserved_1 = 0;
    old_rte->dest.logical.logical_dest = iremap_entry->lo.dst;

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
}

static void ioapic_rte_to_remap_entry(struct iommu *iommu,
    int apic_id, struct IO_APIC_route_entry *old_rte)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct IO_APIC_route_remap_entry *remap_rte;
    unsigned int index;
    unsigned long flags;
    int ret = 0;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    remap_rte = (struct IO_APIC_route_remap_entry *) old_rte;
    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);
    index = ir_ctrl->iremap_index;
    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
               "The interrupt number is more than 256!\n");
        goto out;
    }

    iremap_entries =
        (struct iremap_entry *)map_vtd_domain_page(ir_ctrl->iremap_maddr);
    iremap_entry = &iremap_entries[index];

    if ( *(u64 *)iremap_entry != 0 )
        dprintk(XENLOG_WARNING VTDPREFIX,
               "Interrupt remapping entry is in use already!\n");
    iremap_entry->lo.fpd = 0;
    iremap_entry->lo.dm = old_rte->dest_mode;
    iremap_entry->lo.rh = 0;
    iremap_entry->lo.tm = old_rte->trigger;
    iremap_entry->lo.dlm = old_rte->delivery_mode;
    iremap_entry->lo.avail = 0;
    iremap_entry->lo.res_1 = 0;
    iremap_entry->lo.vector = old_rte->vector;
    iremap_entry->lo.res_2 = 0;
    iremap_entry->lo.dst = (old_rte->dest.logical.logical_dest << 8);
    iremap_entry->hi.sid = apicid_to_bdf(apic_id);
    iremap_entry->hi.sq = 0;    /* comparing all 16-bit of SID */
    iremap_entry->hi.svt = 1;   /* turn on requestor ID verification SID/SQ */
    iremap_entry->hi.res_1 = 0;
    iremap_entry->lo.p = 1;    /* finally, set present bit */
    ir_ctrl->iremap_index++;

    unmap_vtd_domain_page(iremap_entries);
    iommu_flush_iec_index(iommu, 0, index);
    ret = invalidate_sync(iommu);

    /* now construct new ioapic rte entry */
    remap_rte->vector = old_rte->vector;
    remap_rte->delivery_mode = 0;    /* has to be 0 for remap format */
    remap_rte->index_15 = index & 0x8000;
    remap_rte->index_0_14 = index & 0x7fff;
    remap_rte->delivery_status = old_rte->delivery_status;
    remap_rte->polarity = old_rte->polarity;
    remap_rte->irr = old_rte->irr;
    remap_rte->trigger = old_rte->trigger;
    remap_rte->mask = 1;
    remap_rte->reserved = 0;
    remap_rte->format = 1;    /* indicate remap format */
out:
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return;
}

unsigned int
io_apic_read_remap_rte(
    unsigned int apic, unsigned int reg)
{
    struct IO_APIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_remap_entry *remap_rte;
    int rte_upper = (reg & 1) ? 1 : 0;
    struct iommu *iommu = ioapic_to_iommu(mp_ioapics[apic].mpc_apicid);
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( !iommu || !ir_ctrl || ir_ctrl->iremap_maddr == 0 )
    {
        *IO_APIC_BASE(apic) = reg;
        return *(IO_APIC_BASE(apic)+4);
    }

    if ( rte_upper )
        reg--;

    /* read lower and upper 32-bits of rte entry */
    *IO_APIC_BASE(apic) = reg;
    *(((u32 *)&old_rte) + 0) = *(IO_APIC_BASE(apic)+4);
    *IO_APIC_BASE(apic) = reg + 1;
    *(((u32 *)&old_rte) + 1) = *(IO_APIC_BASE(apic)+4);

    remap_rte = (struct IO_APIC_route_remap_entry *) &old_rte;

    if ( remap_rte->mask || (remap_rte->format == 0) )
    {
        *IO_APIC_BASE(apic) = reg;
        return *(IO_APIC_BASE(apic)+4);
    }

    remap_entry_to_ioapic_rte(iommu, &old_rte);
    if ( rte_upper )
    {
        *IO_APIC_BASE(apic) = reg + 1;
        return (*(((u32 *)&old_rte) + 1));
    }
    else
    {
        *IO_APIC_BASE(apic) = reg;
        return (*(((u32 *)&old_rte) + 0));
    }
}

void
io_apic_write_remap_rte(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    struct IO_APIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_remap_entry *remap_rte;
    int rte_upper = (reg & 1) ? 1 : 0;
    struct iommu *iommu = ioapic_to_iommu(mp_ioapics[apic].mpc_apicid);
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( !iommu || !ir_ctrl || ir_ctrl->iremap_maddr == 0 )
    {
        *IO_APIC_BASE(apic) = reg;
        *(IO_APIC_BASE(apic)+4) = value;
        return;
    }

    if ( rte_upper )
        reg--;

    /* read both lower and upper 32-bits of rte entry */
    *IO_APIC_BASE(apic) = reg;
    *(((u32 *)&old_rte) + 0) = *(IO_APIC_BASE(apic)+4);
    *IO_APIC_BASE(apic) = reg + 1;
    *(((u32 *)&old_rte) + 1) = *(IO_APIC_BASE(apic)+4);

    remap_rte = (struct IO_APIC_route_remap_entry *) &old_rte;
    if ( remap_rte->mask || (remap_rte->format == 0) )
    {
        *IO_APIC_BASE(apic) = rte_upper ? ++reg : reg;
        *(IO_APIC_BASE(apic)+4) = value;
        return;
    }

    *(((u32 *)&old_rte) + rte_upper) = value;
    ioapic_rte_to_remap_entry(iommu, mp_ioapics[apic].mpc_apicid, &old_rte);

    /* write new entry to ioapic */
    *IO_APIC_BASE(apic) = reg;
    *(IO_APIC_BASE(apic)+4) = *(((int *)&old_rte)+0);
    *IO_APIC_BASE(apic) = reg + 1;
    *(IO_APIC_BASE(apic)+4) = *(((int *)&old_rte)+1);
}

int intremap_setup(struct iommu *iommu)
{
    struct ir_ctrl *ir_ctrl;
    s_time_t start_time;

    if ( !ecap_intr_remap(iommu->ecap) )
        return -ENODEV;

    ir_ctrl = iommu_ir_ctrl(iommu);
    if ( ir_ctrl->iremap_maddr == 0 )
    {
        ir_ctrl->iremap_maddr = alloc_pgtable_maddr();
        if ( ir_ctrl->iremap_maddr == 0 )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Cannot allocate memory for ir_ctrl->iremap_maddr\n");
            return -ENODEV;
        }
    }

#if defined(ENABLED_EXTENDED_INTERRUPT_SUPPORT)
    /* set extended interrupt mode bit */
    ir_ctrl->iremap_maddr |=
            ecap_ext_intr(iommu->ecap) ? (1 << IRTA_REG_EIMI_SHIFT) : 0;
#endif
    /* size field = 256 entries per 4K page = 8 - 1 */
    ir_ctrl->iremap_maddr |= 7;
    dmar_writeq(iommu->reg, DMAR_IRTA_REG, ir_ctrl->iremap_maddr);

    /* set SIRTP */
    iommu->gcmd |= DMA_GCMD_SIRTP;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);

    /* Make sure hardware complete it */
    start_time = NOW();
    while ( !(dmar_readl(iommu->reg, DMAR_GSTS_REG) & DMA_GSTS_SIRTPS) )
    {
        if ( NOW() > (start_time + DMAR_OPERATION_TIMEOUT) )
        {
            dprintk(XENLOG_ERR VTDPREFIX,
                    "Cannot set SIRTP field for interrupt remapping\n");
            return -ENODEV;
        }
        cpu_relax();
    }

    /* enable comaptiblity format interrupt pass through */
    iommu->gcmd |= DMA_GCMD_CFI;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);

    start_time = NOW();
    while ( !(dmar_readl(iommu->reg, DMAR_GSTS_REG) & DMA_GSTS_CFIS) )
    {
        if ( NOW() > (start_time + DMAR_OPERATION_TIMEOUT) )
        {
            dprintk(XENLOG_ERR VTDPREFIX,
                    "Cannot set CFI field for interrupt remapping\n");
            return -ENODEV;
        }
        cpu_relax();
    }

    /* enable interrupt remapping hardware */
    iommu->gcmd |= DMA_GCMD_IRE;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);

    start_time = NOW();
    while ( !(dmar_readl(iommu->reg, DMAR_GSTS_REG) & DMA_GSTS_IRES) )
    {
        if ( NOW() > (start_time + DMAR_OPERATION_TIMEOUT) ) 
        {
            dprintk(XENLOG_ERR VTDPREFIX,
                    "Cannot set IRE field for interrupt remapping\n");
            return -ENODEV;
        }
        cpu_relax();
    }

    /* After set SIRTP, we should do globally invalidate the IEC */
    iommu_flush_iec_global(iommu);

    return 0;
}
