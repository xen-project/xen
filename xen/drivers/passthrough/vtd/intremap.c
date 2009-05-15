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
#include <asm/hvm/iommu.h>
#include <xen/time.h>
#include <xen/list.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include "iommu.h"
#include "dmar.h"
#include "vtd.h"
#include "extern.h"

#ifndef dest_SMI
#define dest_SMI -1
#endif

/* The max number of IOAPIC (or IOSAPIC) pin. The typical values can be 24 or
 * 48 on x86 and Itanium platforms. Here we use a biger number 256. This
 * should be big enough. Actually now IREMAP_ENTRY_NR is also 256.
 */
#define MAX_IOAPIC_PIN_NUM  256

struct ioapicid_pin_intremap_index {
	struct list_head list;
	unsigned int ioapic_id;
	unsigned int pin;
	int intremap_index;
};

static struct list_head ioapic_pin_to_intremap_index[MAX_IOAPIC_PIN_NUM];

static int init_ioapic_pin_intremap_index(void)
{
    static int initialized = 0;
    int i;

    if ( initialized == 1 )
        return 0;

    for ( i = 0; i < MAX_IOAPIC_PIN_NUM; i++ )
        INIT_LIST_HEAD(&ioapic_pin_to_intremap_index[i]);

    initialized = 1;
    return 0;
}

static int get_ioapic_pin_intremap_index(unsigned int ioapic_id,
                                         unsigned int pin)
{
    struct ioapicid_pin_intremap_index *entry;
    struct list_head *pos, *tmp;

    list_for_each_safe ( pos, tmp, &ioapic_pin_to_intremap_index[pin] )
    {
        entry = list_entry(pos, struct ioapicid_pin_intremap_index, list);
        if ( entry->ioapic_id == ioapic_id )
            return entry->intremap_index;
    }

    return -1;
}

static int set_ioapic_pin_intremap_index(unsigned int ioapic_id,
                                         unsigned int pin,
                                         int index)
{
    struct ioapicid_pin_intremap_index *entry;

    entry = xmalloc(struct ioapicid_pin_intremap_index);
    if ( !entry )
        return -ENOMEM;

    entry->ioapic_id = ioapic_id;
    entry->pin = pin;
    entry->intremap_index = index;

    list_add_tail(&entry->list, &ioapic_pin_to_intremap_index[pin]);

    return 0;
}

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

static int remap_entry_to_ioapic_rte(
    struct iommu *iommu, struct IO_xAPIC_route_entry *old_rte)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct IO_APIC_route_remap_entry *remap_rte;
    int index = 0;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( ir_ctrl == NULL )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "remap_entry_to_ioapic_rte: ir_ctl is not ready\n");
        return -EFAULT;
    }

    remap_rte = (struct IO_APIC_route_remap_entry *) old_rte;
    index = (remap_rte->index_15 << 15) | remap_rte->index_0_14;

    if ( index > ir_ctrl->iremap_index )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) is larger than remap table entry size (%d)!\n",
                __func__, index, ir_ctrl->iremap_index);
        return -EFAULT;
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
    old_rte->dest.logical.logical_dest = iremap_entry->lo.dst >> 8;

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

static int ioapic_rte_to_remap_entry(struct iommu *iommu,
    int apic_id, unsigned int ioapic_pin, struct IO_xAPIC_route_entry *old_rte,
    unsigned int rte_upper, unsigned int value)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct iremap_entry new_ire;
    struct IO_APIC_route_remap_entry *remap_rte;
    struct IO_xAPIC_route_entry new_rte;
    int index;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    remap_rte = (struct IO_APIC_route_remap_entry *) old_rte;
    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    index = get_ioapic_pin_intremap_index(apic_id, ioapic_pin);
    if ( index < 0 )
    {
        ir_ctrl->iremap_index++;
        index = ir_ctrl->iremap_index;
        set_ioapic_pin_intremap_index(apic_id, ioapic_pin, index);
    }

    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: intremap index (%d) is larger than"
                " the maximum index (%ld)!\n",
                __func__, index, IREMAP_ENTRY_NR - 1);
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return -EFAULT;
    }

    iremap_entries =
        (struct iremap_entry *)map_vtd_domain_page(ir_ctrl->iremap_maddr);
    iremap_entry = &iremap_entries[index];

    memcpy(&new_ire, iremap_entry, sizeof(struct iremap_entry));

    if ( rte_upper )
    {
#if defined(__i386__) || defined(__x86_64__)
        new_ire.lo.dst = (value >> 24) << 8;
#else /* __ia64__ */
        new_ire.lo.dst = value >> 16;
#endif
    }
    else
    {
        *(((u32 *)&new_rte) + 0) = value;
        new_ire.lo.fpd = 0;
        new_ire.lo.dm = new_rte.dest_mode;
        new_ire.lo.rh = 0;
        new_ire.lo.tm = new_rte.trigger;
        new_ire.lo.dlm = new_rte.delivery_mode;
        new_ire.lo.avail = 0;
        new_ire.lo.res_1 = 0;
        new_ire.lo.vector = new_rte.vector;
        new_ire.lo.res_2 = 0;
        new_ire.hi.sid = apicid_to_bdf(apic_id);

        new_ire.hi.sq = 0;    /* comparing all 16-bit of SID */
        new_ire.hi.svt = 1;   /* requestor ID verification SID/SQ */
        new_ire.hi.res_1 = 0;
        new_ire.lo.p = 1;     /* finally, set present bit */

        /* now construct new ioapic rte entry */
        remap_rte->vector = new_rte.vector;
        remap_rte->delivery_mode = 0;    /* has to be 0 for remap format */
        remap_rte->index_15 = (index >> 15) & 0x1;
        remap_rte->index_0_14 = index & 0x7fff;

        remap_rte->delivery_status = new_rte.delivery_status;
        remap_rte->polarity = new_rte.polarity;
        remap_rte->irr = new_rte.irr;
        remap_rte->trigger = new_rte.trigger;
        remap_rte->mask = new_rte.mask;
        remap_rte->reserved = 0;
        remap_rte->format = 1;    /* indicate remap format */
    }

    memcpy(iremap_entry, &new_ire, sizeof(struct iremap_entry));
    iommu_flush_cache_entry(iremap_entry);
    iommu_flush_iec_index(iommu, 0, index);
    invalidate_sync(iommu);

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

unsigned int io_apic_read_remap_rte(
    unsigned int apic, unsigned int reg)
{
    struct IO_xAPIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_remap_entry *remap_rte;
    int rte_upper = (reg & 1) ? 1 : 0;
    struct iommu *iommu = ioapic_to_iommu(IO_APIC_ID(apic));
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( !iommu || !ir_ctrl || ir_ctrl->iremap_maddr == 0 ||
         ir_ctrl->iremap_index == -1 )
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

    if ( (remap_rte->format == 0) || (old_rte.delivery_mode == dest_SMI) )
    {
        *IO_APIC_BASE(apic) = rte_upper ? (reg + 1) : reg;
        return *(IO_APIC_BASE(apic)+4);
    }

    if ( remap_entry_to_ioapic_rte(iommu, &old_rte) )
    {
        *IO_APIC_BASE(apic) = rte_upper ? (reg + 1) : reg;
        return *(IO_APIC_BASE(apic)+4);
    }

    if ( rte_upper )
        return (*(((u32 *)&old_rte) + 1));
    else
        return (*(((u32 *)&old_rte) + 0));
}

void io_apic_write_remap_rte(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    unsigned int ioapic_pin = (reg - 0x10) / 2;
    struct IO_xAPIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_remap_entry *remap_rte;
    unsigned int rte_upper = (reg & 1) ? 1 : 0;
    struct iommu *iommu = ioapic_to_iommu(IO_APIC_ID(apic));
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);
    int saved_mask;

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

    if ( old_rte.delivery_mode == dest_SMI )
    {
        /* Some BIOS does not zero out reserve fields in IOAPIC
         * RTE's.  clear_IO_APIC() zeroes out all RTE's except for RTE
         * with MSI delivery type.  This is a problem when the host
         * OS converts SMI delivery type to some other type but leaving
         * the reserved field uninitialized.  This can cause interrupt
         * remapping table out of bound error if "format" field is 1
         * and the "index" field has a value that that is larger than 
         * the maximum index of interrupt remapping table.
         */
        if ( remap_rte->format == 1 )
        {
            remap_rte->format = 0;
            *IO_APIC_BASE(apic) = reg;
            *(IO_APIC_BASE(apic)+4) = *(((u32 *)&old_rte)+0);
            *IO_APIC_BASE(apic) = reg + 1;
            *(IO_APIC_BASE(apic)+4) = *(((u32 *)&old_rte)+1);
        }

        *IO_APIC_BASE(apic) = rte_upper ? (reg + 1) : reg;
        *(IO_APIC_BASE(apic)+4) = value;
        return;
    }

    /* mask the interrupt while we change the intremap table */
    saved_mask = remap_rte->mask;
    remap_rte->mask = 1;
    *IO_APIC_BASE(apic) = reg;
    *(IO_APIC_BASE(apic)+4) = *(((int *)&old_rte)+0);
    remap_rte->mask = saved_mask;

    ASSERT(ioapic_pin < MAX_IOAPIC_PIN_NUM);
    if ( ioapic_rte_to_remap_entry(iommu, IO_APIC_ID(apic), ioapic_pin,
                                   &old_rte, rte_upper, value) )
    {
        *IO_APIC_BASE(apic) = rte_upper ? (reg + 1) : reg;
        *(IO_APIC_BASE(apic)+4) = value;
        return;
    }

    /* write new entry to ioapic */
    *IO_APIC_BASE(apic) = reg;
    *(IO_APIC_BASE(apic)+4) = *(((u32 *)&old_rte)+0);
    *IO_APIC_BASE(apic) = reg + 1;
    *(IO_APIC_BASE(apic)+4) = *(((u32 *)&old_rte)+1);
}

#if defined(__i386__) || defined(__x86_64__)
static int remap_entry_to_msi_msg(
    struct iommu *iommu, struct msi_msg *msg)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct msi_msg_remap_entry *remap_rte;
    int index;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( ir_ctrl == NULL )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "remap_entry_to_msi_msg: ir_ctl == NULL");
        return -EFAULT;
    }

    remap_rte = (struct msi_msg_remap_entry *) msg;
    index = (remap_rte->address_lo.index_15 << 15) |
             remap_rte->address_lo.index_0_14;

    if ( index > ir_ctrl->iremap_index )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) is larger than remap table entry size (%d)\n",
                __func__, index, ir_ctrl->iremap_index);
        return -EFAULT;
    }

    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    iremap_entries =
        (struct iremap_entry *)map_vtd_domain_page(ir_ctrl->iremap_maddr);
    iremap_entry = &iremap_entries[index];

    msg->address_hi = MSI_ADDR_BASE_HI;
    msg->address_lo =
        MSI_ADDR_BASE_LO |
        ((iremap_entry->lo.dm == 0) ?
            MSI_ADDR_DESTMODE_PHYS:
            MSI_ADDR_DESTMODE_LOGIC) |
        ((iremap_entry->lo.dlm != dest_LowestPrio) ?
            MSI_ADDR_REDIRECTION_CPU:
            MSI_ADDR_REDIRECTION_LOWPRI) |
        iremap_entry->lo.dst >> 8;

    msg->data =
        MSI_DATA_TRIGGER_EDGE |
        MSI_DATA_LEVEL_ASSERT |
        ((iremap_entry->lo.dlm != dest_LowestPrio) ?
            MSI_DATA_DELIVERY_FIXED:
            MSI_DATA_DELIVERY_LOWPRI) |
        iremap_entry->lo.vector;

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

static int msi_msg_to_remap_entry(
    struct iommu *iommu, struct pci_dev *pdev,
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct iremap_entry new_ire;
    struct msi_msg_remap_entry *remap_rte;
    unsigned int index;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    remap_rte = (struct msi_msg_remap_entry *) msg;
    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    if ( msi_desc->remap_index < 0 )
    {
        ir_ctrl->iremap_index++;
        index = ir_ctrl->iremap_index;
        msi_desc->remap_index = index;
    }
    else
        index = msi_desc->remap_index;

    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: intremap index (%d) is larger than"
                " the maximum index (%ld)!\n",
                __func__, index, IREMAP_ENTRY_NR - 1);
        msi_desc->remap_index = -1;
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return -EFAULT;
    }

    iremap_entries =
        (struct iremap_entry *)map_vtd_domain_page(ir_ctrl->iremap_maddr);
    iremap_entry = &iremap_entries[index];
    memcpy(&new_ire, iremap_entry, sizeof(struct iremap_entry));

    /* Set interrupt remapping table entry */
    new_ire.lo.fpd = 0;
    new_ire.lo.dm = (msg->address_lo >> MSI_ADDR_DESTMODE_SHIFT) & 0x1;
    new_ire.lo.rh = 0;
    new_ire.lo.tm = (msg->data >> MSI_DATA_TRIGGER_SHIFT) & 0x1;
    new_ire.lo.dlm = (msg->data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x1;
    new_ire.lo.avail = 0;
    new_ire.lo.res_1 = 0;
    new_ire.lo.vector = (msg->data >> MSI_DATA_VECTOR_SHIFT) &
                        MSI_DATA_VECTOR_MASK;
    new_ire.lo.res_2 = 0;
    new_ire.lo.dst = ((msg->address_lo >> MSI_ADDR_DEST_ID_SHIFT)
                      & 0xff) << 8;

    new_ire.hi.sid = (pdev->bus << 8) | pdev->devfn;
    new_ire.hi.sq = 0;
    new_ire.hi.svt = 1;
    new_ire.hi.res_1 = 0;
    new_ire.lo.p = 1;    /* finally, set present bit */

    /* now construct new MSI/MSI-X rte entry */
    remap_rte->address_lo.dontcare = 0;
    remap_rte->address_lo.index_15 = (index >> 15) & 0x1;
    remap_rte->address_lo.index_0_14 = index & 0x7fff;
    remap_rte->address_lo.SHV = 1;
    remap_rte->address_lo.format = 1;

    remap_rte->address_hi = 0;
    remap_rte->data = 0;

    memcpy(iremap_entry, &new_ire, sizeof(struct iremap_entry));
    iommu_flush_cache_entry(iremap_entry);
    iommu_flush_iec_index(iommu, 0, index);
    invalidate_sync(iommu);

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

void msi_msg_read_remap_rte(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct pci_dev *pdev = msi_desc->dev;
    struct acpi_drhd_unit *drhd = NULL;
    struct iommu *iommu = NULL;
    struct ir_ctrl *ir_ctrl;

    drhd = acpi_find_matched_drhd_unit(pdev);
    iommu = drhd->iommu;

    ir_ctrl = iommu_ir_ctrl(iommu);
    if ( !iommu || !ir_ctrl || ir_ctrl->iremap_maddr == 0 )
        return;

    remap_entry_to_msi_msg(iommu, msg);
}

void msi_msg_write_remap_rte(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct pci_dev *pdev = msi_desc->dev;
    struct acpi_drhd_unit *drhd = NULL;
    struct iommu *iommu = NULL;
    struct ir_ctrl *ir_ctrl;

    drhd = acpi_find_matched_drhd_unit(pdev);
    iommu = drhd->iommu;

    ir_ctrl = iommu_ir_ctrl(iommu);
    if ( !iommu || !ir_ctrl || ir_ctrl->iremap_maddr == 0 )
        return;

    msi_msg_to_remap_entry(iommu, pdev, msi_desc, msg);
}
#elif defined(__ia64__)
void msi_msg_read_remap_rte(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    /* TODO. */
}

void msi_msg_write_remap_rte(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    /* TODO. */
}
#endif

int enable_intremap(struct iommu *iommu)
{
    struct ir_ctrl *ir_ctrl;
    s_time_t start_time;

    ASSERT(ecap_intr_remap(iommu->ecap) && iommu_intremap);

    ir_ctrl = iommu_ir_ctrl(iommu);
    if ( ir_ctrl->iremap_maddr == 0 )
    {
        ir_ctrl->iremap_maddr = alloc_pgtable_maddr(NULL, 1);
        if ( ir_ctrl->iremap_maddr == 0 )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Cannot allocate memory for ir_ctrl->iremap_maddr\n");
            return -ENOMEM;
        }
        ir_ctrl->iremap_index = -1;
    }

#if defined(ENABLED_EXTENDED_INTERRUPT_SUPPORT)
    /* set extended interrupt mode bit */
    ir_ctrl->iremap_maddr |=
            ecap_ext_intr(iommu->ecap) ? (1 << IRTA_REG_EIME_SHIFT) : 0;
#endif
    /* set size of the interrupt remapping table */
    ir_ctrl->iremap_maddr |= IRTA_REG_TABLE_SIZE;
    dmar_writeq(iommu->reg, DMAR_IRTA_REG, ir_ctrl->iremap_maddr);

    /* set SIRTP */
    iommu->gcmd |= DMA_GCMD_SIRTP;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);

    /* Make sure hardware complete it */
    start_time = NOW();
    while ( !(dmar_readl(iommu->reg, DMAR_GSTS_REG) & DMA_GSTS_SIRTPS) )
    {
        if ( NOW() > (start_time + DMAR_OPERATION_TIMEOUT) )
            panic("Cannot set SIRTP field for interrupt remapping\n");
        cpu_relax();
    }

    /* enable comaptiblity format interrupt pass through */
    iommu->gcmd |= DMA_GCMD_CFI;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);

    start_time = NOW();
    while ( !(dmar_readl(iommu->reg, DMAR_GSTS_REG) & DMA_GSTS_CFIS) )
    {
        if ( NOW() > (start_time + DMAR_OPERATION_TIMEOUT) )
            panic("Cannot set CFI field for interrupt remapping\n");
        cpu_relax();
    }

    /* enable interrupt remapping hardware */
    iommu->gcmd |= DMA_GCMD_IRE;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);

    start_time = NOW();
    while ( !(dmar_readl(iommu->reg, DMAR_GSTS_REG) & DMA_GSTS_IRES) )
    {
        if ( NOW() > (start_time + DMAR_OPERATION_TIMEOUT) )
            panic("Cannot set IRE field for interrupt remapping\n");
        cpu_relax();
    }

    /* After set SIRTP, we should do globally invalidate the IEC */
    iommu_flush_iec_global(iommu);

    init_ioapic_pin_intremap_index();

    return 0;
}

void disable_intremap(struct iommu *iommu)
{
    s_time_t start_time;

    ASSERT(ecap_intr_remap(iommu->ecap) && iommu_intremap);

    iommu->gcmd &= ~(DMA_GCMD_SIRTP | DMA_GCMD_CFI | DMA_GCMD_IRE);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);

    start_time = NOW();
    while ( dmar_readl(iommu->reg, DMAR_GSTS_REG) & DMA_GSTS_IRES )
    {
        if ( NOW() > (start_time + DMAR_OPERATION_TIMEOUT) )
            panic("Cannot clear IRE field for interrupt remapping\n");
        cpu_relax();
    }
}
