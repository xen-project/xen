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

#ifdef __ia64__
#define nr_ioapics              iosapic_get_nr_iosapics()
#define nr_ioapic_registers(i)  iosapic_get_nr_pins(i)
#else
#include <asm/apic.h>
#include <asm/io_apic.h>
#define nr_ioapic_registers(i)  nr_ioapic_registers[i]
#endif

/*
 * source validation type (SVT)
 */
#define SVT_NO_VERIFY       0x0  /* no verification is required */
#define SVT_VERIFY_SID_SQ   0x1  /* verify using SID and SQ fiels */
#define SVT_VERIFY_BUS      0x2  /* verify bus of request-id */

/*
 * source-id qualifier (SQ)
 */
#define SQ_ALL_16           0x0  /* verify all 16 bits of request-id */
#define SQ_13_IGNORE_1      0x1  /* verify most significant 13 bits, ignore
                                  * the third least significant bit
                                  */
#define SQ_13_IGNORE_2      0x2  /* verify most significant 13 bits, ignore
                                  * the second and third least significant bits
                                  */
#define SQ_13_IGNORE_3      0x3  /* verify most significant 13 bits, ignore
                                  * the least three significant bits
                                  */

/* apic_pin_2_ir_idx[apicid][pin] = interrupt remapping table index */
static int **apic_pin_2_ir_idx;

static int init_apic_pin_2_ir_idx(void)
{
    int *_apic_pin_2_ir_idx;
    unsigned int nr_pins, i;

    /* Here we shouldn't need to re-init when resuming from S3. */
    if ( apic_pin_2_ir_idx != NULL )
        return 0;

    nr_pins = 0;
    for ( i = 0; i < nr_ioapics; i++ )
        nr_pins += nr_ioapic_registers(i);

    _apic_pin_2_ir_idx = xmalloc_array(int, nr_pins);
    apic_pin_2_ir_idx = xmalloc_array(int *, nr_ioapics);
    if ( (_apic_pin_2_ir_idx == NULL) || (apic_pin_2_ir_idx == NULL) )
    {
        xfree(_apic_pin_2_ir_idx);
        xfree(apic_pin_2_ir_idx);
        return -ENOMEM;
    }

    for ( i = 0; i < nr_pins; i++ )
        _apic_pin_2_ir_idx[i] = -1;

    nr_pins = 0;
    for ( i = 0; i < nr_ioapics; i++ )
    {
        apic_pin_2_ir_idx[i] = &_apic_pin_2_ir_idx[nr_pins];
        nr_pins += nr_ioapic_registers(i);
    }

    return 0;
}

static u16 apicid_to_bdf(int apic_id)
{
    struct acpi_drhd_unit *drhd = ioapic_to_drhd(apic_id);
    struct acpi_ioapic_unit *acpi_ioapic_unit;

    list_for_each_entry ( acpi_ioapic_unit, &drhd->ioapic_list, list )
        if ( acpi_ioapic_unit->apic_id == apic_id )
            return acpi_ioapic_unit->ioapic.info;

    dprintk(XENLOG_ERR VTDPREFIX, "Didn't find the bdf for the apic_id!\n");
    return 0;
}

static void set_ire_sid(struct iremap_entry *ire,
                        unsigned int svt, unsigned int sq, unsigned int sid)
{
    ire->hi.svt = svt;
    ire->hi.sq = sq;
    ire->hi.sid = sid;
}

static void set_ioapic_source_id(int apic_id, struct iremap_entry *ire)
{
    set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16,
                apicid_to_bdf(apic_id));
}

int iommu_supports_eim(void)
{
    struct acpi_drhd_unit *drhd;
    int apic;

    if ( !iommu_enabled || !iommu_qinval || !iommu_intremap )
        return 0;

    if ( list_empty(&acpi_drhd_units) )
    {
        dprintk(XENLOG_WARNING VTDPREFIX, "VT-d is not supported\n");
        return 0;
    }

    /* We MUST have a DRHD unit for each IOAPIC. */
    for ( apic = 0; apic < nr_ioapics; apic++ )
        if ( !ioapic_to_drhd(IO_APIC_ID(apic)) )
    {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "There is not a DRHD for IOAPIC 0x%x (id: 0x%x)!\n",
                    apic, IO_APIC_ID(apic));
            return 0;
    }

    for_each_drhd_unit ( drhd )
        if ( !ecap_queued_inval(drhd->iommu->ecap) ||
             !ecap_intr_remap(drhd->iommu->ecap) ||
             !ecap_eim(drhd->iommu->ecap) )
            return 0;

    return 1;
}

/* Mark specified intr remap entry as free */
static void free_remap_entry(struct iommu *iommu, int index)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( index < 0 || index > IREMAP_ENTRY_NR - 1 )
        return;

    ASSERT( spin_is_locked(&ir_ctrl->iremap_lock) );

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    memset(iremap_entry, 0, sizeof(struct iremap_entry));
    iommu_flush_cache_entry(iremap_entry, sizeof(struct iremap_entry));
    iommu_flush_iec_index(iommu, 0, index);

    unmap_vtd_domain_page(iremap_entries);
    ir_ctrl->iremap_num--;
}

/*
 * Look for a free intr remap entry.
 * Need hold iremap_lock, and setup returned entry before releasing lock.
 */
static int alloc_remap_entry(struct iommu *iommu)
{
    struct iremap_entry *iremap_entries = NULL;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);
    int i;

    ASSERT( spin_is_locked(&ir_ctrl->iremap_lock) );

    for ( i = 0; i < IREMAP_ENTRY_NR; i++ )
    {
        struct iremap_entry *p;
        if ( i % (1 << IREMAP_ENTRY_ORDER) == 0 )
        {
            /* This entry across page boundry */
            if ( iremap_entries )
                unmap_vtd_domain_page(iremap_entries);

            GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, i,
                             iremap_entries, p);
        }
        else
            p = &iremap_entries[i % (1 << IREMAP_ENTRY_ORDER)];

        if ( p->lo_val == 0 && p->hi_val == 0 ) /* a free entry */
            break;
    }

    if ( iremap_entries )
        unmap_vtd_domain_page(iremap_entries);

    ir_ctrl->iremap_num++;
    return i;
}

static int remap_entry_to_ioapic_rte(
    struct iommu *iommu, int index, struct IO_xAPIC_route_entry *old_rte)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( ir_ctrl == NULL )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "remap_entry_to_ioapic_rte: ir_ctl is not ready\n");
        return -EFAULT;
    }

    if ( index < 0 || index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) for remap table is invalid !\n",
                __func__, index);
        return -EFAULT;
    }

    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    if ( iremap_entry->hi_val == 0 && iremap_entry->lo_val == 0 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) get an empty entry!\n",
                __func__, index);
        return -EFAULT;
    }

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
    int apic, unsigned int ioapic_pin, struct IO_xAPIC_route_entry *old_rte,
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

    index = apic_pin_2_ir_idx[apic][ioapic_pin];
    if ( index < 0 )
    {
        index = alloc_remap_entry(iommu);
        apic_pin_2_ir_idx[apic][ioapic_pin] = index;
    }

    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: intremap index (%d) is larger than"
                " the maximum index (%d)!\n",
                __func__, index, IREMAP_ENTRY_NR - 1);
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return -EFAULT;
    }

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    memcpy(&new_ire, iremap_entry, sizeof(struct iremap_entry));

    if ( rte_upper )
    {
#if defined(__i386__) || defined(__x86_64__)
        if ( x2apic_enabled )
            new_ire.lo.dst = value;
        else
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

        set_ioapic_source_id(IO_APIC_ID(apic), &new_ire);
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
    iommu_flush_cache_entry(iremap_entry, sizeof(struct iremap_entry));
    iommu_flush_iec_index(iommu, 0, index);
    invalidate_sync(iommu);

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

unsigned int io_apic_read_remap_rte(
    unsigned int apic, unsigned int reg)
{
    unsigned int ioapic_pin = (reg - 0x10) / 2;
    int index;
    struct IO_xAPIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_remap_entry *remap_rte;
    int rte_upper = (reg & 1) ? 1 : 0;
    struct iommu *iommu = ioapic_to_iommu(IO_APIC_ID(apic));
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( !iommu || !ir_ctrl || ir_ctrl->iremap_maddr == 0 ||
        (ir_ctrl->iremap_num == 0) ||
        ( (index = apic_pin_2_ir_idx[apic][ioapic_pin]) < 0 ) )
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

    if ( remap_entry_to_ioapic_rte(iommu, index, &old_rte) )
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

    /* mask the interrupt while we change the intremap table */
    saved_mask = remap_rte->mask;
    remap_rte->mask = 1;
    *IO_APIC_BASE(apic) = reg;
    *(IO_APIC_BASE(apic)+4) = *(((int *)&old_rte)+0);
    remap_rte->mask = saved_mask;

    if ( ioapic_rte_to_remap_entry(iommu, apic, ioapic_pin,
                                   &old_rte, rte_upper, value) )
    {
        *IO_APIC_BASE(apic) = rte_upper ? (reg + 1) : reg;
        *(IO_APIC_BASE(apic)+4) = value;
        return;
    }

    /* write new entry to ioapic */
    *IO_APIC_BASE(apic) = reg + 1;
    *(IO_APIC_BASE(apic)+4) = *(((u32 *)&old_rte)+1);
    *IO_APIC_BASE(apic) = reg;
    *(IO_APIC_BASE(apic)+4) = *(((u32 *)&old_rte)+0);
}

#if defined(__i386__) || defined(__x86_64__)

static void set_msi_source_id(struct pci_dev *pdev, struct iremap_entry *ire)
{
    int type;
    u8 bus, devfn, secbus;
    int ret;

    if ( !pdev || !ire )
        return;

    bus = pdev->bus;
    devfn = pdev->devfn;
    type = pdev_type(bus, devfn);
    switch ( type )
    {
    case DEV_TYPE_PCIe_BRIDGE:
    case DEV_TYPE_PCIe2PCI_BRIDGE:
    case DEV_TYPE_LEGACY_PCI_BRIDGE:
        break;

    case DEV_TYPE_PCIe_ENDPOINT:
        set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16, PCI_BDF2(bus, devfn));
        break;

    case DEV_TYPE_PCI:
        ret = find_upstream_bridge(&bus, &devfn, &secbus);
        if ( ret == 0 ) /* integrated PCI device */
        {
            set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16,
                        PCI_BDF2(bus, devfn));
        }
        else if ( ret == 1 ) /* find upstream bridge */
        {
            if ( pdev_type(bus, devfn) == DEV_TYPE_PCIe2PCI_BRIDGE )
                set_ire_sid(ire, SVT_VERIFY_BUS, SQ_ALL_16,
                            (bus << 8) | pdev->bus);
            else if ( pdev_type(bus, devfn) == DEV_TYPE_LEGACY_PCI_BRIDGE )
                set_ire_sid(ire, SVT_VERIFY_BUS, SQ_ALL_16,
                            PCI_BDF2(bus, devfn));
        }
        break;

    default:
        dprintk(XENLOG_WARNING VTDPREFIX, "d%d: unknown(%u): bdf = %x:%x.%x\n",
                pdev->domain->domain_id, type,
                bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        break;
   }
}

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

    if ( index < 0 || index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) for remap table is invalid !\n",
                __func__, index);
        return -EFAULT;
    }

    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    if ( iremap_entry->hi_val == 0 && iremap_entry->lo_val == 0 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) get an empty entry!\n",
                __func__, index);
        return -EFAULT;
    }

    msg->address_hi = MSI_ADDR_BASE_HI;
    msg->address_lo =
        MSI_ADDR_BASE_LO |
        ((iremap_entry->lo.dm == 0) ?
            MSI_ADDR_DESTMODE_PHYS:
            MSI_ADDR_DESTMODE_LOGIC) |
        ((iremap_entry->lo.dlm != dest_LowestPrio) ?
            MSI_ADDR_REDIRECTION_CPU:
            MSI_ADDR_REDIRECTION_LOWPRI);
    if ( x2apic_enabled )
        msg->dest32 = iremap_entry->lo.dst;
    else
        msg->address_lo |=
            ((iremap_entry->lo.dst >> 8) & 0xff ) << MSI_ADDR_DEST_ID_SHIFT;

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
    int index;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    remap_rte = (struct msi_msg_remap_entry *) msg;
    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    if ( msg == NULL )
    {
        /* Free specified unused IRTE */
        free_remap_entry(iommu, msi_desc->remap_index);
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return 0;
    }

    if ( msi_desc->remap_index < 0 )
    {
        /*
         * TODO: Multiple-vector MSI requires allocating multiple continuous
         * entries and configuring addr/data of msi_msg in different way. So
         * alloca_remap_entry will be changed if enabling multiple-vector MSI
         * in future.
         */
        index = alloc_remap_entry(iommu);
        msi_desc->remap_index = index;
    }
    else
        index = msi_desc->remap_index;

    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: intremap index (%d) is larger than"
                " the maximum index (%d)!\n",
                __func__, index, IREMAP_ENTRY_NR - 1);
        msi_desc->remap_index = -1;
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return -EFAULT;
    }

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

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
    if ( x2apic_enabled )
        new_ire.lo.dst = msg->dest32;
    else
        new_ire.lo.dst = ((msg->address_lo >> MSI_ADDR_DEST_ID_SHIFT)
                          & 0xff) << 8;

    set_msi_source_id(pdev, &new_ire);
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
    iommu_flush_cache_entry(iremap_entry, sizeof(struct iremap_entry));
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

    if ( (drhd = acpi_find_matched_drhd_unit(pdev)) == NULL )
        return;
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

    if ( (drhd = acpi_find_matched_drhd_unit(pdev)) == NULL )
        return;
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

int enable_intremap(struct iommu *iommu, int eim)
{
    struct acpi_drhd_unit *drhd;
    struct ir_ctrl *ir_ctrl;
    u32 sts, gcmd;
    unsigned long flags;

    ASSERT(ecap_intr_remap(iommu->ecap) && iommu_intremap);

    ir_ctrl = iommu_ir_ctrl(iommu);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);

    /* Return if already enabled by Xen */
    if ( (sts & DMA_GSTS_IRES) && ir_ctrl->iremap_maddr )
        return 0;

    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    if ( !(sts & DMA_GSTS_QIES) )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "Queued invalidation is not enabled, should not enable "
                "interrupt remapping\n");
        return -EINVAL;
    }

    if ( ir_ctrl->iremap_maddr == 0 )
    {
        drhd = iommu_to_drhd(iommu);
        ir_ctrl->iremap_maddr = alloc_pgtable_maddr(drhd, IREMAP_ARCH_PAGE_NR);
        if ( ir_ctrl->iremap_maddr == 0 )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Cannot allocate memory for ir_ctrl->iremap_maddr\n");
            return -ENOMEM;
        }
        ir_ctrl->iremap_num = 0;
    }

#ifdef CONFIG_X86
    /* set extended interrupt mode bit */
    ir_ctrl->iremap_maddr |=
            eim ? (1 << IRTA_REG_EIME_SHIFT) : 0;
#endif
    spin_lock_irqsave(&iommu->register_lock, flags);

    /* set size of the interrupt remapping table */
    ir_ctrl->iremap_maddr |= IRTA_REG_TABLE_SIZE;
    dmar_writeq(iommu->reg, DMAR_IRTA_REG, ir_ctrl->iremap_maddr);

    /* set SIRTP */
    gcmd = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    gcmd |= DMA_GCMD_SIRTP;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, gcmd);

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_SIRTPS), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* After set SIRTP, must globally invalidate the interrupt entry cache */
    iommu_flush_iec_global(iommu);

    spin_lock_irqsave(&iommu->register_lock, flags);
    /* enable interrupt remapping hardware */
    gcmd |= DMA_GCMD_IRE;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, gcmd);

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_IRES), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    return init_apic_pin_2_ir_idx();
}

void disable_intremap(struct iommu *iommu)
{
    u32 sts;
    unsigned long flags;

    if ( !ecap_intr_remap(iommu->ecap) )
        return;

    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    if ( !(sts & DMA_GSTS_IRES) )
        goto out;

    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts & (~DMA_GCMD_IRE));

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  !(sts & DMA_GSTS_IRES), sts);
out:
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

/*
 * This function is used to enable Interrutp remapping when
 * enable x2apic
 */
int iommu_enable_IR(void)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;

    if ( !iommu_supports_eim() )
        return -1;

    for_each_drhd_unit ( drhd )
    {
        struct qi_ctrl *qi_ctrl = NULL;

        iommu = drhd->iommu;
        qi_ctrl = iommu_qi_ctrl(iommu);

        /* Clear previous faults */
        clear_fault_bits(iommu);

        /*
         * Disable interrupt remapping and queued invalidation if
         * already enabled by BIOS
         */
        disable_intremap(iommu);
        disable_qinval(iommu);
    }

    /* Enable queue invalidation */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( enable_qinval(iommu) != 0 )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "Failed to enable Queued Invalidation!\n");
            return -1;
        }
    }

    /* Enable interrupt remapping */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( enable_intremap(iommu, 1) )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "Failed to enable Interrupt Remapping!\n");
            return -1;
        }
    }

    return 0;
}

/*
 * Check if interrupt remapping is enabled or not
 * return 1: enabled
 * return 0: not enabled
 */
int intremap_enabled(void)
{
    struct acpi_drhd_unit *drhd;
    u32 sts;

    for_each_drhd_unit ( drhd )
    {
        sts = dmar_readl(drhd->iommu->reg, DMAR_GSTS_REG);
        if ( !(sts & DMA_GSTS_IRES) )
            return 0;
    }

    return 1;
}
